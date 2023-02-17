use crate::updated_once::{MemoryValidator, UpdatedOnceValidator};
use crate::{DBColumn, Error, HotColdDB, ItemStore, KeyValueStoreOp, StoreItem, StoreOp};
use bls::PUBLIC_KEY_UNCOMPRESSED_BYTES_LEN;
use slog::debug;
use smallvec::SmallVec;
use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::sync::Arc;
use types::{BeaconState, ChainSpec, EthSpec, Hash256, PublicKey, PublicKeyBytes, Slot, Validator};

/// Provides a mapping of `validator_index -> validator_publickey`.
///
/// This cache exists for two reasons:
///
/// 1. To avoid reading a `BeaconState` from disk each time we need a public key.
/// 2. To reduce the amount of public key _decompression_ required. A `BeaconState` stores public
///    keys in compressed form and they are needed in decompressed form for signature verification.
///    Decompression is expensive when many keys are involved.
///
/// The cache has a `backing` that it uses to maintain a persistent, on-disk
/// copy of itself. This allows it to be restored between process invocations.
#[derive(Debug)]
pub struct ValidatorPubkeyCache<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> {
    pubkeys: Vec<PublicKey>,
    indices: HashMap<PublicKeyBytes, usize>,
    pub validators: Vec<MemoryValidator>,
    /// Validator indices (positions in `self.validators`) that have been updated and are
    /// awaiting being flushed to disk.
    dirty_indices: HashSet<usize>,
    _phantom: PhantomData<(E, Hot, Cold)>,
}

// Temp value.
impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> Default
    for ValidatorPubkeyCache<E, Hot, Cold>
{
    fn default() -> Self {
        ValidatorPubkeyCache {
            pubkeys: vec![],
            indices: HashMap::new(),
            validators: vec![],
            dirty_indices: HashSet::new(),
            _phantom: PhantomData,
        }
    }
}

impl<E: EthSpec, Hot: ItemStore<E>, Cold: ItemStore<E>> ValidatorPubkeyCache<E, Hot, Cold> {
    /// Create a new public key cache using the keys in `state.validators`.
    ///
    /// The new cache will be updated with the keys from `state` and immediately written to disk.
    pub fn new(state: &BeaconState<E>, store: &HotColdDB<E, Hot, Cold>) -> Result<Self, Error> {
        let mut cache = Self {
            pubkeys: vec![],
            indices: HashMap::new(),
            validators: vec![],
            dirty_indices: HashSet::new(),
            _phantom: PhantomData,
        };

        cache.update_for_finalized_state(&state, state.slot(), store.get_chain_spec())?;
        store
            .hot_db
            .do_atomically(cache.get_pending_validator_ops()?)?;
        debug!(
            store.log,
            "Initialized finalized validator store";
            "num_validators" => cache.validators.len(),
        );

        Ok(cache)
    }

    /// Load the pubkey cache from the given on-disk database.
    pub fn load_from_store(store: &HotColdDB<E, Hot, Cold>) -> Result<Self, Error> {
        let mut pubkeys = vec![];
        let mut indices = HashMap::new();
        let mut validators = vec![];
        let dirty_indices = HashSet::new();

        for validator_index in 0.. {
            if let Some(db_validator) =
                store.get_item(&DatabaseValidator::key_for_index(validator_index))?
            {
                let (pubkey, validator) = DatabaseValidator::into_memory_validator(db_validator)?;
                pubkeys.push(pubkey);
                indices.insert(*validator.pubkey, validator_index);
                validators.push(validator);
            } else {
                break;
            }
        }

        Ok(ValidatorPubkeyCache {
            pubkeys,
            indices,
            validators,
            dirty_indices,
            _phantom: PhantomData,
        })
    }

    /// Scan the given `state` and add any new validator public keys.
    ///
    /// Does not delete any keys from `self` if they don't appear in `state`.
    ///
    /// NOTE: The caller *must* commit the returned I/O batch as part of the block import process.
    pub fn import_new_pubkeys(
        &mut self,
        state: &BeaconState<E>,
    ) -> Result<Vec<StoreOp<'static, E>>, Error> {
        if state.validators().len() > self.validators.len() {
            self.import_new(
                state
                    .validators()
                    .iter_from(self.pubkeys.len())?
                    .map(|v| v.pubkey.clone()),
            )
        } else {
            Ok(vec![])
        }
    }

    /// Adds zero or more validators to `self`.
    fn import_new<I>(&mut self, validator_keys: I) -> Result<Vec<StoreOp<'static, E>>, Error>
    where
        I: Iterator<Item = Arc<PublicKeyBytes>> + ExactSizeIterator,
    {
        self.validators.reserve(validator_keys.len());
        self.pubkeys.reserve(validator_keys.len());
        self.indices.reserve(validator_keys.len());

        let mut store_ops = Vec::with_capacity(validator_keys.len());
        for pubkey_bytes in validator_keys {
            let i = self.pubkeys.len();

            if self.indices.contains_key(&pubkey_bytes) {
                return Err(Error::DuplicateValidatorPublicKey);
            }

            let pubkey = pubkey_bytes
                .decompress()
                .map_err(Error::InvalidValidatorPubkeyBytes)?;

            // Stage the new validator key for writing to disk.
            // It will be committed atomically when the block that introduced it is written to disk.
            // Notably it is NOT written while the write lock on the cache is held.
            // See: https://github.com/sigp/lighthouse/issues/2327
            let db_validator = DatabaseValidator::new_unfinalized_validator(&pubkey);
            store_ops.push(StoreOp::KeyValueOp(
                db_validator.as_kv_store_op(DatabaseValidator::key_for_index(i))?,
            ));

            self.pubkeys.push(pubkey);
            self.indices.insert(*pubkey_bytes, i);

            let memory_validator = MemoryValidator {
                pubkey: pubkey_bytes,
                updated_once: db_validator.updated_once,
            };
            self.validators.push(memory_validator);
        }

        Ok(store_ops)
    }

    pub fn update_for_finalized_state(
        &mut self,
        finalized_state: &BeaconState<E>,
        latest_restore_point_slot: Slot,
        spec: &ChainSpec,
    ) -> Result<(usize, usize), Error> {
        let slot = finalized_state.slot();

        let mut num_validators_updated = 0;
        let mut num_fields_updated = 0;

        for (i, validator) in finalized_state.validators().iter().enumerate() {
            if let Some(memory_validator) = self.validators.get_mut(i) {
                // Dummy validator? Override it.
                if memory_validator.updated_once.is_dummy() {
                    memory_validator.updated_once =
                        UpdatedOnceValidator::from_validator(validator, slot, spec)?;
                    num_validators_updated += 1;
                    self.dirty_indices.insert(i);
                    continue;
                }

                // Otherwise update the existing validator.
                let num_updated = memory_validator.updated_once.update_knowledge(
                    validator,
                    slot,
                    latest_restore_point_slot,
                )?;

                if num_updated > 0 {
                    num_validators_updated += 1;
                    num_fields_updated += num_updated;
                    self.dirty_indices.insert(i);
                }
            } else {
                assert_eq!(i, self.validators.len());
                assert_eq!(i, self.pubkeys.len());
                let pubkey_bytes = validator.pubkey_clone();
                let pubkey = pubkey_bytes
                    .decompress()
                    .map_err(Error::InvalidValidatorPubkeyBytes)?;
                self.indices.insert(*pubkey_bytes, i);
                self.pubkeys.push(pubkey);
                self.validators.push(MemoryValidator {
                    pubkey: pubkey_bytes,
                    updated_once: UpdatedOnceValidator::from_validator(validator, slot, spec)?,
                });
                num_validators_updated += 1;
                self.dirty_indices.insert(i);
            }
        }

        Ok((num_validators_updated, num_fields_updated))
    }

    pub fn get_pending_validator_ops(&mut self) -> Result<Vec<KeyValueStoreOp>, Error> {
        let mut ops = Vec::with_capacity(self.dirty_indices.len());
        for &i in &self.dirty_indices {
            let pubkey = self.get(i).ok_or(Error::MissingValidator(i))?;
            let updated_once = self
                .validators
                .get(i)
                .ok_or(Error::MissingValidator(i))?
                .updated_once
                .clone();
            let db_validator = DatabaseValidator::new(pubkey, updated_once);
            ops.push(db_validator.as_kv_store_op(DatabaseValidator::key_for_index(i))?);
        }

        // Clear dirty indices but retain allocated capacity.
        self.dirty_indices.clear();

        Ok(ops)
    }

    /// Get the public key for a validator with index `i`.
    pub fn get(&self, i: usize) -> Option<&PublicKey> {
        self.pubkeys.get(i)
    }

    /// Get the immutable pubkey of the validator with index `i`.
    pub fn get_validator_pubkey(&self, i: usize) -> Option<Arc<PublicKeyBytes>> {
        self.validators.get(i).map(|val| val.pubkey.clone())
    }

    pub fn get_validator_at_slot(
        &self,
        i: usize,
        effective_balance: u64,
        slot: Slot,
    ) -> Result<Validator, Error> {
        self.validators
            .get(i)
            .ok_or(Error::MissingValidator(i))?
            .into_validator(effective_balance, slot)
            .map_err(Into::into)
    }

    /// Get the `PublicKey` for a validator with `PublicKeyBytes`.
    pub fn get_pubkey_from_pubkey_bytes(&self, pubkey: &PublicKeyBytes) -> Option<&PublicKey> {
        self.get_index(pubkey).and_then(|index| self.get(index))
    }

    /// Get the public key (in bytes form) for a validator with index `i`.
    pub fn get_pubkey_bytes(&self, i: usize) -> Option<&PublicKeyBytes> {
        self.validators.get(i).map(|validator| &*validator.pubkey)
    }

    /// Get the index of a validator with `pubkey`.
    pub fn get_index(&self, pubkey: &PublicKeyBytes) -> Option<usize> {
        self.indices.get(pubkey).copied()
    }

    /// Returns the number of validators in the cache.
    pub fn len(&self) -> usize {
        self.indices.len()
    }

    /// Returns `true` if there are no validators in the cache.
    pub fn is_empty(&self) -> bool {
        self.indices.is_empty()
    }
}

/// Wrapper for a public key stored in the database.
///
/// Keyed by the validator index as `Hash256::from_low_u64_be(index)`.
#[derive(Encode, Decode)]
struct DatabaseValidator {
    pubkey: SmallVec<[u8; PUBLIC_KEY_UNCOMPRESSED_BYTES_LEN]>,
    updated_once: UpdatedOnceValidator,
}

impl StoreItem for DatabaseValidator {
    fn db_column() -> DBColumn {
        DBColumn::PubkeyCache
    }

    fn as_store_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(self.as_ssz_bytes())
    }

    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_ssz_bytes(bytes)?)
    }
}

impl DatabaseValidator {
    fn key_for_index(index: usize) -> Hash256 {
        Hash256::from_low_u64_be(index as u64)
    }

    fn new_unfinalized_validator(pubkey: &PublicKey) -> Self {
        DatabaseValidator {
            pubkey: pubkey.serialize_uncompressed().into(),
            updated_once: UpdatedOnceValidator::dummy(),
        }
    }

    fn new(pubkey: &PublicKey, validator: UpdatedOnceValidator) -> Self {
        DatabaseValidator {
            pubkey: pubkey.serialize_uncompressed().into(),
            updated_once: validator,
        }
    }

    fn into_memory_validator(self) -> Result<(PublicKey, MemoryValidator), Error> {
        let pubkey = PublicKey::deserialize_uncompressed(&self.pubkey)
            .map_err(Error::InvalidValidatorPubkeyBytes)?;
        let pubkey_bytes = Arc::new(pubkey.compress());
        let updated_once = self.updated_once;
        Ok((
            pubkey,
            MemoryValidator {
                pubkey: pubkey_bytes,
                updated_once,
            },
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{HotColdDB, KeyValueStore, MemoryStore};
    use beacon_chain::test_utils::BeaconChainHarness;
    use logging::test_logger;
    use std::sync::Arc;
    use types::{BeaconState, EthSpec, Keypair, MainnetEthSpec};

    type E = MainnetEthSpec;
    type Store = MemoryStore<E>;

    fn get_state(validator_count: usize) -> (BeaconState<E>, Vec<Keypair>) {
        let harness = BeaconChainHarness::builder(MainnetEthSpec)
            .default_spec()
            .deterministic_keypairs(validator_count)
            .fresh_ephemeral_store()
            .build();

        harness.advance_slot();

        (harness.get_current_state(), harness.validator_keypairs)
    }

    fn get_store() -> Arc<HotColdDB<E, Store, Store>> {
        Arc::new(
            HotColdDB::open_ephemeral(<_>::default(), E::default_spec(), test_logger()).unwrap(),
        )
    }

    #[allow(clippy::needless_range_loop)]
    fn check_cache_get(cache: &ValidatorPubkeyCache<E, Store, Store>, keypairs: &[Keypair]) {
        let validator_count = keypairs.len();

        for i in 0..validator_count + 1 {
            if i < validator_count {
                let pubkey = cache.get(i).expect("pubkey should be present");
                assert_eq!(pubkey, &keypairs[i].pk, "pubkey should match cache");

                let pubkey_bytes: PublicKeyBytes = pubkey.clone().into();

                assert_eq!(
                    i,
                    cache
                        .get_index(&pubkey_bytes)
                        .expect("should resolve index"),
                    "index should match cache"
                );
            } else {
                assert_eq!(
                    cache.get(i),
                    None,
                    "should not get pubkey for out of bounds index",
                );
            }
        }
    }

    #[test]
    fn basic_operation() {
        let (state, keypairs) = get_state(8);

        let store = get_store();

        let mut cache = ValidatorPubkeyCache::new(&state, &store).expect("should create cache");

        check_cache_get(&cache, &keypairs[..]);

        // Try adding a state with the same number of keypairs.
        let (state, keypairs) = get_state(8);
        cache
            .import_new_pubkeys(&state)
            .expect("should import pubkeys");
        check_cache_get(&cache, &keypairs[..]);

        // Try adding a state with less keypairs.
        let (state, _) = get_state(1);
        cache
            .import_new_pubkeys(&state)
            .expect("should import pubkeys");
        check_cache_get(&cache, &keypairs[..]);

        // Try adding a state with more keypairs.
        let (state, keypairs) = get_state(12);
        cache
            .import_new_pubkeys(&state)
            .expect("should import pubkeys");
        check_cache_get(&cache, &keypairs[..]);
    }

    #[test]
    fn persistence() {
        let (state, keypairs) = get_state(8);

        let store = get_store();

        // Create a new cache.
        let cache = ValidatorPubkeyCache::new(&state, &store).expect("should create cache");
        check_cache_get(&cache, &keypairs[..]);
        drop(cache);

        // Re-init the cache from the store.
        let mut cache = ValidatorPubkeyCache::load_from_store(&store).expect("should open cache");
        check_cache_get(&cache, &keypairs[..]);

        // Add some more keypairs.
        let (state, keypairs) = get_state(12);
        let ops = cache
            .import_new_pubkeys(&state)
            .expect("should import pubkeys");
        store.do_atomically(ops).unwrap();
        check_cache_get(&cache, &keypairs[..]);
        drop(cache);

        // Re-init the cache from the store.
        let cache = ValidatorPubkeyCache::load_from_store(&store).expect("should open cache");
        check_cache_get(&cache, &keypairs[..]);
    }
}
