use ssz_derive::{Decode, Encode};
use types::{BeaconState, Epoch, Hash256, PublicKeyBytes, Slot, Validator, ValidatorMutable};

/// A bound represents possibly partial knowledge of the point in time at which an
/// updated-once field changes.
pub enum Bound {
    /// The update slot for the field is known exactly.
    ///
    /// All states at `slot >= self.slot` have the updated value, and all states at `slot <
    /// self.slot` have the initial value.
    Exact { slot: Slot },
    /// The update slot for the field is known to be:
    ///
    /// - `update_slot >= lower` and
    /// - `update_slot < upper`
    ///
    /// This means that the value is known for states with `state.slot < lower`, where it *must*
    /// be the initial value, and for states with `state.slot >= upper`, where it *must* be the
    /// updated value.
    Between { lower: Slot, upper: Slot },
}

#[derive(Encode, Decode)]
pub enum UpdatedOnce<T> {
    OneValueKnown {
        pub value: T,
        pub first_seen: Slot,
        pub last_seen: Slot,
    },
    InitialValueKnown {
        pub initial: T,
        pub lower: Slot,
    },
    TwoValuesKnown {
        pub initial: T,
        pub updated: T,
        pub bound: Bound,
    },
}

/// Succinct representation of the updated-once fields of a validator.
#[derive(Encode, Decode)]
pub struct UpdatedOnceValidator {
    /// Withdrawal credentials can be updated once by a BLS to execution change.
    pub withdrawal_credentials: UpdatedOnce<Hash256>,
    /// Validators can be slashed once at a specific epoch.
    ///
    /// Before that `slashed` is always `false`.
    pub slashed: UpdatedOnce<bool>,
    /// The activation eligibility epoch is set by `process_registry_updates` on the first epoch
    /// transition after the validator's deposit is processed.
    pub activation_eligibility_epoch: UpdatedOnce<Epoch>,
    /// The activation epoch is set in `process_registry_updates` once the validator's eligibility
    /// epoch is finalized and it reaches the front of the queue.
    pub activation_epoch: UpdatedOnce<Epoch>,
    /// The exit epoch is set when the validator exits.
    pub exit_epoch: UpdatedOnce<Epoch>,
    /// The withdrawable epoch is set when the validator becomes withdrawable.
    pub withdrawable_epoch: UpdatedOnce<Epoch>,
}

/// Immutable *and* updated-once fields of a validator stored in memory.
///
/// Effective balance is mutable and changes frequently so it is omitted. It is stored elsewhere with
/// compression.
pub struct MemoryValidator {
    /// Public key is immutable.
    pub pubkey: Arc<PublicKeyBytes>,
    pub updated_once: UpdatedOnceValidator,
}

impl<T> UpdatedOnce<T> {
    pub fn from_field_with_initial_default(value: T, slot: Slot, default: T) -> Self {
        if value != default {
            UpdatedOnce::TwoValuesKnown {
                initial: default,
                updated: value,
                bound: Bound::Between {
                    lower: Slot::new(0),
                    upper: slot,
                },
            }
        } else {
            UpdatedOnce::InitialValueKnown {
                initial: value,
                lower: slot,
            }
        }
    }
}

impl UpdatedOnceValidator {
    pub fn from_validator(validator: &Validator, slot: Slot, spec: &ChainSpec) -> Self {
        let far_future_epoch = spec.far_future_epoch;

        let withdrawal_credentials = UpdatedOnce::OneValueKnown {
            value: validator.withdrawal_credentials(),
            first_seen: Slot,
            last_seen: Slot,
        };
        let slashed =
            UpdatedOnce::from_field_with_initial_default(validator.slashed(), slot, false);
        let activation_eligibility_epoch = UpdatedOnce::from_field_with_initial_default(
            validator.activation_eligibility_epoch(),
            slot,
            far_future_epoch,
        );
        let activation_epoch = UpdatedOnce::from_field_with_initial_default(
            validator.activation_epoch(),
            slot,
            far_future_epoch,
        );
        let exit_epoch = UpdatedOnce::from_field_with_initial_default(
            validator.exit_epoch(),
            slot,
            far_future_epoch,
        );
        let withdrawable_epoch = UpdatedOnce::from_field_with_initial_default(
            validator.withdrawal_epoch(),
            slot,
            far_future_epoch,
        );

        Self {
            withdrawal_credentials,
            slashed,
            activation_eligibility_epoch,
            activation_epoch,
            exit_epoch,
            withdrawable_epoch,
        }
    }
}
