use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::sync::Arc;
use types::{ChainSpec, Epoch, Hash256, PublicKeyBytes, Slot, Validator, ValidatorMutable};

#[derive(Debug)]
pub enum UpdatedOnceError {
    OutOfBoundsOneValue {
        slot: Slot,
        first_seen: Slot,
        last_seen: Slot,
    },
    OutOfBoundsInitialValue {
        slot: Slot,
        lower_bound: Slot,
    },
    OutOfBoundsBetween {
        slot: Slot,
        bound: Bound,
    },
    InvalidBound {
        lower: Slot,
        upper: Slot,
    },
    OneValueKnownConflict {
        slot: Slot,
        first_seen: Slot,
        last_seen: Slot,
    },
    InitialValueKnownConflict {
        slot: Slot,
        latest_restore_point_slot: Slot,
    },
    TwoValuesKnownInitialConflict {
        slot: Slot,
        bound: Bound,
    },
    TwoValuesKnownUpdatedConflict {
        slot: Slot,
        bound: Bound,
    },
    TwoValuesKnownThirdValueConflict {
        slot: Slot,
    },
}

/// A bound represents possibly partial knowledge of the point in time at which an
/// updated-once field changes.
///
/// The update slot for the field is known to be:
///
/// - `update_slot > lower` and
/// - `update_slot <= upper`
///
/// This means that the value is known for states with `slot <= lower`, where it *must*
/// be the initial value, and for states with `slot >= upper`, where it *must* be the
/// updated value. This follows from case-analysis on this expression:
///
///  value = if slot >= update_slot { updated } else { initial }
///
/// For the first case we have:
///
///   slot <= lower /\ update_slot > lower -->
///   slot <= lower /\ lower < update_slot -->
///   slot < updated -->
///   !(slot >= update_slot) -->
///   value = initial
///
/// For the second case we have:
///
///   slot >= upper /\ update_slot <= upper -->
///   slot >= upper /\ upper >= update_slot -->
///   slot >= update_slot -->
///   value = updated
#[derive(Debug, Encode, Decode, Clone, Copy, PartialEq)]
pub struct Bound {
    pub lower: Slot,
    pub upper: Slot,
}

/// A single value is known for the field but we don't know whether it is the initial or updated
/// value.
///
/// If it is the initial value then the update slot lies at some point in the future `> last_seen`.
/// If it is the updated value then the update slot lies at some point in the past `<= first_seen`.
#[derive(Debug, Encode, Decode, Clone, PartialEq)]
pub struct OneValueKnown<T: Encode + Decode> {
    pub value: T,
    pub first_seen: Slot,
    pub last_seen: Slot,
}

/// The initial value is known for the field and we don't know of any updates for it (yet).
///
/// We can think of the `InitialValueKnown` state as containing an implicit `lower_bound` such
/// that the update slot is certainly in the future at a slot `> lower_bound`. To avoid constantly
/// updating and re-writing the bound as the split point advances we elide this `lower_bound` from
/// the data structure in-memory and on-disk and infer it from the store's
/// `latest_restore_point_slot`.
///
/// When loading states we know that the initial value is valid for all slots
/// `<= lower_bound/latest_restore_point_slot`.
#[derive(Debug, Encode, Decode, Clone, PartialEq)]
pub struct InitialValueKnown<T: Encode + Decode> {
    pub initial: T,
}

#[derive(Debug, Encode, Decode, Clone, PartialEq)]
pub struct TwoValuesKnown<T: Encode + Decode> {
    pub initial: T,
    pub updated: T,
    pub bound: Bound,
}

#[derive(Debug, Encode, Decode, Clone, PartialEq)]
#[ssz(enum_behaviour = "union")]
pub enum UpdatedOnce<T: Encode + Decode> {
    OneValueKnown(OneValueKnown<T>),
    InitialValueKnown(InitialValueKnown<T>),
    TwoValuesKnown(TwoValuesKnown<T>),
}

/// Succinct representation of the updated-once fields of a validator.
#[derive(Debug, Encode, Decode, Clone)]
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
#[derive(Debug)]
pub struct MemoryValidator {
    /// Public key is immutable.
    pub pubkey: Arc<PublicKeyBytes>,
    pub updated_once: UpdatedOnceValidator,
}

impl MemoryValidator {
    pub fn into_validator(
        &self,
        effective_balance: u64,
        slot: Slot,
    ) -> Result<Validator, UpdatedOnceError> {
        let pubkey = self.pubkey.clone();
        let mutable = self
            .updated_once
            .into_validator_mutable(effective_balance, slot)?;
        Ok(Validator { pubkey, mutable })
    }
}

impl Bound {
    fn new(lower: Slot, upper: Slot) -> Result<Self, UpdatedOnceError> {
        // FIXME(sproul): was checking lower < upper but validators activated at genesis
        // require a 0..0 bound for their 0-epoch activation.
        if lower <= upper {
            Ok(Bound { lower, upper })
        } else {
            // FIXME(sproul): debug
            panic!("invalid bound: {lower}..{upper}")
            // Err(UpdatedOnceError::InvalidBound { lower, upper })
        }
    }
}

impl<T: Encode + Decode + PartialEq> UpdatedOnce<T> {
    pub fn dummy() -> Self
    where
        T: Default,
    {
        // Set impossible bounds to ensure this value is never used.
        UpdatedOnce::OneValueKnown(OneValueKnown {
            value: T::default(),
            first_seen: Slot::new(u64::MAX),
            last_seen: Slot::new(0),
        })
    }

    pub fn is_dummy(&self) -> bool
    where
        T: Default,
    {
        // This could probably be more efficient.
        self == &Self::dummy()
    }

    pub fn from_field_with_initial_default(
        value: T,
        slot: Slot,
        is_initial_default: impl Fn(T) -> bool,
        default: T,
    ) -> Result<Self, UpdatedOnceError>
    where
        T: Copy,
    {
        if is_initial_default(value) {
            Ok(UpdatedOnce::InitialValueKnown(InitialValueKnown {
                initial: value,
            }))
        } else {
            Ok(UpdatedOnce::TwoValuesKnown(TwoValuesKnown {
                initial: default,
                updated: value,
                bound: Bound::new(Slot::new(0), slot)?,
            }))
        }
    }

    pub fn value_at_slot(&self, slot: Slot) -> Result<T, UpdatedOnceError>
    where
        T: Copy,
    {
        match self {
            UpdatedOnce::OneValueKnown(OneValueKnown {
                value,
                first_seen,
                last_seen,
            }) => {
                if slot >= *first_seen && slot <= *last_seen {
                    Ok(*value)
                } else {
                    // FIXME(sproul): unpanic
                    panic!("out of bounds on one value: {slot}, {first_seen}, {last_seen}")
                    /*
                    Err(UpdatedOnceError::OutOfBoundsOneValue {
                        slot,
                        first_seen: *first_seen,
                        last_seen: *last_seen,
                    })
                    */
                }
            }
            UpdatedOnce::InitialValueKnown(InitialValueKnown { initial }) => {
                // FIXME(sproul): bounds checking with relation to `latest_restore_point_slot`.
                Ok(*initial)
            }
            UpdatedOnce::TwoValuesKnown(TwoValuesKnown {
                initial,
                updated,
                bound,
            }) => {
                // Prefer updated value in case of equal lower & upper bounds. This covers the
                // genesis validators who have their activation epoch immediately updated to 0.
                if slot >= bound.upper {
                    Ok(*updated)
                } else if slot <= bound.lower {
                    Ok(*initial)
                } else {
                    Err(UpdatedOnceError::OutOfBoundsBetween {
                        slot,
                        bound: *bound,
                    })
                }
            }
        }
    }

    pub fn update(
        &mut self,
        slot: Slot,
        latest_restore_point_slot: Slot,
        new_value: T,
    ) -> Result<bool, UpdatedOnceError>
    where
        T: Copy,
    {
        match self {
            UpdatedOnce::OneValueKnown(OneValueKnown {
                value,
                first_seen,
                last_seen,
            }) => {
                if *value == new_value {
                    if slot < *first_seen {
                        // New knowledge of when this value was first seen.
                        *first_seen = slot;
                        Ok(true)
                    } else if slot > *last_seen {
                        // New knowledge of when this value was last seen.
                        *last_seen = slot;
                        Ok(true)
                    } else {
                        // No new information. No-op.
                        Ok(false)
                    }
                } else if slot > *last_seen {
                    // Learnt the updated value and have bounds for the update slot.
                    // We know the lower bound for the update slot is `> last_seen` because
                    // it still had the initial value at `last_seen`.
                    *self = UpdatedOnce::TwoValuesKnown(TwoValuesKnown {
                        initial: *value,
                        updated: new_value,
                        bound: Bound::new(*last_seen, slot)?,
                    });
                    Ok(true)
                } else if slot < *first_seen {
                    // Learnt the initial value and bounds.
                    // We know the update slot must be greater than `slot` because the field still
                    // has the initial value at `slot`. Similarly the update slot must be <= the
                    // `first_seen` value because we know it had updated by that point.
                    *self = UpdatedOnce::TwoValuesKnown(TwoValuesKnown {
                        initial: new_value,
                        updated: *value,
                        bound: Bound::new(slot, *first_seen)?,
                    });
                    Ok(true)
                } else {
                    Err(UpdatedOnceError::OneValueKnownConflict {
                        slot,
                        first_seen: *first_seen,
                        last_seen: *last_seen,
                    })
                }
            }
            UpdatedOnce::InitialValueKnown(InitialValueKnown { initial }) => {
                if *initial == new_value {
                    // No new information
                    Ok(false)
                } else if slot >= latest_restore_point_slot {
                    // Value has been updated to a new value at `slot` and could lie anywhere
                    // between `latest_restore_point` and the `slot` we've seen the updated value
                    // at.
                    *self = UpdatedOnce::TwoValuesKnown(TwoValuesKnown {
                        initial: *initial,
                        updated: new_value,
                        bound: Bound::new(latest_restore_point_slot - 1, slot)?,
                    });
                    Ok(true)
                } else {
                    // Invalid mutation, we should not be seeing updates during state reconstruction
                    // which are not applied at the head. This implies the update is applied and
                    // later reverted, which doesn't make any sense for an updated-once field.
                    Err(UpdatedOnceError::InitialValueKnownConflict {
                        slot,
                        latest_restore_point_slot,
                    })
                }
            }
            UpdatedOnce::TwoValuesKnown(TwoValuesKnown {
                initial,
                updated,
                bound,
            }) => {
                if *initial == new_value {
                    if slot <= bound.lower {
                        // Value matches initial and is in the range implied by `bound`. No-op.
                        Ok(false)
                    } else if slot < bound.upper {
                        // New information about the initial value, it is seen at `slot` which
                        // raises the lower bound to `slot`.
                        bound.lower = slot;
                        Ok(true)
                    } else {
                        Err(UpdatedOnceError::TwoValuesKnownInitialConflict {
                            slot,
                            bound: *bound,
                        })
                    }
                } else if *updated == new_value {
                    if slot >= bound.upper {
                        // Value matches updated and provides no new information. No-op.
                        Ok(false)
                    } else if slot > bound.lower {
                        // New information about the updated value lowering the upper bound.
                        bound.upper = slot;
                        Ok(true)
                    } else {
                        Err(UpdatedOnceError::TwoValuesKnownUpdatedConflict {
                            slot,
                            bound: *bound,
                        })
                    }
                } else {
                    // Value is equal to neither the initial nor updated value, something is very
                    // very wrong.
                    Err(UpdatedOnceError::TwoValuesKnownThirdValueConflict { slot })
                }
            }
        }
    }
}

impl UpdatedOnceValidator {
    pub fn from_validator(
        validator: &Validator,
        slot: Slot,
        spec: &ChainSpec,
    ) -> Result<Self, UpdatedOnceError> {
        let far_future_epoch = spec.far_future_epoch;

        // BLS withdrawal credentials are always initial values.
        let withdrawal_credentials = if !validator.has_eth1_withdrawal_credential(spec) {
            UpdatedOnce::InitialValueKnown(InitialValueKnown {
                initial: validator.withdrawal_credentials(),
            })
        } else {
            UpdatedOnce::OneValueKnown(OneValueKnown {
                value: validator.withdrawal_credentials(),
                first_seen: slot,
                last_seen: slot,
            })
        };
        let slashed =
            UpdatedOnce::from_field_with_initial_default(validator.slashed(), slot, |x| !x, false)?;
        let activation_eligibility_epoch = UpdatedOnce::from_field_with_initial_default(
            validator.activation_eligibility_epoch(),
            slot,
            |epoch| epoch == 0 || epoch == far_future_epoch,
            far_future_epoch,
        )?;
        let activation_epoch = UpdatedOnce::from_field_with_initial_default(
            validator.activation_epoch(),
            slot,
            |epoch| epoch == 0 || epoch == far_future_epoch,
            far_future_epoch,
        )?;
        let exit_epoch = UpdatedOnce::from_field_with_initial_default(
            validator.exit_epoch(),
            slot,
            |epoch| epoch == far_future_epoch,
            far_future_epoch,
        )?;
        let withdrawable_epoch = UpdatedOnce::from_field_with_initial_default(
            validator.withdrawable_epoch(),
            slot,
            |epoch| epoch == far_future_epoch,
            far_future_epoch,
        )?;

        Ok(Self {
            withdrawal_credentials,
            slashed,
            activation_eligibility_epoch,
            activation_epoch,
            exit_epoch,
            withdrawable_epoch,
        })
    }

    pub fn into_validator_mutable(
        &self,
        effective_balance: u64,
        slot: Slot,
    ) -> Result<ValidatorMutable, UpdatedOnceError> {
        let withdrawal_credentials = self.withdrawal_credentials.value_at_slot(slot)?;
        let slashed = self.slashed.value_at_slot(slot)?;
        let activation_eligibility_epoch = self.activation_eligibility_epoch.value_at_slot(slot)?;
        let activation_epoch = self.activation_epoch.value_at_slot(slot)?;
        let exit_epoch = self.exit_epoch.value_at_slot(slot)?;
        let withdrawable_epoch = self.withdrawable_epoch.value_at_slot(slot)?;
        Ok(ValidatorMutable {
            withdrawal_credentials,
            effective_balance,
            slashed,
            activation_eligibility_epoch,
            activation_epoch,
            exit_epoch,
            withdrawable_epoch,
        })
    }

    /// Update our knowledge of `self` at `slot` using data from `validator`.
    ///
    /// The `slot` *must* be a finalized or the update will corrupt the store.
    ///
    /// Return the number of updated fields.
    pub fn update_knowledge(
        &mut self,
        validator: &Validator,
        slot: Slot,
        latest_restore_point_slot: Slot,
    ) -> Result<usize, UpdatedOnceError> {
        let mut num_updated = 0;

        macro_rules! update_field {
            ($field_name:ident) => {
                let updated = self.$field_name.update(
                    slot,
                    latest_restore_point_slot,
                    validator.$field_name(),
                )?;
                if updated {
                    num_updated += 1;
                }
            };
        }

        update_field!(withdrawal_credentials);
        update_field!(slashed);
        update_field!(activation_eligibility_epoch);
        update_field!(activation_epoch);
        update_field!(exit_epoch);
        update_field!(withdrawable_epoch);

        Ok(num_updated)
    }

    /// The dummy value is used for validators that do not yet exist in the finalized database.
    pub fn dummy() -> Self {
        Self {
            withdrawal_credentials: UpdatedOnce::dummy(),
            slashed: UpdatedOnce::dummy(),
            activation_eligibility_epoch: UpdatedOnce::dummy(),
            activation_epoch: UpdatedOnce::dummy(),
            exit_epoch: UpdatedOnce::dummy(),
            withdrawable_epoch: UpdatedOnce::dummy(),
        }
    }

    pub fn is_dummy(&self) -> bool {
        self.withdrawal_credentials.is_dummy()
            && self.slashed.is_dummy()
            && self.activation_eligibility_epoch.is_dummy()
            && self.activation_epoch.is_dummy()
            && self.exit_epoch.is_dummy()
            && self.withdrawable_epoch.is_dummy()
    }
}
