use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::sync::Arc;
use types::{
    BeaconState, ChainSpec, Epoch, Hash256, PublicKeyBytes, Slot, Validator, ValidatorMutable,
};

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
        lower: Slot,
        upper: Slot,
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
}

/// A bound represents possibly partial knowledge of the point in time at which an
/// updated-once field changes.
#[derive(Debug, Encode, Decode, Clone, Copy)]
#[ssz(enum_behaviour = "union")]
pub enum Bound {
    Exact(ExactBound),
    Between(BetweenBound),
}

/// The update slot for the field is known exactly.
///
/// All states at `slot >= self.update_slot` have the updated value, and all states at `slot <
/// self.update_slot` have the initial value.
#[derive(Debug, Encode, Decode, Clone, Copy)]
pub struct ExactBound {
    pub update_slot: Slot,
}

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
#[derive(Debug, Encode, Decode, Clone, Copy)]
pub struct BetweenBound {
    pub lower: Slot,
    pub upper: Slot,
}

/// A single value is known for the field but we don't know whether it is the initial or updated
/// value.
///
/// If it is the initial value then the update slot lies at some point in the future `> last_seen`.
/// If it is the updated value then the update slot lies at some point in the past `<= first_seen`.
#[derive(Debug, Encode, Decode)]
pub struct OneValueKnown<T: Encode + Decode> {
    pub value: T,
    pub first_seen: Slot,
    pub last_seen: Slot,
}

/// The initial value is known for the field and we don't know of any updates for it (yet).
///
/// The update slot is certainly in the future at a slot `> lower_bound`. Equivalently we know
/// that the initial value is valid for all slots `<= lower_bound`.
#[derive(Debug, Encode, Decode)]
pub struct InitialValueKnown<T: Encode + Decode> {
    pub initial: T,
    pub lower_bound: Slot,
}

#[derive(Debug, Encode, Decode)]
pub struct TwoValuesKnown<T: Encode + Decode> {
    pub initial: T,
    pub updated: T,
    pub bound: Bound,
}

#[derive(Debug, Encode, Decode)]
#[ssz(enum_behaviour = "union")]
pub enum UpdatedOnce<T: Encode + Decode> {
    OneValueKnown(OneValueKnown<T>),
    InitialValueKnown(InitialValueKnown<T>),
    TwoValuesKnown(TwoValuesKnown<T>),
}

/// Succinct representation of the updated-once fields of a validator.
#[derive(Debug, Encode, Decode)]
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
        if lower + 1 == upper {
            Ok(Bound::Exact(ExactBound { update_slot: upper }))
        } else if lower < upper {
            Ok(Bound::Between(BoundBetween { lower, upper }))
        } else {
            Err(UpdatedOnceError::InvalidBound { lower, upper })
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

    pub fn from_field_with_initial_default(value: T, slot: Slot, default: T) -> Self {
        if value != default {
            UpdatedOnce::TwoValuesKnown(TwoValuesKnown {
                initial: default,
                updated: value,
                bound: Bound::Between(BetweenBound {
                    lower: Slot::new(0),
                    upper: slot,
                }),
            })
        } else {
            UpdatedOnce::InitialValueKnown(InitialValueKnown {
                initial: value,
                lower_bound: slot,
            })
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
                    Err(UpdatedOnceError::OutOfBoundsOneValue {
                        slot,
                        first_seen: *first_seen,
                        last_seen: *last_seen,
                    })
                }
            }
            UpdatedOnce::InitialValueKnown(InitialValueKnown {
                initial,
                lower_bound,
            }) => {
                if slot <= *lower_bound {
                    Ok(*initial)
                } else {
                    Err(UpdatedOnceError::OutOfBoundsInitialValue {
                        slot,
                        lower_bound: *lower_bound,
                    })
                }
            }
            UpdatedOnce::TwoValuesKnown(TwoValuesKnown {
                initial,
                updated,
                bound,
            }) => match *bound {
                Bound::Exact(ExactBound { update_slot }) => {
                    if slot >= update_slot {
                        Ok(*updated)
                    } else {
                        Ok(*initial)
                    }
                }
                Bound::Between(BetweenBound { lower, upper }) => {
                    if slot <= lower {
                        Ok(*initial)
                    } else if slot >= upper {
                        Ok(*updated)
                    } else {
                        Err(UpdatedOnceError::OutOfBoundsBetween { slot, lower, upper })
                    }
                }
            },
        }
    }

    pub fn update(&mut self, slot: Slot, new_value: T) -> Result<bool, UpdatedOnceError>
    where
        T: Copy,
    {
        match self {
            UpdatedOnce::OneValueKnown(OneValueKnown {
                value,
                first_seen,
                last_seen,
            }) => {
                if value == new_value {
                    // No new information. No-op.
                    Ok(false)
                } else if slot > last_seen {
                    // Learnt the updated value and have bounds for the update slot.
                    // We know the lower bound for the update slot is `> last_seen` because
                    // it still had the initial value at `last_seen`.
                    *self = UpdatedOnce::TwoValuesKnown(TwoValuesKnown {
                        initial: value,
                        updated: new_value,
                        bound: Bound::new(last_seen, slot),
                    });
                    Ok(true)
                } else if slot < first_seen {
                    // Learnt the initial value and bounds.
                    // We know the update slot must be greater than `slot` because the field still
                    // has the initial value at `slot`. Similarly the update slot must be <= the
                    // `first_seen` value because we know it had updated by that point.
                    *self = UpdatedOnce::TwoValuesKnown(TwoValuesKnown {
                        initial: new_value,
                        updated: value,
                        bound: Bound::new(slot, first_seen),
                    });
                    Ok(true)
                } else {
                    Err(UpdatedOnceError::OneValueKnownConflict {
                        slot,
                        first_seen,
                        last_seen,
                    })
                }
            }
        }
    }
}

impl UpdatedOnceValidator {
    pub fn from_validator(validator: &Validator, slot: Slot, spec: &ChainSpec) -> Self {
        let far_future_epoch = spec.far_future_epoch;

        let withdrawal_credentials = UpdatedOnce::OneValueKnown(OneValueKnown {
            value: validator.withdrawal_credentials(),
            first_seen: slot,
            last_seen: slot,
        });
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
            validator.withdrawable_epoch(),
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
    pub fn update_knowledge(&mut self, slot: Slot, validator: &Validator) -> Result<bool, Error> {}

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
}
