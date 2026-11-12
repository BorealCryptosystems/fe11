// SPDX-License-Identifier: Apache-2.0
//! Prepaid projections retained across compound observations.
//!
//! Public report getters borrow these values. An explicit report clone belongs
//! to its consumer and intentionally does not duplicate the module reservation.
use super::*;

pub(crate) struct AttributeSnapshot {
    fields: Vec<CK_ATTRIBUTE_TYPE>,
    values: Vec<AttributeValue>,
    credit: Option<Credit>,
}
impl Default for AttributeSnapshot {
    fn default() -> Self {
        Self {
            fields: Vec::new(),
            values: Vec::new(),
            credit: None,
        }
    }
}
impl Clone for AttributeSnapshot {
    fn clone(&self) -> Self {
        Self {
            fields: self.fields.clone(),
            values: self.values.clone(),
            credit: None,
        }
    }
}
impl std::fmt::Debug for AttributeSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map()
            .entries(self.fields.iter().zip(&self.values))
            .finish()
    }
}
impl PartialEq for AttributeSnapshot {
    fn eq(&self, other: &Self) -> bool {
        self.fields == other.fields && self.values == other.values
    }
}
impl Eq for AttributeSnapshot {}
impl AttributeSnapshot {
    pub(crate) fn from_credited_parts(
        fields: Vec<CK_ATTRIBUTE_TYPE>,
        values: Vec<AttributeValue>,
        mut credit: Credit,
    ) -> Result<Self> {
        let mut snapshot = Self::from_parts(fields, values)?;
        let bytes =
            snapshot
                .values
                .iter()
                .try_fold(snapshot.allocated_bytes()?, |total, value| {
                    total
                        .checked_add(match value {
                            AttributeValue::Available(bytes) => bytes.capacity(),
                            _ => 0,
                        })
                        .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                            crate::KeyAdmissionRejection::AttributeProjectionStorageSize,
                        )))
                })?;
        snapshot.credit = Some(credit.split(bytes)?);
        Ok(snapshot)
    }
    pub(crate) fn all_available(&self) -> bool {
        self.values
            .iter()
            .all(|value| matches!(value, AttributeValue::Available(_)))
    }
    pub(crate) fn bytes(&self, field: CK_ATTRIBUTE_TYPE) -> crate::Observation<&[u8]> {
        use crate::{AttributeUnavailableCause as Cause, Observation};
        match self.get(field) {
            AttributeValue::Available(bytes) => Observation::Observed(bytes),
            AttributeValue::Sensitive => Observation::Unavailable(Cause::Sensitive),
            AttributeValue::Unsupported => Observation::Unavailable(Cause::Unsupported),
            AttributeValue::Indeterminate => Observation::Unavailable(Cause::Unspecified),
            AttributeValue::NotRequested => Observation::NotRequested,
        }
    }
    pub(crate) fn select(mut self, selected: &[crate::Attribute]) -> Self {
        for (field, value) in self.fields.iter().zip(&mut self.values) {
            if selected.iter().any(|selected| selected.raw() == *field) {
                continue;
            }
            let discarded = std::mem::replace(value, AttributeValue::NotRequested);
            let bytes = match &discarded {
                AttributeValue::Available(bytes) => bytes.capacity(),
                _ => 0,
            };
            drop(discarded);
            if let Some(credit) = &mut self.credit {
                credit.release(bytes);
            }
        }
        self
    }
    pub(crate) fn from_parts(
        fields: Vec<CK_ATTRIBUTE_TYPE>,
        values: Vec<AttributeValue>,
    ) -> Result<Self> {
        if fields.len() != values.len() {
            return Err(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::AttributeProjectionCount,
                ),
            ));
        }
        Ok(Self {
            fields,
            values,
            credit: None,
        })
    }
    pub(crate) fn get(&self, field: CK_ATTRIBUTE_TYPE) -> &AttributeValue {
        self.fields
            .iter()
            .position(|value| *value == field)
            .map_or(&AttributeValue::NotRequested, |index| &self.values[index])
    }
    pub(crate) fn len(&self) -> usize {
        self.values.len()
    }

    pub(super) fn requested(count: usize) -> Result<usize> {
        count
            .checked_mul(
                std::mem::size_of::<CK_ATTRIBUTE_TYPE>() + std::mem::size_of::<AttributeValue>(),
            )
            .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AttributeProjectionStorageSize,
            )))
    }
    pub(super) fn allocate(recipe: Recipe<'_>) -> Result<Self> {
        let count = recipe.export_len();
        let mut fields = reserved(count)?;
        let mut values = reserved(count)?;
        for index in 0..count {
            fields.push(recipe.export_field(index));
            values.push(AttributeValue::Indeterminate);
        }
        Ok(Self {
            fields,
            values,
            credit: None,
        })
    }
    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        self.fields
            .capacity()
            .checked_mul(std::mem::size_of::<CK_ATTRIBUTE_TYPE>())
            .and_then(|bytes| {
                self.values
                    .capacity()
                    .checked_mul(std::mem::size_of::<AttributeValue>())
                    .and_then(|more| bytes.checked_add(more))
            })
            .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AttributeProjectionStorageSize,
            )))
    }
    pub(super) fn bind(mut self, prepaid: &mut Credit) -> Result<Self> {
        let bytes = self.allocated_bytes()?;
        if bytes != 0 {
            self.credit = Some(prepaid.split(bytes)?);
        }
        Ok(self)
    }
    pub(super) fn field(&self, index: usize) -> CK_ATTRIBUTE_TYPE {
        self.fields[index]
    }
    pub(super) fn set_refusal(&mut self, index: usize, value: &PreciseAttributeValue) {
        self.values[index] = match value {
            PreciseAttributeValue::Sensitive => AttributeValue::Sensitive,
            PreciseAttributeValue::Unsupported => AttributeValue::Unsupported,
            PreciseAttributeValue::Indeterminate => AttributeValue::Indeterminate,
            PreciseAttributeValue::Available(_) => {
                unreachable!("available projection requires prepared bytes")
            }
        };
    }
    pub(super) fn set_copy(
        &mut self,
        index: usize,
        mut copy: PublicCopy,
        bytes: &[u8],
    ) -> Result<()> {
        if copy.bytes.len() != bytes.len() {
            return Err(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::AttributeProjectionLengthChanged,
                ),
            ));
        }
        copy.bytes.copy_from_slice(bytes);
        self.credit
            .as_mut()
            .ok_or(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::AttributeProjectionCreditAbsent,
                ),
            ))?
            .merge_retained(&mut copy.credit)?;
        self.values[index] = AttributeValue::Available(copy.bytes);
        Ok(())
    }
    /// Final public Vec handoff. No internal phase may discard this retention
    /// while keeping the values; inventory uses map_retaining instead.
    pub(crate) fn into_values(self) -> Vec<AttributeValue> {
        self.values
    }
    /// The private converter consumes and destroys the temporary value table;
    /// its result keeps only the value payloads (the inventory row converter).
    pub(crate) fn map_retaining<T>(
        mut self,
        owner: &mut Credit,
        convert: impl FnOnce(Vec<AttributeValue>) -> Result<T>,
    ) -> Result<T> {
        let field_bytes = self
            .fields
            .capacity()
            .checked_mul(std::mem::size_of::<CK_ATTRIBUTE_TYPE>())
            .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AttributeProjectionStorageSize,
            )))?;
        let table_bytes = self
            .values
            .capacity()
            .checked_mul(std::mem::size_of::<AttributeValue>())
            .and_then(|bytes| bytes.checked_add(field_bytes))
            .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AttributeProjectionStorageSize,
            )))?;
        drop(self.fields);
        let result = convert(self.values)?;
        if let Some(mut credit) = self.credit.take() {
            credit.release(table_bytes);
            owner.merge(credit)?;
        }
        Ok(result)
    }
}

pub(crate) struct PublicCopy {
    bytes: Vec<u8>,
    credit: Credit,
}

/// The original report retains its decoded payload credit. Consumer clones
/// own independent vectors, outside the module's allocation contract.
pub(crate) struct MechanismValues {
    observation: crate::Observation<Vec<u64>>,
    _credit: Option<Credit>,
}
impl Clone for MechanismValues {
    fn clone(&self) -> Self {
        Self::from_observation(self.observation.clone())
    }
}
impl std::fmt::Debug for MechanismValues {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.observation.fmt(f)
    }
}
impl PartialEq for MechanismValues {
    fn eq(&self, other: &Self) -> bool {
        self.observation == other.observation
    }
}
impl Eq for MechanismValues {}
impl MechanismValues {
    pub(crate) fn decode_prepared(
        bytes: &[u8],
        mut values: Vec<u64>,
        mut credit: Credit,
    ) -> Result<Self> {
        let width = std::mem::size_of::<CK_MECHANISM_TYPE>();
        if bytes.len() % width != 0 {
            return Ok(Self::from_observation(crate::Observation::Unusable(
                crate::ObservationIssue::MechanismListEncoding,
            )));
        }
        if !values.is_empty() || values.capacity() < bytes.len() / width {
            return Err(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::MechanismProjectionCapacity,
                ),
            ));
        }
        let allocated = values
            .capacity()
            .checked_mul(std::mem::size_of::<u64>())
            .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::MechanismProjectionStorageSize,
            )))?;
        let retained = credit.split(allocated)?;
        values.extend(crate::attributes::mechanisms(bytes)?.map(|value| value as u64));
        Ok(Self {
            observation: crate::Observation::Observed(values),
            _credit: Some(retained),
        })
    }
    pub(crate) fn from_observation(observation: crate::Observation<Vec<u64>>) -> Self {
        Self {
            observation,
            _credit: None,
        }
    }
    pub(crate) fn observation(&self) -> &crate::Observation<Vec<u64>> {
        &self.observation
    }
}

pub(crate) struct MechanismCopy {
    values: Vec<u64>,
    credit: Credit,
}
impl MechanismCopy {
    pub(super) fn prepare(
        length: usize,
        budget: &std::sync::Arc<crate::symmetric::memory::Budget>,
        policy: &crate::ResourceAdmission,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        let width = std::mem::size_of::<CK_MECHANISM_TYPE>();
        if length % width != 0 {
            return Err(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::MechanismProjectionWidth,
                ),
            ));
        }
        let count = length / width;
        let mut required = count
            .checked_mul(std::mem::size_of::<u64>())
            .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::MechanismProjectionStorageSize,
            )))?;
        loop {
            let mut credit = match budget.reserve_controlled_retaining(
                required,
                crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
                policy,
                || {
                    check()?;
                    Ok(None::<()>)
                },
                || Ok(None),
            )? {
                crate::symmetric::memory::ControlledReservation::Acquired(credit) => credit,
                crate::symmetric::memory::ControlledReservation::Redirect(()) => {
                    unreachable!("no redirect requested")
                }
            };
            let values: Vec<u64> = reserved(count)?;
            let actual = values
                .capacity()
                .checked_mul(std::mem::size_of::<u64>())
                .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::MechanismProjectionStorageSize,
                )))?;
            if actual > required {
                drop(values);
                drop(credit);
                required = actual;
                continue;
            }
            credit.release(required - actual);
            return Ok(Self { values, credit });
        }
    }
    pub(super) fn decode(mut self, bytes: &[u8]) -> Result<MechanismValues> {
        let count = bytes.len() / std::mem::size_of::<CK_MECHANISM_TYPE>();
        if count > self.values.capacity() {
            return Err(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::MechanismProjectionCapacity,
                ),
            ));
        }
        self.values
            .extend(crate::attributes::mechanisms(bytes)?.map(|value| value as u64));
        Ok(MechanismValues {
            observation: crate::Observation::Observed(self.values),
            _credit: Some(self.credit),
        })
    }
}
impl PublicCopy {
    pub(super) fn prepare(
        length: usize,
        budget: &std::sync::Arc<crate::symmetric::memory::Budget>,
        policy: &crate::ResourceAdmission,
        mut check: impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        let mut required = length;
        loop {
            let mut credit = match budget.reserve_controlled_retaining(
                required,
                crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
                policy,
                || {
                    check()?;
                    Ok(None::<()>)
                },
                || Ok(None),
            )? {
                crate::symmetric::memory::ControlledReservation::Acquired(credit) => credit,
                crate::symmetric::memory::ControlledReservation::Redirect(()) => {
                    unreachable!("no redirect requested")
                }
            };
            let mut bytes = reserved(length)?;
            if bytes.capacity() > required {
                required = bytes.capacity();
                drop(bytes);
                drop(credit);
                continue;
            }
            credit.release(required - bytes.capacity());
            bytes.resize(length, 0);
            return Ok(Self { bytes, credit });
        }
    }
}
