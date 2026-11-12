// SPDX-License-Identifier: Apache-2.0
//! Attribute response ownership. Native completion and local acceptance are
//! separate phases: resource admission never repeats a completed native call.
use crate::{
    attributes::{AlignedOutput, PreciseAttributeValue},
    bounds,
    error::check,
    symmetric::memory::{Budget, ControlledReservation, Credit},
    Error, Result,
};
use fe11_sys::{
    CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID, CKR_OK, CK_ATTRIBUTE, CK_ATTRIBUTE_TYPE,
    CK_RV, CK_ULONG, CK_UNAVAILABLE_INFORMATION,
};
use std::sync::Arc;
mod preparation;
mod recipe;
pub(super) use preparation::PlansStorage;
pub(super) use preparation::{ReadOwner, ReadPlan, ReadPlans};

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadStage {
    Size,
    SizeReceived { rv: CK_RV },
    Values,
    ValuesReceived { rv: CK_RV, accepted: usize },
    Done { rv: CK_RV },
    Consumed,
}

struct ReadBuffer {
    value: AlignedOutput,
    _credit: Credit,
}

// A consumed index can never be mistaken for a missing native owner.
enum Slot {
    Live(ReadBuffer),
    Indeterminate,
    Accepted,
}

/// Immutable scalar sizing metadata; no native pointers or source allocations.
/// Its allocation is prepared with the read frame, before a sizing response.
pub(crate) struct SizePlan {
    lengths: Vec<Option<usize>>,
    bytes: usize,
    _credit: Credit,
}

#[derive(Clone)]
pub(crate) enum ReadNeed {
    Frame(Arc<ReadPlan>),
    Sizes(Arc<SizePlan>),
    Value {
        position: usize,
        length: usize,
        decode_mechanisms: bool,
    },
}
impl ReadNeed {
    pub(crate) fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Frame(a), Self::Frame(b)) => Arc::ptr_eq(a, b),
            (Self::Sizes(a), Self::Sizes(b)) => Arc::ptr_eq(a, b),
            (
                Self::Value {
                    position: a,
                    length: x,
                    decode_mechanisms: mx,
                },
                Self::Value {
                    position: b,
                    length: y,
                    decode_mechanisms: my,
                },
            ) => a == b && x == y && mx == my,
            _ => false,
        }
    }
}

pub(crate) struct ReadCandidate {
    need: ReadNeed,
    storage: PreparedStorage,
    // Storage is destroyed before aggregate credit, including failed candidates.
    credit: Credit,
}
enum PreparedStorage {
    Frame(ReadFrame),
    Sizes(Vec<Slot>),
    Value { bytes: Vec<u8>, decoded: Vec<u64> },
}
pub(crate) enum PreparedRead<T> {
    Ready(ReadCandidate),
    Redirect(T),
}
fn decoded_bytes(length: usize, selected: bool) -> Result<usize> {
    let width = std::mem::size_of::<fe11_sys::CK_MECHANISM_TYPE>();
    if !selected || length % width != 0 {
        return Ok(0);
    }
    (length / width)
        .checked_mul(std::mem::size_of::<u64>())
        .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
            crate::KeyAdmissionRejection::MechanismProjectionStorageSize,
        )))
}
impl ReadCandidate {
    pub(crate) fn need(&self) -> &ReadNeed {
        &self.need
    }

    /// Called with no module/token/session/operation guard. Retained operation
    /// storage stays charged to its private account; this call's separate
    /// envelope is included explicitly. Discard the whole candidate before an
    /// allocator-excess retry.
    pub(crate) fn prepare<T>(
        need: ReadNeed,
        budget: &Arc<Budget>,
        retained_bytes: usize,
        admission: &crate::ResourceAdmission,
        mut before: impl FnMut() -> Result<Option<T>>,
    ) -> Result<PreparedRead<T>> {
        if let ReadNeed::Frame(plan) = need {
            return preparation::prepare_frame(plan, budget, retained_bytes, admission, before);
        }
        let mut required = match &need {
            ReadNeed::Frame(_) => unreachable!(),
            ReadNeed::Sizes(plan) => plan
                .bytes
                .checked_add(
                    plan.lengths
                        .len()
                        .checked_mul(std::mem::size_of::<Slot>())
                        .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                            crate::KeyAdmissionRejection::OwnedAttributeMetadata,
                        )))?,
                )
                .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::OwnedAttributeMetadata,
                )))?,
            ReadNeed::Value {
                length,
                decode_mechanisms,
                ..
            } => length
                .checked_add(decoded_bytes(*length, *decode_mechanisms)?)
                .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::OwnedAttributeMetadata,
                )))?,
        };
        loop {
            let mut credit = match budget.reserve_controlled_retaining(
                required,
                crate::session::lifecycle_diagnostics::Store::including(retained_bytes)?,
                admission,
                &mut before,
                || Ok(None),
            )? {
                ControlledReservation::Acquired(credit) => credit,
                ControlledReservation::Redirect(route) => return Ok(PreparedRead::Redirect(route)),
            };
            let (storage, allocated) =
                match &need {
                    ReadNeed::Frame(_) => unreachable!(),
                    ReadNeed::Sizes(plan) => {
                        let mut slots = Vec::new();
                        slots.try_reserve_exact(plan.lengths.len()).map_err(|_| {
                            Error::Rejected(crate::RejectionReason::KeyAdmission(
                                crate::KeyAdmissionRejection::OwnedAttributeAllocation,
                            ))
                        })?;
                        let mut allocated = slots
                            .capacity()
                            .checked_mul(std::mem::size_of::<Slot>())
                            .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                                crate::KeyAdmissionRejection::OwnedAttributeMetadata,
                            )))?;
                        for length in &plan.lengths {
                            slots.push(match length {
                                None => Slot::Indeterminate,
                                Some(length) => {
                                    let value = AlignedOutput::new(*length)?;
                                    allocated = allocated
                                        .checked_add(value.allocated_bytes()?)
                                        .ok_or(Error::Rejected(
                                        crate::RejectionReason::AttributePreparation(
                                            crate::AttributePreparationRejection::AttributeTotal,
                                        ),
                                    ))?;
                                    // Aggregate credit covers this candidate until all
                                    // real capacities have been checked together.
                                    Slot::Live(ReadBuffer {
                                        value,
                                        _credit: credit.split(0)?,
                                    })
                                }
                            });
                        }
                        (PreparedStorage::Sizes(slots), allocated)
                    }
                    ReadNeed::Value {
                        length,
                        decode_mechanisms,
                        ..
                    } => {
                        let mut value = Vec::new();
                        value.try_reserve_exact(*length).map_err(|_| {
                            Error::Rejected(crate::RejectionReason::KeyAdmission(
                                crate::KeyAdmissionRejection::OwnedAttributeAllocation,
                            ))
                        })?;
                        let mut decoded = Vec::new();
                        decoded
                            .try_reserve_exact(
                                decoded_bytes(*length, *decode_mechanisms)?
                                    / std::mem::size_of::<u64>(),
                            )
                            .map_err(|_| {
                                Error::Rejected(crate::RejectionReason::KeyAdmission(
                                    crate::KeyAdmissionRejection::MechanismProjectionAllocation,
                                ))
                            })?;
                        let allocated = decoded
                            .capacity()
                            .checked_mul(std::mem::size_of::<u64>())
                            .and_then(|bytes| bytes.checked_add(value.capacity()))
                            .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                                crate::KeyAdmissionRejection::MechanismProjectionStorageSize,
                            )))?;
                        value.resize(*length, 0);
                        (
                            PreparedStorage::Value {
                                bytes: value,
                                decoded,
                            },
                            allocated,
                        )
                    }
                };
            if allocated > required {
                drop(storage);
                drop(credit);
                required = allocated;
                continue;
            }
            credit.release(required - allocated);
            let mut candidate = Self {
                need,
                storage,
                credit,
            };
            if let PreparedStorage::Sizes(slots) = &mut candidate.storage {
                for slot in slots {
                    if let Slot::Live(buffer) = slot {
                        buffer._credit = candidate.credit.split(buffer.value.allocated_bytes()?)?;
                    }
                }
            }
            return Ok(PreparedRead::Ready(candidate));
        }
    }
}

pub(in crate::advanced) struct ReadFrame {
    pub(super) kinds: Vec<CK_ATTRIBUTE_TYPE>,
    pub(super) attrs: Vec<CK_ATTRIBUTE>,
    indices: Vec<usize>,
    slots: Vec<Slot>,
    values: Vec<Option<PreciseAttributeValue>>,
    output: Vec<crate::AttributeValue>,
    stage: ReadStage,
    limit: usize,
    precise: bool,
    decode_mechanisms: bool,
    mechanisms: Option<crate::attributes::owned::resident::MechanismValues>,
    sizes: Arc<SizePlan>,
    pub(super) retained: Vec<Credit>,
    _slot_credit: Option<Credit>,
    _credit: Credit,
}
// SAFETY: descriptors point only to owned aligned buffers. They are frozen
// during native work. A returned batch is validated in full before local
// acceptance. Each consumed slot clears its descriptor before dropping storage;
// the cursor never dereferences a consumed descriptor or a provider pointer.
unsafe impl Send for ReadFrame {}

impl ReadFrame {
    pub(super) fn take_mechanisms(
        &mut self,
        values: &crate::attributes::ObservedAttributes,
    ) -> Result<crate::attributes::owned::resident::MechanismValues> {
        if !self.decode_mechanisms || !matches!(self.stage, ReadStage::Consumed) {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::MechanismProjectionPhase,
            )));
        }
        if let Some(values) = self.mechanisms.take() {
            return Ok(values);
        }
        let observation = match values.bytes(fe11_sys::CKA_ALLOWED_MECHANISMS) {
            crate::Observation::Unavailable(cause) => crate::Observation::Unavailable(cause),
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::MechanismProjectionAbsent,
                )))
            }
        };
        Ok(crate::attributes::owned::resident::MechanismValues::from_observation(observation))
    }

    pub(super) fn complete(&self) -> bool {
        matches!(self.stage, ReadStage::Done { .. })
    }
    pub(super) fn completed_rv(&self) -> Option<CK_RV> {
        match self.stage {
            ReadStage::Done { rv } => Some(rv),
            _ => None,
        }
    }

    /// Immutable descriptor identity is meaningful even when a refusal defines
    /// no length or value. The return barrier calls this before precise/partial
    /// acceptance can finish or an ordinary native error can escape.
    pub(super) fn validate_identity(&mut self) -> Result<()> {
        if self.attrs.len() != self.indices.len() {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AttributeDescriptorChanged,
            )));
        }
        for (attr, &index) in self.attrs.iter().zip(&self.indices) {
            if index >= self.kinds.len() || attr.r#type != self.kinds[index] {
                return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::AttributeDescriptorChanged,
                )));
            }
            let pointer = match self.stage {
                ReadStage::Size => std::ptr::null_mut(),
                ReadStage::Values => {
                    let Some(Slot::Live(buffer)) = self.slots.get_mut(index) else {
                        return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                            crate::KeyAdmissionRejection::AttributeOwnerAbsent,
                        )));
                    };
                    buffer.value.pointer()
                }
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::AttributeReadIncomplete,
                    )))
                }
            };
            if attr.pValue != pointer {
                return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::AttributeDescriptorChanged,
                )));
            }
        }
        Ok(())
    }

    // This is a pure pass over the entire native batch. Nothing is copied,
    // allocated, or accepted until every pointer, type and length is valid.
    fn validate_return(&mut self) -> Result<()> {
        if self.attrs.len() != self.indices.len() {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AttributeDescriptorChanged,
            )));
        }
        let mut total = 0usize;
        for (attr, &index) in self.attrs.iter().zip(&self.indices) {
            if index >= self.kinds.len() || attr.r#type != self.kinds[index] {
                return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::AttributeDescriptorChanged,
                )));
            }
            let length = match self.stage {
                ReadStage::Size => {
                    if !attr.pValue.is_null() {
                        return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                            crate::KeyAdmissionRejection::AttributeDescriptorChanged,
                        )));
                    }
                    if attr.ulValueLen == CK_UNAVAILABLE_INFORMATION {
                        continue;
                    }
                    bounds::count(attr.ulValueLen, self.limit)?
                }
                ReadStage::Values => {
                    let Some(Slot::Live(buffer)) = self.slots.get_mut(index) else {
                        return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                            crate::KeyAdmissionRejection::AttributeOwnerAbsent,
                        )));
                    };
                    if attr.pValue != buffer.value.pointer() {
                        return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                            crate::KeyAdmissionRejection::AttributeDescriptorChanged,
                        )));
                    }
                    if attr.ulValueLen == CK_UNAVAILABLE_INFORMATION {
                        continue;
                    }
                    if attr.ulValueLen as u128 > buffer.value.capacity as u128 {
                        return Err(Error::Rejected(
                            crate::RejectionReason::KeyAdmission(crate::KeyAdmissionRejection::AttributeLengthExceedsAllocatedValueBuffer),
                        ));
                    }
                    bounds::final_length(attr.ulValueLen, buffer.value.capacity)?
                }
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::AttributeReadIncomplete,
                    )))
                }
            };
            total = total
                .checked_add(length)
                .filter(|n| *n <= self.limit)
                .ok_or(Error::Rejected(
                    crate::RejectionReason::AttributePreparation(
                        crate::AttributePreparationRejection::AttributeTotal,
                    ),
                ))?;
        }
        Ok(())
    }

    pub(super) fn accept(&mut self, rv: CK_RV) -> Result<()> {
        if !matches!(
            rv,
            CKR_OK | CKR_ATTRIBUTE_SENSITIVE | CKR_ATTRIBUTE_TYPE_INVALID
        ) {
            return check(rv, "C_GetAttributeValue", false);
        }
        if !matches!(self.stage, ReadStage::Size | ReadStage::Values) {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::DuplicateAdmissionCompletion,
            )));
        }
        if self.precise && matches!(rv, CKR_ATTRIBUTE_SENSITIVE | CKR_ATTRIBUTE_TYPE_INVALID) {
            self.values[0] = Some(if rv == CKR_ATTRIBUTE_SENSITIVE {
                PreciseAttributeValue::Sensitive
            } else {
                PreciseAttributeValue::Unsupported
            });
            self.stage = ReadStage::Done { rv };
            return Ok(());
        }
        self.validate_return()?;
        match self.stage {
            ReadStage::Size => {
                let plan = Arc::get_mut(&mut self.sizes).ok_or(Error::Rejected(
                    crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::AttributeSizingOwnerShared,
                    ),
                ))?;
                let width = std::mem::size_of::<CK_ULONG>();
                for (attr, &index) in self.attrs.iter().zip(&self.indices) {
                    if attr.ulValueLen != CK_UNAVAILABLE_INFORMATION {
                        let length = bounds::count(attr.ulValueLen, self.limit)?;
                        let aligned = length.checked_add(width - 1).ok_or(Error::Rejected(
                            crate::RejectionReason::AttributePreparation(
                                crate::AttributePreparationRejection::AttributeAlignmentSize,
                            ),
                        ))? / width
                            * width;
                        plan.bytes = plan.bytes.checked_add(aligned).ok_or(Error::Rejected(
                            crate::RejectionReason::AttributePreparation(
                                crate::AttributePreparationRejection::AttributeTotal,
                            ),
                        ))?;
                        plan.lengths[index] = Some(length);
                    }
                }
                self.stage = ReadStage::SizeReceived { rv };
            }
            ReadStage::Values => {
                self.stage = ReadStage::ValuesReceived { rv, accepted: 0 };
                self.advance_indeterminate()?;
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    pub(super) fn need(&self) -> Option<ReadNeed> {
        match self.stage {
            ReadStage::SizeReceived { .. } => Some(ReadNeed::Sizes(self.sizes.clone())),
            ReadStage::ValuesReceived { accepted, .. } => Some(ReadNeed::Value {
                position: accepted,
                length: self.attrs[accepted].ulValueLen as usize,
                decode_mechanisms: self.decode_mechanisms,
            }),
            _ => None,
        }
    }

    pub(super) fn attach(&mut self, mut candidate: ReadCandidate) -> Result<()> {
        if !self.need().is_some_and(|need| need.same(candidate.need())) {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AttributePreparationChanged,
            )));
        }
        match (self.stage, candidate.storage) {
            (ReadStage::SizeReceived { rv }, PreparedStorage::Sizes(slots)) => {
                self.slots = slots;
                self._slot_credit = Some(candidate.credit);
                self.attrs.clear();
                self.indices.clear();
                for (index, slot) in self.slots.iter_mut().enumerate() {
                    match slot {
                        Slot::Live(buffer) => {
                            self.attrs.push(CK_ATTRIBUTE {
                                r#type: self.kinds[index],
                                pValue: buffer.value.pointer(),
                                ulValueLen: bounds::ck_length(buffer.value.capacity)?,
                            });
                            self.indices.push(index);
                        }
                        Slot::Indeterminate => {
                            self.values[index] = Some(PreciseAttributeValue::Indeterminate)
                        }
                        Slot::Accepted => {
                            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                                crate::KeyAdmissionRejection::AttributePreparationChanged,
                            )))
                        }
                    }
                }
                self.stage = if self.attrs.is_empty() {
                    ReadStage::Done { rv }
                } else {
                    ReadStage::Values
                };
            }
            (
                ReadStage::ValuesReceived { rv, accepted },
                PreparedStorage::Value { mut bytes, decoded },
            ) => {
                let index = self.indices[accepted];
                let Slot::Live(buffer) = &self.slots[index] else {
                    return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::AttributeOwnerAbsent,
                    )));
                };
                if self.retained.len() == self.retained.capacity() {
                    return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::AdmissionObservationPlanExceeded,
                    )));
                }
                buffer.value.copy_into(&mut bytes)?;
                if self.decode_mechanisms {
                    let decoded_size =
                        decoded
                            .capacity()
                            .checked_mul(std::mem::size_of::<u64>())
                            .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                                crate::KeyAdmissionRejection::MechanismProjectionStorageSize,
                            )))?;
                    self.mechanisms = Some(
                        crate::attributes::owned::resident::MechanismValues::decode_prepared(
                            &bytes,
                            decoded,
                            candidate.credit.split(decoded_size)?,
                        )?,
                    );
                }
                self.values[index] = Some(PreciseAttributeValue::Available(bytes));
                self.retained.push(candidate.credit);
                // Remove the raw descriptor before releasing its allocation.
                self.attrs[accepted].pValue = std::ptr::null_mut();
                self.attrs[accepted].ulValueLen = 0;
                self.slots[index] = Slot::Accepted;
                self.stage = ReadStage::ValuesReceived {
                    rv,
                    accepted: accepted + 1,
                };
                self.advance_indeterminate()?;
            }
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::AttributePreparationChanged,
                )))
            }
        }
        Ok(())
    }

    fn advance_indeterminate(&mut self) -> Result<()> {
        let ReadStage::ValuesReceived { rv, mut accepted } = self.stage else {
            return Ok(());
        };
        while accepted < self.attrs.len()
            && self.attrs[accepted].ulValueLen == CK_UNAVAILABLE_INFORMATION
        {
            let index = self.indices[accepted];
            self.values[index] = Some(PreciseAttributeValue::Indeterminate);
            self.attrs[accepted].pValue = std::ptr::null_mut();
            self.attrs[accepted].ulValueLen = 0;
            self.slots[index] = Slot::Indeterminate;
            accepted += 1;
        }
        self.stage = if accepted == self.attrs.len() {
            ReadStage::Done { rv }
        } else {
            ReadStage::ValuesReceived { rv, accepted }
        };
        Ok(())
    }

    pub(super) fn take(&mut self) -> Result<crate::attributes::ObservedAttributes> {
        if !self.complete() {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AttributeReadIncomplete,
            )));
        }
        // Output metadata was prepaid with the read frame; publication only
        // moves values, with no allocation under the session/operation guards.
        for value in &mut self.values {
            self.output.push(
                value
                    .take()
                    .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::AttributeValueAlreadyConsumed,
                    )))?
                    .public(),
            );
        }
        self.stage = ReadStage::Consumed;
        let metadata = self
            .kinds
            .capacity()
            .checked_mul(std::mem::size_of::<CK_ATTRIBUTE_TYPE>())
            .and_then(|bytes| {
                self.output
                    .capacity()
                    .checked_mul(std::mem::size_of::<crate::AttributeValue>())
                    .and_then(|more| bytes.checked_add(more))
            })
            .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AttributeProjectionStorageSize,
            )))?;
        let mut credit = self._credit.split(metadata)?;
        for payload in self.retained.drain(..) {
            credit.merge(payload)?;
        }
        let snapshot = crate::attributes::owned::resident::AttributeSnapshot::from_credited_parts(
            std::mem::take(&mut self.kinds),
            std::mem::take(&mut self.output),
            credit,
        )?;
        Ok(crate::attributes::ObservedAttributes::from_snapshot(
            snapshot,
        ))
    }
}


