// SPDX-License-Identifier: Apache-2.0
//! Historical metadata protocol with resident completed replies.
//!
//! The batch and its optional individual clarifications form one observation.
//! The session owns completed data and its source protection between passes;
//! the waiting caller retains only coordination and the exact scalar need.
use super::*;
use crate::session::observation_protection::ObservationProtection;

mod export;
mod preparation;
pub(crate) use export::{AttributeSnapshot, MechanismValues};
use export::{MechanismCopy, PublicCopy};
pub(crate) use preparation::{prepare_value, Storage as ReadStorage};
mod recipe;
pub(crate) use recipe::Recipe;
use recipe::{Output, OutputKind};

mod runner;
pub(crate) use runner::{observe, observe_controls, observe_history_with, Source};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueNeed {
    Native { index: usize, length: usize },
    PublicCopy { index: usize, length: usize },
    Mechanisms { length: usize },
}
pub(crate) enum ValueCandidate {
    Native(AlignedOutput),
    PublicCopy(PublicCopy),
    Mechanisms(MechanismCopy),
}
#[derive(Clone, Copy)]
enum RequestKind {
    Batch,
    Individual { index: usize },
}
enum ReadState {
    Size(ReadCall),
    AfterSize {
        call: ReadCall,
        next: usize,
        total: usize,
    },
    NeedValue {
        call: ReadCall,
        need: ValueNeed,
        total: usize,
    },
    Values(ReadCall),
    Export {
        call: ReadCall,
        next: usize,
    },
    NeedExport {
        call: ReadCall,
        need: ValueNeed,
    },
    Complete(ReadCall),
    Stopped,
    InFlight,
    Uncertain,
}

pub(crate) struct LegacyOwner {
    request: RequestKind,
    fields: Vec<CK_ATTRIBUTE_TYPE>,
    kinds: Vec<CK_ATTRIBUTE_TYPE>,
    values: Vec<PreciseAttributeValue>,
    // Internal readers borrow completed native storage. Public projections
    // are separately prepared before copying, outside session possession.
    retained: Vec<Option<(AlignedOutput, usize)>>,
    export: AttributeSnapshot,
    mechanisms: Option<MechanismValues>,
    plan: AttributeReadPlan,
    output: OutputKind,
    handle: CK_OBJECT_HANDLE,
    authentication: Option<u64>,
    total: usize,
    next_clarification: usize,
    _protection: ObservationProtection,
    state: ReadState,
    // Independent of the temporary ReadCall, including on native refusal or
    // context failure after completion. Released after the resident vectors.
    _credit: Credit,
}

/// Private view: no public result container or payload copy is constructed.
pub(crate) struct FingerprintValues<'a>(&'a LegacyOwner);

/// Completed internal observations keep the original aligned allocations and
/// table credit across later phases (for example DER preparation). No source
/// buffer is copied merely to change its Rust observation view.
pub(crate) struct ResidentValues {
    _fields: Vec<CK_ATTRIBUTE_TYPE>,
    kinds: Vec<CK_ATTRIBUTE_TYPE>,
    values: Vec<PreciseAttributeValue>,
    retained: Vec<Option<(AlignedOutput, usize)>>,
    export: AttributeSnapshot,
    _credit: Credit,
}
impl ResidentValues {
    pub(crate) fn into_public(self) -> AttributeSnapshot {
        self.export
    }
    pub(crate) fn bytes(&self, kind: CK_ATTRIBUTE_TYPE) -> crate::Observation<&[u8]> {
        use crate::{AttributeUnavailableCause as Cause, Observation};
        let Some(index) = self.kinds.iter().position(|field| *field == kind) else {
            return Observation::NotRequested;
        };
        if let Some((storage, length)) = &self.retained[index] {
            return Observation::Observed(
                storage
                    .completed_bytes(*length)
                    .expect("length validated before completed buffer transfer"),
            );
        }
        match self.values[index] {
            PreciseAttributeValue::Sensitive => Observation::Unavailable(Cause::Sensitive),
            PreciseAttributeValue::Unsupported => Observation::Unavailable(Cause::Unsupported),
            PreciseAttributeValue::Indeterminate => Observation::Unavailable(Cause::Unspecified),
            PreciseAttributeValue::Available(_) => {
                unreachable!("available value owns retained storage")
            }
        }
    }
    pub(crate) fn all_available(&self) -> bool {
        self.retained.iter().all(Option::is_some)
    }
}
impl FingerprintValues<'_> {
    pub(crate) fn len(&self) -> usize {
        self.0.fields.len()
    }
    pub(crate) fn get(
        &self,
        index: usize,
    ) -> Result<std::result::Result<&[u8], crate::AttributeUnavailableCause>> {
        let field = self.0.fields.get(index).ok_or(Error::Rejected(
            crate::RejectionReason::AttributePreparation(
                crate::AttributePreparationRejection::FingerprintFieldIndex,
            ),
        ))?;
        let index = self
            .0
            .kinds
            .iter()
            .position(|kind| kind == field)
            .ok_or(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::FingerprintFieldMissing,
                ),
            ))?;
        if let Some((buffer, length)) = &self.0.retained[index] {
            return Ok(Ok(buffer.completed_bytes(*length)?));
        }
        use crate::AttributeUnavailableCause as Cause;
        Ok(match self.0.values[index] {
            PreciseAttributeValue::Sensitive => Err(Cause::Sensitive),
            PreciseAttributeValue::Unsupported => Err(Cause::Unsupported),
            PreciseAttributeValue::Indeterminate => Err(Cause::Unspecified),
            PreciseAttributeValue::Available(_) => {
                return Err(Error::Rejected(
                    crate::RejectionReason::AttributePreparation(
                        crate::AttributePreparationRejection::FingerprintCompletedStorageMissing,
                    ),
                ));
            }
        })
    }
}
impl LegacyOwner {
    pub(crate) fn fingerprint_result<T>(
        self,
        session: &crate::Session,
        access: &SessionAccess<'_>,
        finish: impl FnOnce(FingerprintValues<'_>) -> Result<T>,
    ) -> Result<T> {
        if !self.complete() || !matches!(self.output, OutputKind::Fingerprint) {
            return Err(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::FingerprintObservationIncomplete,
                ),
            ));
        }
        // The view cannot outlive this owner. Hashing completes before any
        // native buffer, credit or source protection is released.
        let result = finish(FingerprintValues(&self));
        session.metadata_result(access, self.authentication, result)
    }
    pub(crate) fn history_result(
        self,
        session: &crate::Session,
        access: &SessionAccess<'_>,
        plan: crate::HistoryObservationPlan,
    ) -> Result<crate::TransportProtection> {
        self.result(session, access, |output| match output {
            Output::Observed(values) => {
                Ok(crate::crypto::derivation::history::snapshot(plan, &values))
            }
            _ => Err(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::AttributeObservationOutputKind,
                ),
            )),
        })
    }
    pub(crate) fn precise_result(
        self,
        session: &crate::Session,
        access: &SessionAccess<'_>,
    ) -> Result<MechanismValues> {
        self.result(session, access, |output| match output {
            Output::Precise(value) => Ok(value),
            _ => Err(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::AttributeObservationOutputKind,
                ),
            )),
        })
    }
    pub(crate) fn public_result(
        self,
        session: &crate::Session,
        access: &SessionAccess<'_>,
    ) -> Result<AttributeSnapshot> {
        self.result(session, access, |output| match output {
            Output::Public(values) => Ok(values),
            _ => Err(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::AttributeObservationOutputKind,
                ),
            )),
        })
    }
    pub(crate) fn object_observations_result(
        self,
        session: &crate::Session,
        access: &SessionAccess<'_>,
        admission: &crate::ObjectAdmission,
    ) -> Result<crate::ObjectObservationReport> {
        self.result(session, access, |output| match output {
            Output::Observed(values) => admission.observe_owned(values),
            _ => Err(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::AttributeObservationOutputKind,
                ),
            )),
        })
    }
    pub(crate) fn required_result(
        self,
        session: &crate::Session,
        access: &SessionAccess<'_>,
    ) -> Result<RequiredAttributes> {
        self.result(session, access, |output| match output {
            Output::Required(values) => Ok(values),
            _ => Err(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::AttributeObservationOutputKind,
                ),
            )),
        })
    }
    pub(crate) fn pending(&self) -> bool {
        matches!(self.state, ReadState::InFlight | ReadState::Uncertain)
    }
    pub(crate) fn complete(&self) -> bool {
        matches!(self.state, ReadState::Complete(_))
    }
    pub(crate) fn need(&self) -> Option<ValueNeed> {
        match self.state {
            ReadState::NeedValue { need, .. } | ReadState::NeedExport { need, .. } => Some(need),
            _ => None,
        }
    }
    pub(crate) fn attach(&mut self, need: ValueNeed, value: ValueCandidate) -> Result<()> {
        if self.need() != Some(need) {
            return Err(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::AttributeContinuationPreparationChanged,
                ),
            ));
        }
        let state = std::mem::replace(&mut self.state, ReadState::Stopped);
        self.state =
            match (state, need, value) {
                (
                    ReadState::NeedValue {
                        mut call, total, ..
                    },
                    ValueNeed::Native { index, length },
                    ValueCandidate::Native(value),
                ) if value.capacity == length => {
                    call.buffers[index] = Some(value);
                    ReadState::AfterSize {
                        call,
                        next: index + 1,
                        total,
                    }
                }
                (
                    ReadState::NeedExport { call, .. },
                    ValueNeed::PublicCopy { index, length },
                    ValueCandidate::PublicCopy(copy),
                ) => {
                    let field = self.export.field(index);
                    let source = self.kinds.iter().position(|kind| *kind == field).ok_or(
                        Error::Rejected(crate::RejectionReason::AttributePreparation(
                            crate::AttributePreparationRejection::AttributeExportFieldMissing,
                        )),
                    )?;
                    let (buffer, completed) = self.retained[source].as_ref().ok_or(
                        Error::Rejected(crate::RejectionReason::AttributePreparation(
                            crate::AttributePreparationRejection::AttributeExportSourceAbsent,
                        )),
                    )?;
                    if *completed != length {
                        return Err(Error::Rejected(
                            crate::RejectionReason::AttributePreparation(
                                crate::AttributePreparationRejection::AttributeExportLengthChanged,
                            ),
                        ));
                    }
                    self.export
                        .set_copy(index, copy, buffer.completed_bytes(length)?)?;
                    ReadState::Export {
                        call,
                        next: index + 1,
                    }
                }
                (
                    ReadState::NeedExport { call, .. },
                    ValueNeed::Mechanisms { length },
                    ValueCandidate::Mechanisms(copy),
                ) => {
                    let (buffer, completed) = self.retained[0].as_ref().ok_or(Error::Rejected(
                        crate::RejectionReason::AttributePreparation(
                            crate::AttributePreparationRejection::MechanismProjectionSourceAbsent,
                        ),
                    ))?;
                    if *completed != length {
                        return Err(Error::Rejected(
                        crate::RejectionReason::AttributePreparation(
                            crate::AttributePreparationRejection::MechanismProjectionLengthChanged,
                        ),
                    ));
                    }
                    self.mechanisms = Some(copy.decode(buffer.completed_bytes(length)?)?);
                    ReadState::Complete(call)
                }
                _ => {
                    return Err(Error::Rejected(
                        crate::RejectionReason::AttributePreparation(
                            crate::AttributePreparationRejection::AttributePreparationKindChanged,
                        ),
                    ))
                }
            };
        Ok(())
    }

    fn call(
        &mut self,
        call: ReadCall,
        session: &crate::Session,
        access: &SessionAccess<'_>,
        phase: Phase,
    ) -> Result<(ReadCall, CK_RV)> {
        let mut frame = NativeFrame::session(access.clone(), call)?;
        self.state = ReadState::InFlight;
        let returned = dispatch(&mut frame, session, self.handle, phase);
        let completed = match frame.into_inner() {
            Ok(completed) => completed,
            Err(error) => {
                self.state = ReadState::Uncertain;
                return Err(returned.err().unwrap_or(error));
            }
        };
        self.state = ReadState::Stopped;
        let code = session.metadata_result(access, self.authentication, returned)?;
        Ok((completed.data.into_inner(), code))
    }

    // Classification is identical to read_set: a grouped partial status does
    // not identify the cause for one field, even for a one-field group.
    fn refusal(&self, _call: &ReadCall, code: CK_RV) -> Result<Option<PreciseAttributeValue>> {
        match self.request {
            RequestKind::Batch => Ok(None),
            RequestKind::Individual { .. } => {
                individual_capacity_return(code)?;
                Ok(individual_refusal(code))
            }
        }
    }

    // Inventory children share the parent's remaining logical byte quota.
    // Select its diagnostic only at a proven quota check, never for native
    // buffer bounds, conversion failures or arithmetic overflow.
    fn byte_quota_error(&self, fallback: crate::RejectionReason) -> Error {
        if self._protection.is_inventory() {
            Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::InventoryByteQuota,
            ))
        } else {
            Error::Rejected(fallback)
        }
    }

    // Native requests remain unique. Every exported occurrence consumes
    // the caller's logical value budget; internal retained fields count once.
    fn projected_total(
        &self,
        index: usize,
        total: usize,
        length: usize,
        maximum: usize,
    ) -> Result<usize> {
        let field = self.kinds[index];
        let copies = (0..self.export.len())
            .filter(|position| self.export.field(*position) == field)
            .count()
            .max(1);
        let next = length
            .checked_mul(copies)
            .and_then(|bytes| total.checked_add(bytes))
            .ok_or(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::AttributeTotalOverflow,
                ),
            ))?;
        if next > maximum {
            return Err(self.byte_quota_error(crate::RejectionReason::AttributePreparation(
                crate::AttributePreparationRejection::AttributeTotalBudget,
            )));
        }
        Ok(next)
    }

    fn store(&mut self, local: usize, value: PreciseAttributeValue) -> Result<()> {
        let index = match self.request {
            RequestKind::Batch => local,
            RequestKind::Individual { index } => index,
        };
        if let PreciseAttributeValue::Available(bytes) = &value {
            self.total =
                self.projected_total(index, self.total, bytes.len(), self.plan.maximum_bytes)?;
        }
        self.values[index] = value;
        Ok(())
    }

    fn finish_read(&mut self, mut call: ReadCall) {
        if self.plan.clarification == AttributeClarification::ClarifyIndeterminate {
            while self.next_clarification < self.kinds.len() {
                let index = self.next_clarification;
                self.next_clarification += 1;
                if matches!(self.values[index], PreciseAttributeValue::Indeterminate) {
                    // Reuse the complete initial metadata graph. Its capacity
                    // covers one clarification; no resource acquisition here.
                    call.kinds.clear();
                    call.descriptors.clear();
                    call.indices.clear();
                    call.buffers.clear();
                    call.kinds.push(self.kinds[index]);
                    call.descriptors.push(CK_ATTRIBUTE {
                        r#type: self.kinds[index],
                        pValue: std::ptr::null_mut(),
                        ulValueLen: 0,
                    });
                    call.indices.push(0);
                    call.buffers.push(None);
                    self.request = RequestKind::Individual { index };
                    self.state = ReadState::Size(call);
                    return;
                }
            }
        }
        self.state = ReadState::Export { call, next: 0 };
    }

    pub(crate) fn advance(
        &mut self,
        session: &crate::Session,
        access: &SessionAccess<'_>,
        handle: CK_OBJECT_HANDLE,
    ) -> Result<()> {
        if handle != self.handle {
            return Err(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::AttributeSourceChanged,
                ),
            ));
        }
        loop {
            let state = std::mem::replace(&mut self.state, ReadState::Stopped);
            match state {
                ReadState::Size(call) => {
                    let (call, code) = self.call(call, session, access, Phase::Size)?;
                    if let Some(refusal) = self.refusal(&call, code)? {
                        self.store(0, refusal)?;
                        self.finish_read(call);
                    } else {
                        self.state = ReadState::AfterSize {
                            call,
                            next: 0,
                            total: 0,
                        };
                    }
                }
                ReadState::AfterSize {
                    mut call,
                    mut next,
                    mut total,
                } => {
                    let maximum = match self.request {
                        RequestKind::Batch => self.plan.maximum_bytes,
                        RequestKind::Individual { .. } => {
                            self.plan.maximum_bytes.checked_sub(self.total).ok_or(
                                Error::Rejected(crate::RejectionReason::AttributePreparation(
                                    crate::AttributePreparationRejection::AttributeTotalBudget,
                                )),
                            )?
                        }
                    };
                    while next < call.descriptors.len() {
                        let descriptor = &call.descriptors[next];
                        if descriptor.ulValueLen != CK_UNAVAILABLE_INFORMATION {
                            // The sentinel is excluded above and the running total
                            // is zero: LengthBound here means the size exceeds the
                            // remaining byte quota, not a returned buffer capacity.
                            let (length, _) = add_attribute_size(0, descriptor.ulValueLen, maximum)
                                .map_err(|error| match error {
                                    Error::Rejected(
                                        reason @ crate::RejectionReason::InputBounds(
                                            crate::InputBoundsRejection::LengthBound,
                                        ),
                                    ) => self.byte_quota_error(reason),
                                    error => error,
                                })?;
                            let destination = match self.request {
                                RequestKind::Batch => next,
                                RequestKind::Individual { index } => index,
                            };
                            total = self.projected_total(destination, total, length, maximum)?;
                            let need = ValueNeed::Native {
                                index: next,
                                length,
                            };
                            self.state = ReadState::NeedValue { call, need, total };
                            return Ok(());
                        }
                        next += 1;
                    }
                    call.descriptors.clear();
                    call.indices.clear();
                    for (index, value) in call.buffers.iter_mut().enumerate() {
                        if let Some(value) = value {
                            call.descriptors.push(CK_ATTRIBUTE {
                                r#type: call.kinds[index],
                                pValue: value.pointer(),
                                ulValueLen: bounds::ck_length(value.capacity)?,
                            });
                            call.indices.push(index);
                        }
                    }
                    if call.descriptors.is_empty() {
                        self.finish_read(call);
                    } else {
                        self.state = ReadState::Values(call);
                    }
                }
                ReadState::Values(call) => {
                    let (mut call, code) = self.call(call, session, access, Phase::Values)?;
                    if let Some(refusal) = self.refusal(&call, code)? {
                        self.store(0, refusal)?;
                    } else {
                        for (descriptor, index) in call.descriptors.iter().zip(&call.indices) {
                            let buffer = call.buffers[*index].as_ref().expect("selected value");
                            if let Some(length) = available_length(
                                descriptor.ulValueLen,
                                buffer.capacity,
                                code,
                                call.descriptors.len(),
                            )? {
                                let destination = match self.request {
                                    RequestKind::Batch => *index,
                                    RequestKind::Individual { index } => index,
                                };
                                self.total = self.projected_total(
                                    destination,
                                    self.total,
                                    length,
                                    self.plan.maximum_bytes,
                                )?;
                                self.retained[destination] = Some((
                                    call.buffers[*index].take().expect("selected value"),
                                    length,
                                ));
                                // Marks availability for clarification selection;
                                // the empty Vec owns no allocation.
                                self.values[destination] =
                                    PreciseAttributeValue::Available(Vec::new());
                            }
                        }
                    }
                    self.finish_read(call);
                }
                ReadState::Complete(call) => {
                    self.state = ReadState::Complete(call);
                    return Ok(());
                }
                ReadState::Export { call, mut next } => {
                    if matches!(self.output, OutputKind::Precise) {
                        if self.kinds.as_slice() != [CKA_ALLOWED_MECHANISMS] {
                            return Err(Error::Rejected(
                                crate::RejectionReason::AttributePreparation(
                                    crate::AttributePreparationRejection::MechanismObservationField,
                                ),
                            ));
                        }
                        let observation = match &self.retained[0] {
                            Some((_, length))
                                if *length % std::mem::size_of::<CK_MECHANISM_TYPE>() == 0 =>
                            {
                                self.state = ReadState::NeedExport {
                                    call,
                                    need: ValueNeed::Mechanisms { length: *length },
                                };
                                return Ok(());
                            }
                            Some(_) => crate::Observation::Unusable(
                                crate::ObservationIssue::MechanismListEncoding,
                            ),
                            None => match self.values[0] {
                                PreciseAttributeValue::Sensitive => {
                                    crate::Observation::Unavailable(
                                        crate::AttributeUnavailableCause::Sensitive,
                                    )
                                }
                                PreciseAttributeValue::Unsupported => {
                                    crate::Observation::Unavailable(
                                        crate::AttributeUnavailableCause::Unsupported,
                                    )
                                }
                                PreciseAttributeValue::Indeterminate => {
                                    crate::Observation::Unavailable(
                                        crate::AttributeUnavailableCause::Unspecified,
                                    )
                                }
                                PreciseAttributeValue::Available(_) => {
                                    return Err(Error::Rejected(
                                        crate::RejectionReason::AttributePreparation(crate::AttributePreparationRejection::MechanismObservationStorageAbsent),
                                    ))
                                }
                            },
                        };
                        self.mechanisms = Some(MechanismValues::from_observation(observation));
                    }
                    while next < self.export.len() {
                        let field = self.export.field(next);
                        let index = self.kinds.iter().position(|kind| *kind == field).ok_or(
                            Error::Rejected(crate::RejectionReason::AttributePreparation(
                                crate::AttributePreparationRejection::AttributeExportFieldMissing,
                            )),
                        )?;
                        if let Some((_, length)) = &self.retained[index] {
                            self.state = ReadState::NeedExport {
                                call,
                                need: ValueNeed::PublicCopy {
                                    index: next,
                                    length: *length,
                                },
                            };
                            return Ok(());
                        }
                        self.export.set_refusal(next, &self.values[index]);
                        next += 1;
                    }
                    self.state = ReadState::Complete(call);
                }
                state => {
                    self.state = state;
                    return Err(Error::Rejected(
                        crate::RejectionReason::AttributePreparation(
                            crate::AttributePreparationRejection::AttributeContinuationPhase,
                        ),
                    ));
                }
            }
        }
    }

    fn result<T>(
        mut self,
        session: &crate::Session,
        access: &SessionAccess<'_>,
        finish: impl FnOnce(Output) -> Result<T>,
    ) -> Result<T> {
        if !self.complete() {
            return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeObservationIncomplete,
            )));
        }
        let result = match self.output {
            OutputKind::Fingerprint => Err(Error::Rejected(crate::RejectionReason::AttributePreparation(crate::AttributePreparationRejection::FingerprintRequiresBorrowedResult))),
            OutputKind::Precise => {
                if self.values.len() != 1 || self.kinds.len() != 1 {
                    Err(Error::Rejected(crate::RejectionReason::AttributePreparation(crate::AttributePreparationRejection::PreciseAttributeObservationCardinality)))
                } else {
                    self.mechanisms
                        .take()
                        .map(Output::Precise)
                        .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(crate::KeyAdmissionRejection::MechanismProjectionAbsent)))
                }
            }
            OutputKind::Public => Ok(Output::Public(self.export)),
            OutputKind::Required | OutputKind::Observed => {
                let observed = ObservedAttributes::from_resident(ResidentValues {
                    _fields: self.fields,
                    kinds: self.kinds,
                    values: self.values,
                    retained: self.retained,
                    export: self.export,
                    _credit: self._credit,
                });
                if matches!(self.output, OutputKind::Required) {
                    observed.require_all().map(Output::Required)
                } else {
                    Ok(Output::Observed(observed))
                }
            }
        }
        .and_then(finish);
        // Evaluation and historical publication retain the same source protection;
        // a later context change does not erase the already observed result.

        session.metadata_result(access, self.authentication, result)
    }
}
