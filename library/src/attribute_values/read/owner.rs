// SPDX-License-Identifier: Apache-2.0
//! Completed attribute passes remain owned while later value storage is admitted.
use super::{after_observation, dispatch, value_result, Phase, ReadCall};
use crate::{
    attribute_values::{
        AttributeBatchCall, AttributeBatchCalls, AttributeBytes, AttributeReadCalls,
        FlatAttributeBatch, FlatAttributeObservation, FlatAttributeValue,
    },
    native::frame::NativeFrame,
    registry::ReadPermit,
    session::SessionAccess,
    Error, NativeObjectRef, Result, Session,
};
use fe11_sys::{CK_OBJECT_HANDLE, CK_RV};
use std::sync::{Arc, Weak};

mod preparation;
pub(crate) use preparation::{prepare_value, Plan, Prepared, ValuePreparation};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ValueNeed {
    pub index: usize,
    pub length: usize,
}
struct FirstPass {
    call: ReadCall,
    second: ReadCall,
    next: usize,
    code: CK_RV,
}
enum State {
    First { call: ReadCall, second: ReadCall },
    AcceptFirst(FirstPass),
    NeedValue { pass: FirstPass, need: ValueNeed },
    Second(ReadCall),
    Complete,
    Stopped,
    InFlight,
    // NativeFrame owns quarantined storage on this path; never wait for quota.
    Uncertain,
}
pub(crate) struct FlatOwner {
    data: Prepared,
    source: Weak<crate::managed::NativeIdentity>,
    authentication: Option<u64>,
    // Keep the observed object protected across both C calls and every wait.
    // The registry owns this permit, never the metadata-only waiter.
    _reader: ReadPermit,
}
impl FlatOwner {
    pub(crate) fn bind(
        data: Prepared,
        source: &NativeObjectRef,
        reader: ReadPermit,
        epoch: u64,
    ) -> Self {
        Self {
            data,
            source: Arc::downgrade(&source.identity),
            authentication: Some(epoch),
            _reader: reader,
        }
    }
    fn handle(&self, session: &Session, access: &SessionAccess<'_>) -> Result<CK_OBJECT_HANDLE> {
        // The caller keeps its original reference. Do not create an Entry ->
        // identity -> creator Entry cycle in this session-owned continuation.
        // Its attributed ReadPermit independently keeps Activity alive for close.
        let identity = self.source.upgrade().ok_or(Error::Rejected(
            crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeSourceWithdrawn,
            ),
        ))?;
        session.check_synchronous_dispatch()?;
        session.native_identity_handle(access, &identity)
    }
    pub(crate) fn complete(&self) -> bool {
        matches!(self.data.state, State::Complete)
    }
    pub(crate) fn pending(&self) -> bool {
        matches!(self.data.state, State::InFlight | State::Uncertain)
    }
    pub(crate) fn calls(&self) -> AttributeBatchCalls {
        self.data.calls
    }
    pub(crate) fn need(&self) -> Option<ValueNeed> {
        match &self.data.state {
            State::NeedValue { need, .. } => Some(*need),
            _ => None,
        }
    }
    pub(crate) fn interrupted(error: Error, calls: AttributeBatchCalls) -> Error {
        after_observation(error, calls)
    }
    pub(crate) fn attach(
        &mut self,
        expected: ValueNeed,
        value: Result<AttributeBytes>,
    ) -> Result<()> {
        if self.need() != Some(expected) {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AttributePreparationChanged,
            )));
        }
        let State::NeedValue { mut pass, need } =
            std::mem::replace(&mut self.data.state, State::Stopped)
        else {
            unreachable!("value need checked")
        };
        let request = self.data.requests[need.index];
        match value {
            Ok(bytes) => {
                if bytes.capacity() != need.length {
                    return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                        crate::AttributeValuesRejection::AttributePreparationLengthChanged,
                    )));
                }
                self.data.allocated =
                    self.data
                        .allocated
                        .checked_add(need.length)
                        .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                            crate::AttributeValuesRejection::AttributeValueAccounting,
                        )))?;
                pass.second
                    .push(need.index, request.attribute, Phase::Value(bytes))?;
            }
            Err(cause) => self.data.results.put(
                need.index,
                FlatAttributeObservation {
                    attribute: request.attribute,
                    calls: AttributeReadCalls::Size {
                        code: pass.code as u64,
                    },
                    value: FlatAttributeValue::PreparationFailed {
                        required: need.length,
                        cause,
                    },
                },
            ),
        }
        pass.next += 1;
        self.data.state = State::AcceptFirst(pass);
        Ok(())
    }
    fn call(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        call: ReadCall,
    ) -> Result<(ReadCall, CK_RV)> {
        let handle = self.handle(session, access)?;
        let mut frame = NativeFrame::session(access.clone(), call)?;
        self.data.state = State::InFlight;
        let result = dispatch(&mut frame, session, handle);
        // Inspect the completion marker even on a native error. A known return
        // can retire locally; unknown completion keeps the recovery owner alive.
        let data = match frame.into_inner() {
            Ok(body) => body.data.into_inner(),
            Err(retention) => {
                self.data.state = State::Uncertain;
                return Err(result.err().unwrap_or(retention));
            }
        };
        self.data.state = State::Stopped;
        let code = session.metadata_result(access, self.authentication, result)?;
        Ok((data, code))
    }
    pub(crate) fn advance(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        loop {
            if self.need().is_some() || self.complete() {
                return Ok(());
            }
            match std::mem::replace(&mut self.data.state, State::Stopped) {
                State::First { call, second } => {
                    let (call, code) = self.call(session, access, call)?;
                    self.data.calls = AttributeBatchCalls::One(AttributeBatchCall {
                        code: code as u64,
                        attribute_count: self.data.requests.len(),
                    });
                    self.data.state = State::AcceptFirst(FirstPass {
                        call,
                        second,
                        next: 0,
                        code,
                    });
                }
                State::AcceptFirst(mut pass) => {
                    while pass.next < self.data.requests.len() {
                        let index = pass.next;
                        let request = self.data.requests[index];
                        let length = pass.call.descriptors[index].ulValueLen;
                        let phase =
                            std::mem::replace(&mut pass.call.slots[index].phase, Phase::Size);
                        let (calls, value) = match phase {
                            Phase::Value(bytes) => (
                                AttributeReadCalls::Direct {
                                    code: pass.code as u64,
                                },
                                value_result(bytes, length, pass.code, self.data.requests.len())?,
                            ),
                            Phase::Size => {
                                match super::query_decision(
                                    &request,
                                    length,
                                    pass.code,
                                    self.data.requests.len(),
                                    self.data.maximum,
                                    self.data.allocated,
                                )? {
                                    super::QueryDecision::Result(value) => (
                                        AttributeReadCalls::Size {
                                            code: pass.code as u64,
                                        },
                                        value,
                                    ),
                                    super::QueryDecision::Read(length) => {
                                        self.data.state = State::NeedValue {
                                            pass,
                                            need: ValueNeed { index, length },
                                        };
                                        return Ok(());
                                    }
                                }
                            }
                        };
                        self.data.results.put(
                            index,
                            FlatAttributeObservation {
                                attribute: request.attribute,
                                calls,
                                value,
                            },
                        );
                        pass.next += 1;
                    }
                    self.data.state = if pass.second.slots.is_empty() {
                        State::Complete
                    } else {
                        State::Second(pass.second)
                    };
                }
                State::Second(call) => {
                    let AttributeBatchCalls::One(first) = self.data.calls else {
                        return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                            crate::AttributeValuesRejection::AttributeFirstCallProvenanceAbsent,
                        )));
                    };
                    let count = call.slots.len();
                    let (mut call, code) = self.call(session, access, call)?;
                    self.data.calls = AttributeBatchCalls::Two {
                        first,
                        second: AttributeBatchCall {
                            code: code as u64,
                            attribute_count: count,
                        },
                    };
                    for offset in 0..count {
                        let slot = &mut call.slots[offset];
                        let Phase::Value(bytes) = std::mem::replace(&mut slot.phase, Phase::Size)
                        else {
                            return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                                crate::AttributeValuesRejection::AttributeValueOwnerAbsent,
                            )));
                        };
                        self.data.results.put(
                            slot.index,
                            FlatAttributeObservation {
                                attribute: slot.attribute,
                                calls: AttributeReadCalls::Value {
                                    size_code: first.code,
                                    code: code as u64,
                                },
                                value: value_result(
                                    bytes,
                                    call.descriptors[offset].ulValueLen,
                                    code,
                                    count,
                                )?,
                            },
                        );
                    }
                    self.data.state = State::Complete;
                }
                state @ (State::NeedValue { .. }
                | State::Complete
                | State::InFlight
                | State::Uncertain
                | State::Stopped) => {
                    self.data.state = state;
                    return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                        crate::AttributeValuesRejection::AttributeObservationPhaseUnavailable,
                    )));
                }
            }
        }
    }
    pub(crate) fn result(
        self,
        session: &Session,
        access: &SessionAccess<'_>,
    ) -> Result<FlatAttributeBatch> {
        if !self.complete() {
            return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeObservationIncomplete,
            )));
        }
        self.handle(session, access)
            .map_err(|error| after_observation(error, self.data.calls))?;
        self.data.results.finish(self.data.calls)
    }
}
