// SPDX-License-Identifier: Apache-2.0
//! Session-owned continuation for a protected CKA_VALUE observation.
use super::*;
use crate::{
    registry::ReadPermit, session::observation_protection::ObservationProtection,
    symmetric::memory::ControlledReservation,
};

mod runner;
pub(crate) use runner::{value, value_with};

enum State {
    Size(ValueCall),
    NeedValue { call: ValueCall, length: usize },
    Value(ValueCall),
    Complete(ProtectedContent),
    Stopped,
    InFlight,
    Uncertain,
}
pub(crate) struct ContentOwner {
    state: State,
    handle: CK_OBJECT_HANDLE,
    maximum: usize,
    authentication: Option<u64>,
    _protection: ObservationProtection,
}
impl ContentOwner {
    pub(crate) fn fixed_bytes() -> usize {
        std::mem::size_of::<ValueCall>() + SessionFrame::<'static, ValueCall>::allocation_bytes()
    }
    pub(crate) fn prepaid_protected(
        prepaid: &mut Credit,
        handle: CK_OBJECT_HANDLE,
        maximum: usize,
        authentication: Option<u64>,
        protection: ObservationProtection,
    ) -> Result<Self> {
        let call = ValueCall {
            descriptor: CK_ATTRIBUTE {
                r#type: CKA_VALUE,
                pValue: std::ptr::null_mut(),
                ulValueLen: 0,
            },
            phase: Phase::Sizing,
            _credit: prepaid.split(Self::fixed_bytes())?,
        };
        Ok(Self::bind_protected(
            call,
            handle,
            maximum,
            authentication,
            protection,
        ))
    }
    fn bind(
        call: ValueCall,
        handle: CK_OBJECT_HANDLE,
        maximum: usize,
        authentication: Option<u64>,
        reader: ReadPermit,
    ) -> Self {
        Self::bind_protected(
            call,
            handle,
            maximum,
            authentication,
            ObservationProtection::object(reader),
        )
    }
    fn bind_protected(
        call: ValueCall,
        handle: CK_OBJECT_HANDLE,
        maximum: usize,
        authentication: Option<u64>,
        protection: ObservationProtection,
    ) -> Self {
        Self {
            state: State::Size(call),
            handle,
            maximum,
            authentication,
            _protection: protection,
        }
    }
    pub(crate) fn pending(&self) -> bool {
        matches!(self.state, State::InFlight | State::Uncertain)
    }
    pub(crate) fn need(&self) -> Option<usize> {
        match self.state {
            State::NeedValue { length, .. } => Some(length),
            _ => None,
        }
    }
    pub(crate) fn complete(&self) -> bool {
        matches!(self.state, State::Complete(_))
    }
    fn call(
        &mut self,
        call: ValueCall,
        session: &Session,
        access: &SessionAccess<'_>,
    ) -> Result<(ValueCall, CK_RV)> {
        let mut frame = NativeFrame::session(access.clone(), call)?;
        self.state = State::InFlight;
        let result = dispatch(&mut frame, session, self.handle);
        let completed = match frame.into_inner() {
            Ok(completed) => completed,
            Err(error) => {
                self.state = State::Uncertain;
                return Err(result.err().unwrap_or(error));
            }
        };
        self.state = State::Stopped;
        let code = session.metadata_result(access, self.authentication, result)?;
        Ok((completed.data.into_inner(), code))
    }
    pub(crate) fn advance(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        handle: CK_OBJECT_HANDLE,
    ) -> Result<()> {
        if handle != self.handle {
            return Err(Error::Rejected(crate::RejectionReason::ObjectContent(
                crate::ObjectContentRejection::ContentSourceChanged,
            )));
        }
        match std::mem::replace(&mut self.state, State::Stopped) {
            State::Size(call) => {
                let (call, code) = self.call(call, session, access)?;
                if let Some(content) = absence(code, call.descriptor.ulValueLen) {
                    self.state = State::Complete(content);
                } else {
                    let length = bounds::count(call.descriptor.ulValueLen, self.maximum)?;
                    self.state = State::NeedValue { call, length };
                }
            }
            State::Value(call) => {
                let (call, code) = self.call(call, session, access)?;
                let content = if let Some(content) = absence(code, call.descriptor.ulValueLen) {
                    content
                } else {
                    let Phase::Reading(mut bytes) = call.phase else {
                        return Err(Error::Rejected(crate::RejectionReason::ObjectContent(
                            crate::ObjectContentRejection::ContentReadPhase,
                        )));
                    };
                    bytes.truncate(bounds::final_length(
                        call.descriptor.ulValueLen,
                        bytes.len(),
                    )?)?;
                    ProtectedContent::Available(bytes)
                };
                self.state = State::Complete(content);
            }
            State::Complete(content) => self.state = State::Complete(content),
            state => {
                self.state = state;
                return Err(Error::Rejected(crate::RejectionReason::ObjectContent(
                    crate::ObjectContentRejection::ContentContinuationPhase,
                )));
            }
        }
        Ok(())
    }
    pub(crate) fn attach(&mut self, length: usize, mut bytes: SecretBytes) -> Result<()> {
        if self.need() != Some(length) || bytes.len() != length {
            return Err(Error::Rejected(crate::RejectionReason::ObjectContent(
                crate::ObjectContentRejection::ContentPreparationChanged,
            )));
        }
        let State::NeedValue { mut call, .. } = std::mem::replace(&mut self.state, State::Stopped)
        else {
            unreachable!("exact need checked")
        };
        call.descriptor.pValue = bytes.as_mut_slice().as_mut_ptr().cast();
        call.descriptor.ulValueLen = bounds::ck_length(length)?;
        call.phase = Phase::Reading(bytes);
        self.state = State::Value(call);
        Ok(())
    }
    pub(crate) fn result<T>(
        mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        finish: impl FnOnce(ProtectedContent) -> Result<T>,
    ) -> Result<T> {
        let result = match std::mem::replace(&mut self.state, State::Stopped) {
            State::Complete(content) => Ok(content),
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectContent(
                crate::ObjectContentRejection::ContentObservationIncomplete,
            ))),
        };
        // Retain source protection through publication of the historical result;
        // publication does not renew its context or authorize another native call.
        session.metadata_result(access, self.authentication, result.and_then(finish))
    }
}

pub(crate) fn prepare_value(
    length: usize,
    budget: &std::sync::Arc<crate::symmetric::memory::Budget>,
    policy: &crate::ResourceAdmission,
    mut check: impl FnMut() -> Result<()>,
) -> Result<SecretBytes> {
    // ValueCall's initial frame charge already includes the SecretBytes header.
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
            ControlledReservation::Acquired(credit) => credit,
            ControlledReservation::Redirect(()) => unreachable!("no redirect requested"),
        };
        let storage = SecretBytes::new(length)?;
        let actual = storage.allocated_bytes();
        if actual > required {
            drop(storage);
            drop(credit);
            required = actual;
            continue;
        }
        credit.release(required - actual);
        return storage.bind_prepaid_payload(&mut credit);
    }
}
