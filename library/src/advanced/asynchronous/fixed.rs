// SPDX-License-Identifier: Apache-2.0
//! Aligned fixed outputs for the existing PKCS#11 control signatures.
use super::JoinedResult;

use crate::{bounds, symmetric::memory::Credit, Error, Result};
use fe11_sys::{
    CKR_OK, CKR_PENDING, CK_BYTE_PTR, CK_FLAGS, CK_RV, CK_SESSION_INFO, CK_UNAVAILABLE_INFORMATION,
};

enum Value {
    Info(Box<CK_SESSION_INFO>),
    Flags(Box<CK_FLAGS>),
}
pub(super) struct FixedOutput {
    value: Value,
    _credit: Credit,
}
impl FixedOutput {
    /// The FixedOutput value is inline in JoinedCall; only its pointed-to
    /// native scalar/structure is additional storage in that aggregate graph.
    pub(super) fn allocation_bytes(
        function: &str,
        capacity: Option<usize>,
    ) -> Result<Option<usize>> {
        let size = match function {
            "C_GetSessionInfo" => std::mem::size_of::<CK_SESSION_INFO>(),
            "C_GetSessionValidationFlags" => std::mem::size_of::<CK_FLAGS>(),
            _ => return Ok(None),
        };
        if capacity != Some(size) {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::JoinedFixedOutputCapacity,
                ),
            ));
        }
        Ok(Some(size))
    }
    pub(super) fn new_prepaid(
        prepaid: &mut Credit,
        function: &str,
        capacity: Option<usize>,
    ) -> Result<Option<Self>> {
        let Some(size) = Self::allocation_bytes(function, capacity)? else {
            return Ok(None);
        };
        let credit = prepaid.split(size)?;
        let value = if function == "C_GetSessionInfo" {
            Value::Info(Box::new(CK_SESSION_INFO {
                slotID: 0,
                state: CK_UNAVAILABLE_INFORMATION,
                flags: 0,
                ulDeviceError: 0,
            }))
        } else {
            Value::Flags(Box::new(0))
        };
        Ok(Some(Self {
            value,
            _credit: credit,
        }))
    }

    pub(super) fn capacity(&self) -> usize {
        match &self.value {
            Value::Info(_) => std::mem::size_of::<CK_SESSION_INFO>(),
            Value::Flags(_) => std::mem::size_of::<CK_FLAGS>(),
        }
    }
    pub(super) fn pointer(&mut self) -> CK_BYTE_PTR {
        match &mut self.value {
            Value::Info(value) => (&mut **value as *mut CK_SESSION_INFO).cast(),
            Value::Flags(value) => (&mut **value as *mut CK_FLAGS).cast(),
        }
    }
    fn matches(&self, function: &str) -> bool {
        matches!(
            (&self.value, function),
            (Value::Info(_), "C_GetSessionInfo") | (Value::Flags(_), "C_GetSessionValidationFlags")
        )
    }
}
impl JoinedResult {
    fn project_fixed(self, function: &'static str) -> Result<(CK_RV, Option<FixedOutput>)> {
        if self.function != function || self.return_value == CKR_PENDING || self.output.is_some() {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::JoinedFixedResultShape,
                ),
            ));
        }
        if self.return_value != CKR_OK {
            if self.fixed.is_some() {
                return Err(Error::Rejected(
                    crate::RejectionReason::AsynchronousExecution(
                        crate::AsynchronousExecutionRejection::FailedJoinedFixedOutput,
                    ),
                ));
            }
            return Ok((self.return_value, None));
        }
        let fixed = self.fixed.ok_or(Error::Rejected(
            crate::RejectionReason::AsynchronousExecution(
                crate::AsynchronousExecutionRejection::JoinedFixedOutputAbsent,
            ),
        ))?;
        if !fixed.matches(function) || self.value != bounds::ck_length(fixed.capacity())? {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::JoinedFixedResultSizeOrType,
                ),
            ));
        }
        Ok((self.return_value, Some(fixed)))
    }
    pub(in crate::advanced) fn project_info(self) -> Result<(CK_RV, Option<CK_SESSION_INFO>)> {
        let (rv, fixed) = self.project_fixed("C_GetSessionInfo")?;
        Ok((
            rv,
            match fixed {
                Some(FixedOutput {
                    value: Value::Info(info),
                    ..
                }) => Some(*info),
                None => None,
                _ => unreachable!(),
            },
        ))
    }
    pub(in crate::advanced) fn project_flags(self) -> Result<(CK_RV, Option<CK_FLAGS>)> {
        let (rv, fixed) = self.project_fixed("C_GetSessionValidationFlags")?;
        Ok((
            rv,
            match fixed {
                Some(FixedOutput {
                    value: Value::Flags(flags),
                    ..
                }) => Some(*flags),
                None => None,
                _ => unreachable!(),
            },
        ))
    }
    // A size-only state query has no byte buffer. Its returned ulValue is a
    // length, never a flag value, handle, allocation address or object count.
    pub(in crate::advanced) fn project_state_size(
        self,
        maximum: usize,
    ) -> Result<(CK_RV, Option<usize>)> {
        if self.function != "C_GetOperationState"
            || self.return_value == CKR_PENDING
            || self.output.is_some()
            || self.fixed.is_some()
        {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::JoinedStateSizeResultShape,
                ),
            ));
        }
        Ok((
            self.return_value,
            if self.return_value == CKR_OK {
                Some(bounds::count(self.value, maximum)?)
            } else {
                None
            },
        ))
    }
}
