// SPDX-License-Identifier: Apache-2.0
//! Legacy parallel-function calls; never evidence of crypto-owner termination.
use super::*;
use crate::native::frame::NativeFrame;

#[derive(Clone, Copy)]
enum LegacyCall {
    Status,
    Cancel,
}
impl LegacyCall {
    fn name(self) -> &'static str {
        match self {
            Self::Status => "C_GetFunctionStatus",
            Self::Cancel => "C_CancelFunction",
        }
    }
}

impl Session {
    /// Invoke legacy C_GetFunctionStatus and preserve its native return.
    ///
    /// Covered PKCS#11 editions prescribe CKR_FUNCTION_NOT_PARALLEL, returned
    /// here as Error::Native. Ok means only that the module actually returned
    /// CKR_OK; it does not describe a useful parallel-operation state.
    pub fn get_function_status(&self) -> Result<()> {
        let mut diagnostic = None;
        self.legacy_call(LegacyCall::Status, &mut diagnostic)
    }

    /// Invoke legacy C_CancelFunction and preserve its native return.
    ///
    /// CKR_FUNCTION_NOT_PARALLEL remains Error::Native. Neither that refusal
    /// nor CKR_OK releases a crypto owner or proves cancellation. Use the
    /// explicit SessionCancel operation for modern cancellation semantics.
    pub fn cancel_function(&self) -> Result<()> {
        let mut diagnostic = None;
        self.legacy_call(LegacyCall::Cancel, &mut diagnostic)
    }

    fn legacy_call(
        &self,
        operation: LegacyCall,
        diagnostic_root: &mut Option<crate::error::PreparedCompletionCell>,
    ) -> Result<()> {
        // The call is permitted between steps of an existing advanced owner.
        // Possession serializes native dispatch without consuming its ticket.
        let (data, diagnostic, access) = self.prepare_control_with_completion(|| ())?;
        let diagnostic = diagnostic_root.insert(diagnostic).cell();
        let handle = self.entry_common(&access)?.handle;
        let call = match operation {
            LegacyCall::Status => access.native.table.C_GetFunctionStatus,
            LegacyCall::Cancel => access.native.table.C_CancelFunction,
        }
        .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
            crate::SessionLifecycleRejection::LegacyParallelFunctionUnavailable,
        )))?;
        let mut frame = NativeFrame::session(access, data)?;
        let (returned, body) = frame.session_parts();
        let access = &body.access;
        let function = operation.name();
        access.native.record(function)?;
        let sequence = Sequence::for_frame_prepared(access, self, returned, diagnostic);
        // SAFETY: the native handle, image and session possession belong to
        // this retained frame. No caller buffer or stack address is submitted.
        let rv = returned.observe(unsafe { call(handle) }, &access.native);
        sequence
            .inspect_return(
                rv,
                function,
                crate::native_return::protocol::SequencePhase::Continue(
                    crate::native_return::sequence::OutputRequest::Unspecified,
                ),
                // Scalar-only legacy calls never discharge the crypto owner.
                || Ok(()),
            )?
            .check(false)?;
        diagnostic.finish(function, self.entry_common(access).map(|_| ()))
    }
}

impl crate::AdvancedSession {
    /// Invoke C_GetFunctionStatus without consuming or completing any ticket.
    /// The prescribed CKR_FUNCTION_NOT_PARALLEL stays a native error; this is
    /// unrelated to asynchronous completion or readiness.
    pub fn get_function_status(&self) -> Result<()> {
        let mut diagnostic = None;
        self.session
            .legacy_call(LegacyCall::Status, &mut diagnostic)
    }

    /// Invoke C_CancelFunction without changing any local operation owner.
    /// Its prescribed CKR_FUNCTION_NOT_PARALLEL stays a native error. Even
    /// CKR_OK is not used as proof that an operation was cancelled.
    pub fn cancel_function(&self) -> Result<()> {
        let mut diagnostic = None;
        self.session
            .legacy_call(LegacyCall::Cancel, &mut diagnostic)
    }
}
