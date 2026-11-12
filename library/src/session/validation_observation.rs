// SPDX-License-Identifier: Apache-2.0
//! A current native validation observation, without a correlated operation claim.
use crate::{native::frame::NativeFrame, Error, Result, Session};
use fe11_sys::{CK_FLAGS, CK_SESSION_VALIDATION_FLAGS_TYPE};
use std::sync::atomic::Ordering;

impl Session {
    /// Query `C_GetSessionValidationFlags` with the exact caller-selected type.
    /// The module determines supported selectors and the meaning of returned
    /// bits. Neither a missing function nor a refusal is converted to zero.
    ///
    /// This standalone read accepts a synchronous or cooperative session,
    /// including one with a parked operation. It takes session possession without
    /// consuming or resuming that operation's ticket.
    /// It does not run a cryptographic operation or establish which earlier
    /// operation the module's flags describe. Use the existing per-operation
    /// validation capture when that correlation is required. Native asynchronous
    /// sessions retain their separate dispatch rules.
    pub fn validation_flags(&self, flags_type: u64) -> Result<u64> {
        self.check_synchronous_dispatch()?;
        let flags_type = CK_SESSION_VALIDATION_FLAGS_TYPE::try_from(flags_type).map_err(|_| {
            Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ValidationFlagsTypeConversion,
            ))
        })?;
        let (data, access) = self.prepare_control(|| 0 as CK_FLAGS)?;
        let handle = self.entry_common(&access)?.handle;
        let call = access
            .native
            .asynchronous
            .and_then(|functions| functions.validation)
            .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::CGetSessionValidationFlagsUnavailable,
            )))?;
        let mut frame = NativeFrame::session(access, data)?;
        let (returned, body) = frame.session_parts();
        let state = &body.access;
        state.native.record("C_GetSessionValidationFlags")?;
        returned.arm();
        // SAFETY: the frame owns initialized, aligned CK_FLAGS storage and the
        // session/module guards. The selected function's checked 3.2 table has
        // this ABI. Uncertain returns retain that frame through session recovery.
        let rv = returned.observe(
            unsafe { call(handle, flags_type, &mut body.data.value) },
            &state.native,
        );
        if crate::native_return::call_memory_returned(rv) {
            returned.terminated();
        }
        // Match the read classifier used by the correlated validation owner:
        // ordinary read refusals do not withdraw an otherwise usable session.
        let scope = crate::native_return::attribute_scope(rv);
        if scope != crate::native_return::FailureScope::None {
            self.entry.poisoned.store(true, Ordering::Release);
            state.apply_session_failure(&self.entry, rv, scope);
        }
        crate::error::check(
            rv,
            "C_GetSessionValidationFlags",
            crate::native_return::effect_uncertain(rv),
        )?;
        self.metadata_result(state, None, Ok(body.data.value as u64))
    }
}

impl crate::AdvancedSession {
    /// Make the same standalone observation on a cooperative session.
    /// This does not change validation capture selection or a ticket's report.
    /// It remains available after plain synchronous facades, independently of
    /// set_validation_capture; the caller controls the ordering of this read.
    pub fn validation_flags(&self, flags_type: u64) -> Result<u64> {
        self.session.validation_flags(flags_type)
    }
}
