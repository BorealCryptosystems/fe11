// SPDX-License-Identifier: Apache-2.0
//! Expose session admission settings and publish local context observations.
//! Poisoning and mutation checks affect the retained session owner, not arbitrary peers.

use super::*;

impl Session {
    /// Choose how ordinary/advanced access waits for this session's owner.
    /// New sessions inherit the explicit calling scope, or Immediate without
    /// one. This override affects the session owner only; shared resources use
    /// with_resource_admission. Session close possession remains nonblocking.
    /// A WaitUntil deadline is absolute and is never renewed automatically.
    pub fn set_admission(&mut self, admission: crate::SessionAdmission) {
        self.admission = Some(admission);
    }

    /// Current session override, or the calling thread's inherited admission.
    pub fn admission(&self) -> crate::SessionAdmission {
        self.admission
            .clone()
            .unwrap_or_else(crate::admission_wait::current)
    }

    /// Restore the enclosing explicit scope, or Immediate outside a scope.
    pub fn inherit_admission(&mut self) {
        self.admission = None;
    }

    /// Local callback diagnostics. None means no Notify handler was registered.
    /// This does not acquire native admission or invoke the module.
    pub fn notify_diagnostics(&self) -> Option<crate::NotifyDiagnostics> {
        self.entry
            .notification
            .as_ref()
            .map(|notification| notification.diagnostics())
    }

    pub(super) fn epoch_domain(&self) -> Result<Arc<crate::admission_wait::Wake>> {
        let context = self.inner.state.admission_wake();
        // Install fixed links before any predicate or sleep. A preceding
        // context publication is observed by the subsequent atomic check.
        self.snapshot.domain.activity.bind_context(&context)?;
        self.entry.operation.bind_context(&context)?;
        Ok(context)
    }

    pub(crate) fn poison(&self, _s: &State) {
        self.entry.poisoned.store(true, Ordering::Release);
        self.snapshot.notify_admission();
    }

    // Called only after a successful native mutation has retained its ownership
    // evidence. Local withdrawal cannot make that effect disappear.
    /// The public invocation retains the credit of the supplied error marker.
    pub(crate) fn mutation_context(
        &self,
        s: &State,
        mark_remaining: impl FnOnce(Error) -> Error,
    ) -> Result<()> {
        self.entry(s).map(|_| ()).map_err(mark_remaining)
    }

    /// Retrieve actual session state; this does not rediscover token capabilities.
    /// A parked cooperative operation keeps its ticket and buffers. This read
    /// takes ordinary session possession without resuming that operation.
    pub fn info(&self) -> Result<SessionInfo> {
        self.check_synchronous_dispatch()?;
        let (data, diagnostic, s) =
            self.prepare_control_with_completion(crate::native::output::session_info)?;
        let h = self.entry_common(&s)?.handle;
        let mut frame = crate::native::frame::NativeFrame::session(s, data)?;
        let (returned, body) = frame.session_parts();
        let s = &body.access;
        let get_info =
            crate::native::functions::resolve(s.native.table.C_GetSessionInfo, "C_GetSessionInfo")?;
        s.native.record("C_GetSessionInfo")?;
        returned.arm();
        // SAFETY: the stable frame owns the aligned output and the guards with
        // their referent allocations. Uncompleted calls retain all of them.
        let rv = returned.observe(unsafe { get_info(h, &mut body.data.value) }, &s.native);
        // GetSessionInfo opens no multipart operation. A certain native return
        // permits release; no output is inspected on an error.
        if crate::native_return::SessionCall::Info.completion_known(rv) {
            returned.terminated();
        }
        s.check_session_return(
            &self.entry,
            crate::native_return::SessionCall::Info,
            rv,
            false,
        )?;
        let info = &body.data.value;
        // This includes a login performed through another participant. It is
        // an observation of this return, never proof of PIN verification by Fe11
        // or authority for a subsequent call. Preserve CKR_OK on local failure.
        diagnostic.cell().finish(
            "C_GetSessionInfo",
            self.snapshot.observe_session_state(info.state),
        )?;
        self.metadata_result(
            &s,
            None,
            Ok(SessionInfo {
                slot: info.slotID as u64,
                state: info.state as u64,
                flags: info.flags as u64,
                device_error: info.ulDeviceError as u64,
            }),
        )
    }
}
