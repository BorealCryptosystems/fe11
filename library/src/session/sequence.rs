// SPDX-License-Identifier: Apache-2.0
//! Track native sequence returns and validate continuing operation context.
//! Output capacity, completion diagnostics and sequence termination are separate observations.

use super::*;

impl<'a> Sequence<'a> {
    /// Observe and inspect while the existing frame still owns every operand.
    /// Only the resulting token may be projected as a native error or verdict.
    pub(crate) fn inspect_return(
        &self,
        rv: CK_RV,
        function: &'static str,
        phase: crate::native_return::protocol::SequencePhase,
        inspect: impl FnOnce() -> Result<()>,
    ) -> Result<crate::native_return::protocol::ReturnCode> {
        self.inspect_return_with_size(rv, function, phase, inspect, || None)
    }

    /// Read a defined length only after memory return, preserving it on both
    /// ordinary capacity refusal and a simultaneous descriptor failure.
    pub(crate) fn inspect_output_return(
        &self,
        rv: CK_RV,
        function: &'static str,
        capacity: usize,
        length: impl FnOnce() -> fe11_sys::CK_ULONG,
        inspect: impl FnOnce() -> Result<()>,
    ) -> Result<crate::native_return::protocol::ReturnCode> {
        self.inspect_return_with_size(
            rv,
            function,
            crate::native_return::protocol::SequencePhase::Continue(OutputRequest::Buffer),
            inspect,
            || {
                (rv == fe11_sys::CKR_BUFFER_TOO_SMALL
                    && crate::native_return::call_memory_returned(rv))
                .then(|| crate::NativeOutputSize {
                    function,
                    code: rv as u64,
                    reported: length() as u64,
                    limit: capacity,
                })
            },
        )
    }

    fn inspect_return_with_size(
        &self,
        rv: CK_RV,
        function: &'static str,
        phase: crate::native_return::protocol::SequencePhase,
        inspect: impl FnOnce() -> Result<()>,
        output: impl FnOnce() -> Option<crate::NativeOutputSize>,
    ) -> Result<crate::native_return::protocol::ReturnCode> {
        use crate::native_return::protocol::{PendingInspection, SequencePhase};
        let inspected = PendingInspection::returned(function, rv, |scope| {
            if let Some((state, session)) = self.context {
                state.apply_session_failure(&session.entry, rv, scope);
            }
        })
        .inspect(inspect);
        let attempt_returned = self.completion.get() != Completion::Uncertain
            && inspected.initialization_refused(self.version(), phase);
        self.retain_completion(inspected.completion(self.version(), phase));
        if attempt_returned {
            self.initialization_refused.set(true);
            if let Some(frame) = self.frame {
                frame.attempt_returned();
            }
        }
        let size = output();
        let result = inspected.resolve(|result, cause| {
            if let Some((state, _)) = self.context {
                state.native.mark_uncertain();
            }
            match &self.diagnostic {
                SequenceDiagnostic::Prepared(diagnostic) => match size {
                    Some(size) => diagnostic.output_failure(size, cause),
                    None => diagnostic.boundary_failure(result.function(), result.code(), cause),
                },
            }
        })?;
        if let Some(size) = size {
            return Err(size.buffer_too_small());
        }
        // Output identity belongs to an intact successful output call only.
        // An Init or an error cannot leave an old publication receipt selected.
        match phase {
            SequencePhase::Initialize => self.output_function.set(None),
            SequencePhase::Continue(OutputRequest::Buffer) if rv == CKR_OK => {
                self.output_function.set(Some(function));
            }
            SequencePhase::Continue(_) => {}
        }
        Ok(result)
    }

    pub(super) fn for_session(
        state: &'a State,
        session: &'a Session,
        diagnostic: SequenceDiagnostic<'a>,
    ) -> Self {
        Self {
            poison: &session.entry.poisoned,
            completion: std::cell::Cell::new(Completion::Unproven),
            initialization_refused: std::cell::Cell::new(false),
            output_function: std::cell::Cell::new(None),
            context: Some((state, session)),
            frame: None,
            diagnostic,
        }
    }

    /// The invocation prepaid this leaf before taking the native frame. Any
    /// completion failure is terminal for these callers, so publication can reuse
    /// the same leaf when the native sequence did not consume it.
    pub(crate) fn for_frame_prepared(
        state: &'a State,
        session: &'a Session,
        frame: crate::native::frame::FrameReturn<'a>,
        diagnostic: &'a crate::error::CompletionCell,
    ) -> Self {
        let mut sequence =
            Self::for_session(state, session, SequenceDiagnostic::Prepared(diagnostic));
        frame.arm();
        sequence.frame = Some(frame);
        sequence
    }

    pub(super) fn completed_error(&self, function: &'static str, cause: Error) -> Error {
        match &self.diagnostic {
            SequenceDiagnostic::Prepared(diagnostic) => diagnostic.completed_error(function, cause),
        }
    }

    // Local availability only, under the existing session/lifecycle guards.
    // Refusal does not terminate an already-started native operation.
    pub(crate) fn check_context(&self) -> Result<()> {
        if self.completion.get() == Completion::Uncertain {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::SequenceOutcomeUncertain,
            )));
        }
        let (state, session) =
            self.context
                .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::SequenceContextUnavailable,
                )))?;
        session.entry(state)?;
        Ok(())
    }

    pub(crate) fn record_next(&self, function: &'static str) -> Result<()> {
        self.check_context()?;
        // check_context validated this immutable Option on the same Sequence.
        // It is assigned only by construction; neither callbacks nor the native
        // outcome can clear it between validation and dispatch accounting.
        self.context
            .expect("validated sequence context")
            .0
            .native
            .record(function)?;
        if self.completion.get() == Completion::Terminated {
            self.output_function.set(None);
        }
        // Arm before dispatch, including an unwind between native return and
        // classification. No old completion proof covers this new call.
        self.completion.set(Completion::Unproven);
        self.initialization_refused.set(false);
        if let Some(frame) = self.frame {
            frame.arm();
        }
        Ok(())
    }

    // Observe scope before a caller converts the error. This path performs no
    // native call, acquires no exclusive activity guard and frees no resource.
    pub(super) fn observe(&self, rv: CK_RV) {
        if let Some((state, session)) = self.context {
            let scope = crate::native_return::native_context_scope(rv);
            state.apply_session_failure(&session.entry, rv, scope);
        }
    }

    pub(super) fn version(&self) -> (u8, u8) {
        self.context.map_or((3, 2), |(state, _)| {
            let version = state.native.table.version;
            (version.major, version.minor)
        })
    }

    pub(super) fn retain_completion(&self, completion: Completion) {
        // A subsequent local "complete" cannot erase native uncertainty.
        if self.completion.get() != Completion::Uncertain {
            self.completion.set(completion);
            if let Some(frame) = self.frame {
                match completion {
                    Completion::Terminated => frame.terminated(),
                    Completion::Unproven => frame.active(),
                    Completion::Uncertain => frame.uncompleted(),
                }
            }
        }
    }

    pub(crate) fn check(
        &self,
        rv: CK_RV,
        function: &'static str,
        may_have_effect: bool,
    ) -> Result<()> {
        self.check_return(rv, function, may_have_effect, OutputRequest::Unspecified)
    }

    // The caller actually supplied an output buffer, including a non-NULL
    // zero-capacity buffer. Never use this method for a NULL sizing request.

    pub(super) fn check_return(
        &self,
        rv: CK_RV,
        function: &'static str,
        may_have_effect: bool,
        output: OutputRequest,
    ) -> Result<()> {
        self.observe(rv);
        if rv == CKR_OK && output == OutputRequest::Buffer {
            self.output_function.set(Some(function));
        }
        self.retain_completion(crate::native_return::sequence::returned(
            self.version(),
            function,
            output,
            rv,
        ));
        let uncertain = crate::native_return::effect_uncertain(rv);
        check(rv, function, may_have_effect || uncertain)
    }

    // An out-of-allocation length or altered descriptor is a boundary anomaly,
    // not just a semantically unacceptable value inside the allocated output.
    pub(crate) fn invalid_output(&self, reason: crate::RejectionReason) -> Error {
        self.retain_completion(Completion::Uncertain);
        if let Some((state, _)) = self.context {
            state.native.mark_uncertain();
        }
        Error::Rejected(reason)
    }

    pub(crate) fn invalid_value(&self, reason: crate::RejectionReason) -> Error {
        // Publication is refused. Preserve the known successful native output
        // and termination in the diagnostic; do not invite a business retry.
        // An uncompleted multipart/message owner still withdraws on Drop.
        let cause = Error::Rejected(reason);
        if self.completion.get() == Completion::Terminated {
            if let Some(function) = self.output_function.get() {
                return self.completed_error(function, cause);
            }
        }
        cause
    }

    pub(crate) fn complete(&mut self) {
        self.retain_completion(Completion::Terminated);
    }

    pub(crate) fn termination_known(&self) -> bool {
        self.completion.get() == Completion::Terminated
    }

    // Only after C_Decrypt or C_DecryptFinal with an actual output buffer. PKCS#11 terminates
    // that operation on these invalid-input returns. This does not establish
    // a successful decryption, clear an existing withdrawal, or classify a
    // device/general error as invalid input. The caller still erases output.
    pub(crate) fn finish_invalid_decrypt(&mut self, rv: CK_RV) -> bool {
        if matches!(
            rv,
            CKR_ENCRYPTED_DATA_INVALID | CKR_ENCRYPTED_DATA_LEN_RANGE
        ) {
            self.complete();
            true
        } else {
            false
        }
    }
}

impl Drop for Sequence<'_> {
    fn drop(&mut self) {
        if self.completion.get() != Completion::Terminated && !self.initialization_refused.get() {
            self.poison.store(true, Ordering::Release);
        }
    }
}
