// SPDX-License-Identifier: Apache-2.0
//! Stable native boundary shared by parameterless key-pair generators.
use crate::{
    attributes::OwnedTemplate,
    error::CompletionDiagnostic,
    native::{frame::NativeFrame, template::NativeTemplate},
    native_return::MutationCall,
    session::SessionAccess,
    symmetric::memory::Credit,
    Error, Result, Session,
};
use fe11_sys::*;
pub(crate) mod parameters;
use parameters::Parameters;

pub(crate) struct PairGeneration {
    mechanism: CK_MECHANISM,
    parameters: Parameters,
    public: NativeTemplate,
    private: NativeTemplate,
    public_handle: CK_OBJECT_HANDLE,
    private_handle: CK_OBJECT_HANDLE,
    _credit: Credit,
}
// SAFETY: parameters own their aligned graph and templates own descriptor
// referents. Output scalars are pinned by CallData before native dispatch.
unsafe impl Send for PairGeneration {}

impl PairGeneration {
    /// Charge CallData and its SessionFrame; template owners already charge
    /// their inline payload. The generation owner retains the remaining credit.
    pub(crate) fn public_frame_bytes() -> usize {
        std::mem::size_of::<Self>()
            + crate::native::frame::SessionFrame::<'_, Self>::allocation_bytes()
            - 2 * std::mem::size_of::<OwnedTemplate>()
    }

    pub(crate) fn allocation_bytes() -> usize {
        std::mem::size_of::<Self>()
            + crate::native::frame::SessionFrame::<'_, Self>::allocation_bytes()
            - 2 * std::mem::size_of::<crate::attribute_values::InputTemplate>()
    }

    pub(crate) fn new(
        kind: CK_MECHANISM_TYPE,
        public: NativeTemplate,
        private: NativeTemplate,
        credit: Credit,
    ) -> Self {
        Self {
            mechanism: parameterless(kind),
            parameters: Parameters::None,
            public,
            private,
            public_handle: CK_INVALID_HANDLE,
            private_handle: CK_INVALID_HANDLE,
            _credit: credit,
        }
    }

    pub(crate) fn with_parameters(mut self, parameters: Parameters) -> Self {
        self.parameters = parameters;
        self
    }

    pub(crate) fn execute_resident(
        self,
        session: &Session,
        access: &SessionAccess<'_>,
        diagnostic: crate::error::CompletionStorage,
        mut creation: crate::managed::PreparedCreation,
        before_dispatch: impl FnOnce(),
        mark_remaining: impl FnOnce(Error) -> Error,
    ) -> Result<CompletedGeneration<2>> {
        self.execute_prepared(
            session,
            access,
            diagnostic,
            || creation.begin(),
            before_dispatch,
            mark_remaining,
        )
    }
    fn execute_prepared(
        self,
        session: &Session,
        access: &SessionAccess<'_>,
        diagnostic: crate::error::CompletionStorage,
        begin: impl FnOnce() -> Result<crate::managed::CreationTicket>,
        before_dispatch: impl FnOnce(),
        mark_remaining: impl FnOnce(Error) -> Error,
    ) -> Result<CompletedGeneration<2>> {
        let call = MutationCall::GeneratePair;
        let generate = access
            .native
            .table
            .C_GenerateKeyPair
            .ok_or(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::CGenerateKeyPairUnavailable,
            )))?;
        self.parameters
            .check_extension(&session.inner, crate::ExtensionOperation::GenerateKeyPair)?;
        self.public.check_extensions(&session.inner)?;
        self.private.check_extensions(&session.inner)?;
        let public_count = self.public.count()?;
        let private_count = self.private.count()?;
        let kind = self.mechanism.mechanism;
        let diagnostic = diagnostic.bind(call.function());
        let mut frame = NativeFrame::session(access.clone(), self)?;
        // No creation record is installed until every fallible frame allocation
        // has completed. Its provenance remains in the reservation catalogue.
        let creation = begin()?;
        let (returned, body) = frame.session_parts();
        let s = &body.access;
        let data = &mut *body.data;
        let (pointer, length) = data.parameters.projection();
        data.mechanism.pParameter = pointer;
        data.mechanism.ulParameterLen = length;
        creation.prepare_dispatch(s, || {
            session.entry(s)?;
            before_dispatch();
            s.native.record(call.function())
        })?;
        returned.arm();
        // SAFETY: the complete representation and destination guards are owned by
        // the frame. Counts are checked, output slots distinct and stable. No
        // caller-borrowed template data or stack output address reaches native code.
        let rv = returned.observe(
            unsafe {
                generate(
                    session.entry.handle,
                    &mut data.mechanism,
                    data.public.as_mut_ptr(),
                    public_count,
                    data.private.as_mut_ptr(),
                    private_count,
                    &mut data.public_handle,
                    &mut data.private_handle,
                )
            },
            &s.native,
        );
        let inspection = session.inspect_native_inputs(s, call.function(), rv, || {
            data.mechanism.mechanism == kind
                && data.parameters.unchanged(&data.mechanism)
                && data.public.unchanged()
                && data.private.unchanged()
        });
        let completed = rv == CKR_OK || call.non_creation(rv);
        let unchanged = !inspection.violated();
        let output_bounds = if rv == CKR_OK && unchanged {
            data.parameters.validate_output_bounds()
        } else {
            Ok(())
        };
        if !unchanged || output_bounds.is_err() {
            returned.quarantine(&s.native);
        } else if completed {
            returned.terminated();
        } else {
            // A returned but unproved generation keeps its representation until
            // successful session closure. PENDING cannot be downgraded by this.
            returned.recoverable();
            session.poison(s);
        }
        let native = inspection.check(!call.definite_object_refusal(rv));
        if native.is_err()
            && inspection.no_objects(crate::native_return::protocol::CreationContract::Function(
                call,
            ))
        {
            creation.refused(s, call, rv);
        }
        if !unchanged {
            return Err(mark_remaining(diagnostic.boundary_failure(
                rv,
                Error::Rejected(crate::RejectionReason::NativeExecution(
                    crate::NativeExecutionRejection::KeyPairGenerationInputChanged,
                )),
            )));
        }
        if let Err(cause) = output_bounds {
            return Err(mark_remaining(diagnostic.boundary_failure(rv, cause)));
        }
        native?;
        let handles = [data.public_handle, data.private_handle];
        if let Err(cause) = creation.handles_prepared(s, &handles, mark_remaining) {
            return diagnostic.finish(Err(cause));
        }
        let output = data.parameters.take_output();
        Ok(CompletedGeneration {
            handles,
            diagnostic,
            _creation: creation,
            output,
        })
    }
}

pub(crate) struct KeyGeneration {
    mechanism: CK_MECHANISM,
    template: NativeTemplate,
    parameters: Parameters,
    handle: CK_OBJECT_HANDLE,
    _credit: Credit,
}
// SAFETY: owned mechanism parameters, template and one stable output slot;
// no borrowed native address survives the constructing function.
unsafe impl Send for KeyGeneration {}

impl KeyGeneration {
    /// Charge both stable allocations, excluding the template already credited.
    pub(crate) fn allocation_bytes() -> usize {
        std::mem::size_of::<Self>()
            + crate::native::frame::SessionFrame::<'_, Self>::allocation_bytes()
            - std::mem::size_of::<crate::attribute_values::InputTemplate>()
    }

    pub(crate) fn new(
        kind: CK_MECHANISM_TYPE,
        template: NativeTemplate,
        parameters: Parameters,
        credit: Credit,
    ) -> Self {
        Self {
            mechanism: parameterless(kind),
            template,
            parameters,
            handle: CK_INVALID_HANDLE,
            _credit: credit,
        }
    }

    pub(crate) fn execute_resident(
        self,
        session: &Session,
        access: &SessionAccess<'_>,
        diagnostic: crate::error::CompletionStorage,
        mut creation: crate::managed::PreparedCreation,
        cleanup: &mut crate::error::CleanupStorage,
    ) -> Result<(
        CompletedGeneration<1>,
        Result<crate::NativeGenerationOutput>,
    )> {
        self.execute_prepared(session, access, diagnostic, || creation.begin(), cleanup)
    }
    fn execute_prepared(
        self,
        session: &Session,
        access: &SessionAccess<'_>,
        diagnostic: crate::error::CompletionStorage,
        begin: impl FnOnce() -> Result<crate::managed::CreationTicket>,
        cleanup: &mut crate::error::CleanupStorage,
    ) -> Result<(
        CompletedGeneration<1>,
        Result<crate::NativeGenerationOutput>,
    )> {
        let call = MutationCall::GenerateKey;
        let generate = access.native.table.C_GenerateKey.ok_or(Error::Rejected(
            crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::CGenerateKeyUnavailable,
            ),
        ))?;
        self.template.check_extensions(&session.inner)?;
        self.parameters
            .check_extension(&session.inner, crate::ExtensionOperation::GenerateKey)?;
        let count = self.template.count()?;
        let kind = self.mechanism.mechanism;
        let diagnostic = diagnostic.bind(call.function());
        let mut frame = NativeFrame::session(access.clone(), self)?;
        let creation = begin()?;
        let (returned, body) = frame.session_parts();
        let s = &body.access;
        let data = &mut *body.data;
        let (pointer, length) = data.parameters.projection();
        data.mechanism.pParameter = pointer;
        data.mechanism.ulParameterLen = length;
        creation.prepare_dispatch(s, || {
            session.entry(s)?;
            s.native.record(call.function())
        })?;
        returned.arm();
        // SAFETY: checked descriptor count; all descriptor referents, mechanism
        // and output belong to this retained frame under session/destination guards.
        let rv = returned.observe(
            unsafe {
                generate(
                    session.entry.handle,
                    &mut data.mechanism,
                    data.template.as_mut_ptr(),
                    count,
                    &mut data.handle,
                )
            },
            &s.native,
        );
        let inspection = session.inspect_native_inputs(s, call.function(), rv, || {
            data.mechanism.mechanism == kind
                && data.parameters.unchanged(&data.mechanism)
                && data.template.unchanged()
        });
        let completed = rv == CKR_OK || call.non_creation(rv);
        let unchanged = !inspection.violated();
        let output_bounds = if rv == CKR_OK && unchanged {
            data.parameters.validate_output_bounds()
        } else {
            Ok(())
        };
        if !unchanged || output_bounds.is_err() {
            returned.quarantine(&s.native);
        } else if completed {
            returned.terminated();
        } else {
            returned.recoverable();
            session.poison(s);
        }
        let native = inspection.check(!call.definite_object_refusal(rv));
        if native.is_err()
            && inspection.no_objects(crate::native_return::protocol::CreationContract::Function(
                call,
            ))
        {
            creation.refused(s, call, rv);
        }
        if !unchanged {
            return Err(cleanup.mark_remaining(diagnostic.boundary_failure(
                rv,
                Error::Rejected(crate::RejectionReason::NativeExecution(
                    crate::NativeExecutionRejection::KeyGenerationInputChanged,
                )),
            )));
        }
        if let Err(cause) = output_bounds {
            return Err(cleanup.mark_remaining(diagnostic.boundary_failure(rv, cause)));
        }
        native?;
        let handles = [data.handle];
        if let Err(cause) =
            creation.handles_prepared(s, &handles, |cause| cleanup.mark_remaining(cause))
        {
            return diagnostic.finish(Err(cause));
        }
        // Retain the creation ticket even when auxiliary output cannot be
        // published: the caller still needs the registered handle for cleanup.
        let output = data.parameters.take_output();
        Ok((
            CompletedGeneration {
                handles,
                diagnostic,
                _creation: creation,
                output: Ok(crate::NativeGenerationOutput::None),
            },
            output,
        ))
    }
}

fn parameterless(kind: CK_MECHANISM_TYPE) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: kind,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    }
}

/// Preserve the native effect and its provenance through observation/cleanup.
/// In particular, token objects must not lose their only strong creation owner
/// when the native frame is released before their metadata is read.
pub(crate) struct CompletedGeneration<const N: usize> {
    output: Result<crate::NativeGenerationOutput>,
    handles: [CK_OBJECT_HANDLE; N],
    diagnostic: CompletionDiagnostic,
    _creation: crate::managed::CreationTicket,
}
impl<const N: usize> CompletedGeneration<N> {
    pub(crate) fn registered(
        handles: [CK_OBJECT_HANDLE; N],
        diagnostic: CompletionDiagnostic,
        creation: crate::managed::CreationTicket,
    ) -> Self {
        Self {
            handles,
            diagnostic,
            _creation: creation,
            output: Ok(crate::NativeGenerationOutput::None),
        }
    }
    pub(crate) fn into_parts_with_output(
        self,
    ) -> (
        [CK_OBJECT_HANDLE; N],
        crate::managed::CreationTicket,
        CompletionDiagnostic,
        Result<crate::NativeGenerationOutput>,
    ) {
        (self.handles, self._creation, self.diagnostic, self.output)
    }
    pub(crate) fn into_parts(
        self,
    ) -> (
        [CK_OBJECT_HANDLE; N],
        crate::managed::CreationTicket,
        CompletionDiagnostic,
    ) {
        (self.handles, self._creation, self.diagnostic)
    }
    pub(crate) fn handles(&self) -> [CK_OBJECT_HANDLE; N] {
        self.handles
    }
    pub(crate) fn finish<T>(self, result: Result<T>) -> Result<T> {
        self.diagnostic.finish(result)
    }
}
