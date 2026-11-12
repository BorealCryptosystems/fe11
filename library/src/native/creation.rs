// SPDX-License-Identifier: Apache-2.0
//! Owned object creation without stack descriptors or output slots.
use crate::{
    attribute_values::InputTemplate,
    attributes::OwnedTemplate,
    error::CompletionDiagnostic,
    native::{frame::NativeFrame, template::NativeTemplate},
    native_return::MutationCall,
    session::SessionAccess,
    symmetric::memory::Credit,
    transport::secret_template::NativeSecretTemplate,
    Error, Result, Session,
};
use fe11_sys::*;

pub(crate) struct ObjectCreation {
    template: NativeTemplate,
    output: CK_OBJECT_HANDLE,
    // The synchronous access may transfer destination exclusion into a resident
    // observation owner. This copy follows native storage on unknown completion.
    _protection: Option<crate::session::observation_protection::ObservationProtection>,
    _credit: Credit,
}

pub(crate) struct CreatedObject {
    pub(crate) handle: CK_OBJECT_HANDLE,
    _creation: crate::managed::CreationTicket,
}

impl CreatedObject {
    /// Called only after the native creation ticket has accepted the returned
    /// handle. Keep that ticket alive through observation and publication.
    pub(crate) fn accepted(
        handle: CK_OBJECT_HANDLE,
        creation: crate::managed::CreationTicket,
    ) -> Self {
        Self {
            handle,
            _creation: creation,
        }
    }
}

pub(crate) struct CompletedCreation {
    handle: CK_OBJECT_HANDLE,
    diagnostic: CompletionDiagnostic,
    // Retain creation activities through admission/publication or cleanup.
    // TOKEN=true may otherwise remove the only remaining strong origin owner.
    _creation: crate::managed::CreationTicket,
}
impl CompletedCreation {
    pub(crate) fn into_parts(self) -> (CreatedObject, CompletionDiagnostic) {
        (
            CreatedObject {
                handle: self.handle,
                _creation: self._creation,
            },
            self.diagnostic,
        )
    }
}

impl ObjectCreation {
    pub(crate) fn with_protection(
        mut self,
        protection: crate::session::observation_protection::ObservationProtection,
    ) -> Self {
        self._protection = Some(protection);
        self
    }

    // CallData and SessionFrame have distinct allocations. Each template owner
    // already charges its inline payload; retain the remaining credit here.
    pub(crate) fn private_frame_bytes() -> usize {
        std::mem::size_of::<Self>()
            + crate::native::frame::SessionFrame::<'_, Self>::allocation_bytes()
            - std::mem::size_of::<NativeSecretTemplate>()
    }

    pub(crate) fn private_prepaid(
        template: NativeSecretTemplate,
        prepaid: &mut Credit,
    ) -> Result<Self> {
        Ok(Self {
            template: NativeTemplate::Protected(template),
            output: CK_INVALID_HANDLE,
            _protection: None,
            _credit: prepaid.split(Self::private_frame_bytes())?,
        })
    }

    /// CallData and SessionFrame storage outside the public template. Callers
    /// aggregate any additional publication buffers before reserving credit.
    pub(crate) fn public_frame_bytes() -> usize {
        std::mem::size_of::<Self>()
            + crate::native::frame::SessionFrame::<'_, Self>::allocation_bytes()
            - std::mem::size_of::<OwnedTemplate>()
    }

    pub(crate) fn public_prepaid(template: OwnedTemplate, prepaid: &mut Credit) -> Result<Self> {
        Ok(Self {
            template: NativeTemplate::Public(template),
            output: CK_INVALID_HANDLE,
            _protection: None,
            _credit: prepaid.split(Self::public_frame_bytes())?,
        })
    }

    pub(crate) fn typed_frame_bytes() -> usize {
        std::mem::size_of::<Self>()
            + crate::native::frame::SessionFrame::<'_, Self>::allocation_bytes()
            - std::mem::size_of::<InputTemplate>()
    }

    pub(crate) fn typed_prepaid(template: InputTemplate, prepaid: &mut Credit) -> Result<Self> {
        Ok(Self {
            template: NativeTemplate::Typed(template),
            output: CK_INVALID_HANDLE,
            _protection: None,
            _credit: prepaid.split(Self::typed_frame_bytes())?,
        })
    }

    pub(crate) fn execute_resident(
        self,
        session: &Session,
        access: &SessionAccess<'_>,
        creation: &mut crate::managed::PreparedCreation,
        diagnostic: CompletionDiagnostic,
        before_dispatch: impl FnOnce(),
        cleanup: &mut crate::error::CleanupStorage,
    ) -> Result<CompletedCreation> {
        execute_prepared(
            session,
            access,
            self,
            diagnostic,
            before_dispatch,
            || creation.begin(),
            cleanup,
        )
    }
}

fn execute_prepared(
    session: &Session,
    access: &SessionAccess<'_>,
    data: ObjectCreation,
    diagnostic: CompletionDiagnostic,
    before_dispatch: impl FnOnce(),
    begin: impl FnOnce() -> Result<crate::managed::CreationTicket>,
    cleanup: &mut crate::error::CleanupStorage,
) -> Result<CompletedCreation> {
    let call = MutationCall::Create;
    let create = access.native.table.C_CreateObject.ok_or(Error::Rejected(
        crate::RejectionReason::PublicVerification(
            crate::PublicVerificationRejection::CCreateObjectUnavailable,
        ),
    ))?;
    data.template.check_extensions(&session.inner)?;
    let count = data.template.count()?;
    let mut frame = NativeFrame::session(access.clone(), data)?;
    let creation = begin()?;
    let (returned, body) = frame.session_parts();
    let s = &body.access;
    let data = &mut *body.data;
    creation.prepare_dispatch(s, || {
        session.entry(s)?;
        before_dispatch();
        s.native.record(call.function())
    })?;
    returned.arm();
    // SAFETY: complete template storage, descriptor table and scalar output
    // are stable and owned with session/destination protection in this frame.
    let rv = returned.observe(
        unsafe {
            create(
                session.entry.handle,
                data.template.as_mut_ptr(),
                count,
                &mut data.output,
            )
        },
        &s.native,
    );
    let inspection =
        session.inspect_native_inputs(s, call.function(), rv, || data.template.unchanged());
    let completed = inspection.memory_returned();
    let unchanged = !inspection.violated();
    if !unchanged {
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
                crate::NativeExecutionRejection::ObjectCreationInputChanged,
            )),
        )));
    }
    native?;
    let output = data.output;
    if let Err(cause) =
        creation.handles_prepared(s, &[output], |cause| cleanup.mark_remaining(cause))
    {
        return diagnostic.finish(Err(cause));
    }
    // Ordinary release erases both native private buffers and their witnesses
    // before caller metadata reads. Uncertain frames keep those owners instead.
    Ok(CompletedCreation {
        handle: output,
        diagnostic,
        _creation: creation,
    })
}
