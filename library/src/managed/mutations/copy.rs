// SPDX-License-Identifier: Apache-2.0
//! One native copy dispatcher for specialized and generic typed templates.
use crate::{
    error::CompletionDiagnostic,
    managed::revoke_returned_source,
    native::{frame::NativeFrame, template::NativeTemplate},
    native_return::MutationCall,
    session::SessionAccess,
    symmetric::memory::Credit,
    AttributeInput, AttributeTemplateLimits, ContentMutationPlan, Error, ManagedObjectRef,
    ObjectAdmission, ObjectMutationPlan, Result, Session,
};
use fe11_sys::{CK_INVALID_HANDLE, CK_OBJECT_HANDLE};

// Both leaves stay charged by the synchronous root, including while observation
// owners are retired. No diagnostic is retained by the native frame or resident
// copy owner: those owners can outlive the original caller after a failed wait.
pub(crate) struct PreparedCopyDiagnostics {
    storage: Option<CopyDiagnostics>,
    _credit: Credit,
}

pub(crate) type InvocationDiagnostics = Option<(
    PreparedCopyDiagnostics,
    crate::error::PreparedCleanupStorage,
)>;
pub(super) struct CopyDiagnostics {
    completion: CompletionDiagnostic,
    invalid_identity: Box<Error>,
}
impl PreparedCopyDiagnostics {
    pub(super) fn allocation_bytes() -> usize {
        2 * std::mem::size_of::<Error>()
    }

    pub(super) fn prepare(prepaid: &mut Credit) -> Result<Self> {
        let credit = prepaid.split(Self::allocation_bytes())?;
        Ok(Self {
            storage: Some(CopyDiagnostics {
                completion: crate::error::CompletionStorage::allocate()?.bind("C_CopyObject"),
                invalid_identity: crate::allocation::boxed(Error::Rejected(
                    crate::RejectionReason::ObjectCopy(
                        crate::ObjectCopyRejection::CopyReturnedInvalidIdentity,
                    ),
                ))?,
            }),
            _credit: credit,
        })
    }

    pub(super) fn take(&mut self) -> Result<CopyDiagnostics> {
        self.storage
            .take()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectCopy(
                crate::ObjectCopyRejection::CopyDiagnosticsAlreadyConsumed,
            )))
    }
}

pub(super) struct CopyCall {
    template: NativeTemplate,
    created: CK_OBJECT_HANDLE,
    // A suspended parent owns the same proof. Its copy here follows native
    // storage into quarantine on unknown return or changed input witnesses.
    _protection: Option<crate::session::observation_protection::ObservationProtection>,
    _credit: Credit,
}

impl CopyCall {
    /// Charge both stable allocations, excluding the already credited template.
    pub(super) fn typed_frame_bytes() -> usize {
        std::mem::size_of::<Self>()
            + crate::native::frame::SessionFrame::<'_, Self>::allocation_bytes()
            - std::mem::size_of::<crate::attribute_values::InputTemplate>()
    }
    pub(super) fn typed_prepaid(
        template: crate::attribute_values::InputTemplate,
        credit: &mut Credit,
    ) -> Result<Self> {
        Ok(Self {
            template: NativeTemplate::Typed(template),
            created: CK_INVALID_HANDLE,
            _protection: None,
            _credit: credit.split(Self::typed_frame_bytes())?,
        })
    }
    pub(super) fn with_protection(
        mut self,
        protection: crate::session::observation_protection::ObservationProtection,
    ) -> Self {
        self._protection = Some(protection);
        self
    }
}

pub(super) struct CreatedCopy {
    pub(super) handle: CK_OBJECT_HANDLE,
    _creation: crate::managed::CreationTicket,
}

pub(super) struct CompletedCopy {
    handle: CK_OBJECT_HANDLE,
    // Reserved before dispatch and carried to the final publication decision.
    diagnostic: CompletionDiagnostic,
    // Keep creation records alive even if admission observes TOKEN=true and
    // drops the origin before a later content check requests corrective cleanup.
    _creation: crate::managed::CreationTicket,
}
impl CompletedCopy {
    pub(super) fn into_parts(self) -> (CreatedCopy, CompletionDiagnostic) {
        (
            CreatedCopy {
                handle: self.handle,
                _creation: self._creation,
            },
            self.diagnostic,
        )
    }
}

fn public_template<T: crate::attributes::TemplateSink>(
    kind: fe11_sys::CK_ATTRIBUTE_TYPE,
    identity: &[u8],
    label: &[u8],
    persistent: bool,
) -> T {
    let mut template = T::empty();
    template.bytes(kind, identity);
    template.bytes(fe11_sys::CKA_LABEL, label);
    template.boolean(fe11_sys::CKA_TOKEN, persistent);
    template
}

pub(super) fn dispatch_resident(
    session: &Session,
    state: &SessionAccess<'_>,
    source: &crate::NativeObjectRef,
    prepared: CopyCall,
    creation: &mut crate::managed::PreparedCreation,
    diagnostics: CopyDiagnostics,
) -> Result<CompletedCopy> {
    dispatch_owned(session, state, source, prepared, diagnostics, || {
        creation.begin()
    })
}

fn dispatch_owned(
    session: &Session,
    state: &SessionAccess<'_>,
    source: &crate::NativeObjectRef,
    prepared: CopyCall,
    diagnostics: CopyDiagnostics,
    begin: impl FnOnce() -> Result<crate::managed::CreationTicket>,
) -> Result<CompletedCopy> {
    let handle = session.native_object_handle(state, source)?;
    let call = state.native.table.C_CopyObject.ok_or(Error::Rejected(
        crate::RejectionReason::ObjectCopy(crate::ObjectCopyRejection::CCopyObjectUnavailable),
    ))?;
    prepared.template.check_extensions(&session.inner)?;
    let count = prepared.template.count()?;
    let mut frame = NativeFrame::session(state.clone(), prepared)?;
    let CopyDiagnostics {
        completion: diagnostic,
        mut invalid_identity,
    } = diagnostics;
    let creation = begin()?;
    creation.prepare_dispatch(state, || {
        session.entry(state)?;

        state.native.record("C_CopyObject")
    })?;
    let (returned, body) = frame.session_parts();
    let data = &mut *body.data;
    returned.arm();
    // SAFETY: the frame and its retained proof own source activity, session and destination. The
    // complete input graph and output scalar are owned and stable while armed.
    let code = returned.observe(
        unsafe {
            call(
                session.entry.handle,
                handle,
                data.template.as_mut_ptr(),
                count,
                &mut data.created,
            )
        },
        &state.native,
    );
    let mutation = MutationCall::Copy;
    let inspection = session.inspect_native_inputs(state, mutation.function(), code, || {
        data.template.unchanged()
    });
    let completed = inspection.memory_returned();
    let unchanged = !inspection.violated();
    if !unchanged {
        returned.quarantine(&state.native);
    } else if completed {
        returned.terminated();
    } else {
        returned.recoverable();
        session.poison(state);
    }
    let native = inspection.check(!mutation.definite_object_refusal(code));
    if native.is_err()
        && inspection.no_objects(crate::native_return::protocol::CreationContract::Function(
            mutation,
        ))
    {
        creation.refused(state, mutation, code);
    }
    if !unchanged {
        *invalid_identity = diagnostic.boundary_failure(
            code,
            Error::Rejected(crate::RejectionReason::ObjectCopy(
                crate::ObjectCopyRejection::CopyInputChanged,
            )),
        );
        return Err(Error::ObjectsMayRemain(invalid_identity));
    }
    native?;
    let output = data.created;
    if output == handle || output == CK_INVALID_HANDLE {
        // An aliased output is not owned by the copy. Never destroy it. Keep
        // the creation ticket unresolved and invalidate only the source alias
        // if the provider actually returned that source handle as its result.
        if output == handle {
            // Revocation failure and the ordinary alias refusal are exclusive.
            // Keep this one prepared leaf available until that choice is known.
            let mut marker = Some(invalid_identity);
            if let Err(cause) = revoke_returned_source(state, source.identity.resource(), |cause| {
                let mut storage = marker.take().expect("one copy alias failure");
                *storage = cause;
                Error::ObjectsMayRemain(storage)
            }) {
                return diagnostic.finish(Err(cause));
            }
            return diagnostic.finish(Err(Error::ObjectsMayRemain(
                marker
                    .take()
                    .expect("successful revocation retains its marker"),
            )));
        }
        return diagnostic.finish(Err(Error::ObjectsMayRemain(invalid_identity)));
    }
    if let Err(cause) = creation.handles_prepared(state, &[output], |cause| {
        *invalid_identity = cause;
        Error::ObjectsMayRemain(invalid_identity)
    }) {
        return diagnostic.finish(Err(cause));
    }
    drop(frame);
    Ok(CompletedCopy {
        handle: output,
        diagnostic,
        _creation: creation,
    })
}

impl Session {
    /// Copy an object using exactly the supplied standard attribute template.
    /// Omitted attributes are left to C_CopyObject's native inheritance rules;
    /// no ID, label, persistence or application policy is added by this method.
    /// Nested templates and potentially private values retain protected owners.
    ///
    /// The source stays borrowed. Native errors are preserved and never authorize
    /// reading or destroying the output handle. After publication, CreatedObjects
    /// retains the copy independently of a failed requested observation. An
    /// intrinsic publication failure retains its completion/cleanup diagnostic.
    /// There is no automatic retry. Source and unrelated objects are not cleanup
    /// targets, even if the provider returns an invalid or aliased copy handle.
    ///
    /// Stateful signing keys require the same lifecycle precautions documented
    /// on copy_object: this method does not coordinate signing state across copies.
    pub fn copy_object_with_attributes<'a>(
        &self,
        source: &ManagedObjectRef,
        input: &'a [AttributeInput<'a>],
        limits: AttributeTemplateLimits,
        admission: ObjectAdmission,
        mutation: ObjectMutationPlan,
        content: ContentMutationPlan,
    ) -> Result<crate::CreatedObjects<ManagedObjectRef>> {
        let mut diagnostics = None;
        resident::typed(
            self,
            source,
            input,
            limits,
            admission,
            mutation,
            content,
            &mut diagnostics,
        )
    }
}

impl crate::AdvancedSession {
    /// Synchronous generic copy, with the same contract as Session.
    /// This does not enable PKCS#11 native asynchronous mode or add a cooperative worker.
    pub fn copy_object_with_attributes<'a>(
        &self,
        source: &ManagedObjectRef,
        input: &'a [AttributeInput<'a>],
        limits: AttributeTemplateLimits,
        admission: ObjectAdmission,
        mutation: ObjectMutationPlan,
        content: ContentMutationPlan,
    ) -> Result<crate::CreatedObjects<ManagedObjectRef>> {
        let mut diagnostics = None;
        resident::typed(
            &self.session,
            source,
            input,
            limits,
            admission,
            mutation,
            content,
            &mut diagnostics,
        )
    }
}

pub(super) mod resident;
pub(crate) use resident::CopyOwner;
