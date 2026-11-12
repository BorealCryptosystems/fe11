// SPDX-License-Identifier: Apache-2.0
//! Exact wrap/unwrap calls sharing owned parameter graphs and creation tracking.
use super::*;
pub(crate) mod fixed_prefix;
mod resolved;
use crate::{
    attribute_values::InputTemplate,
    bounds,
    error::CompletionStorage,
    managed::{RevocationShape, RevocationTargets},
    native::{
        derivation::InputBytes,
        frame::{NativeFrame, SessionFrame},
        generation::CompletedGeneration,
    },
    native_return::MutationCall,
    session::SessionAccess,
    symmetric::memory::{Buffer, Credit},
    NativeObjectRef, Session,
};
use fe11_sys::*;
use std::mem::size_of;

struct Wrap {
    mechanism: CK_MECHANISM,
    graph: OwnedGraph,
    bytes: Buffer,
    length: CK_ULONG,
    fixed_prefix: Option<fixed_prefix::FixedPrefix>,
    _credit: Credit,
}
// SAFETY: all native pointers address allocations owned by this frame's graph
// or output buffer. NativeFrame retains the session and both key activities.
unsafe impl Send for Wrap {}

pub(crate) fn wrap(
    session: &Session,
    request: ExtensionRequest<'_>,
    key: &crate::NativeObjectRef,
    target: &crate::NativeObjectRef,
    capacity: usize,
    diagnostic_root: &mut Option<Credit>,
) -> Result<ExtensionResult> {
    wrap_with_sources(
        session,
        request,
        key,
        Some(target),
        capacity,
        [None; 4],
        diagnostic_root,
    )
}
pub(crate) fn wrap_with_sources<'a>(
    session: &Session,
    request: impl Into<super::graph::recipe::Request<'a>>,
    key: &crate::NativeObjectRef,
    target: Option<&crate::NativeObjectRef>,
    capacity: usize,
    sources: [Option<&NativeObjectRef>; 4],
    diagnostic_root: &mut Option<Credit>,
) -> Result<ExtensionResult> {
    wrap_with_fixed_prefix(
        session,
        request,
        key,
        target,
        capacity,
        sources,
        None,
        diagnostic_root,
    )
}
pub(crate) fn wrap_with_fixed_prefix<'a>(
    session: &Session,
    request: impl Into<super::graph::recipe::Request<'a>>,
    key: &crate::NativeObjectRef,
    target: Option<&crate::NativeObjectRef>,
    capacity: usize,
    sources: [Option<&NativeObjectRef>; 4],
    fixed_prefix: Option<fixed_prefix::FixedPrefix>,
    diagnostic_root: &mut Option<Credit>,
) -> Result<ExtensionResult> {
    let request = request.into();
    request
        .contract
        .check(&session.inner, ExtensionOperation::WrapKey)?;
    let length = bounds::ck_length(capacity)?;
    let base_bytes = OwnedGraph::recipe_bytes(request.parameters.recipe())?
        .checked_add(size_of::<Wrap>() - size_of::<OwnedGraph>())
        .and_then(|n| n.checked_add(SessionFrame::<'_, Wrap>::allocation_bytes()))
        .and_then(|n| n.checked_add(capacity))
        .and_then(|n| n.checked_add(CompletionStorage::allocation_bytes()))
        .ok_or(Error::Rejected(
            crate::RejectionReason::MechanismExtensions(
                crate::MechanismExtensionsRejection::WrapStorageAccounting,
            ),
        ))?;
    let progress = crate::session::AdmissionProgress::default();
    let mutates = request.contract.mutates_key();
    use crate::session::activity::AccessMode;
    let primary = if mutates {
        AccessMode::Write
    } else {
        AccessMode::Read
    };
    // This epoch spans every registry-growth replan of the original request.
    let authentication = session.snapshot.authentication_stamp();
    // Destructured locals drop in reverse binding order: possession leaves
    // before the successful revocation snapshot on subsequent preflight errors.
    let (diagnostic_credit, diagnostic, prepared, mutation, state) = loop {
        let shape = mutates
            .then(|| RevocationShape::discover(session, key.identity.resource(), authentication))
            .transpose()?;
        let required = base_bytes
            .checked_add(
                shape
                    .as_ref()
                    .map(RevocationShape::allocation_bytes)
                    .transpose()?
                    .unwrap_or(0),
            )
            .ok_or(Error::Rejected(
                crate::RejectionReason::MechanismExtensions(
                    crate::MechanismExtensionsRejection::WrapRevocationStorageAccounting,
                ),
            ))?;
        let ((diagnostic_credit, diagnostic, prepared, mut revocation), state) = session
            .prepare_with_native_roles_prepaid_at_epoch(
                [
                    (Some(key), primary),
                    (target, AccessMode::Read),
                    (sources[0], AccessMode::Read),
                    (sources[1], AccessMode::Read),
                    (sources[2], AccessMode::Read),
                    (sources[3], AccessMode::Read),
                ],
                false,
                authentication,
                &progress,
                |overhead| {
                    let mut required = required.checked_add(overhead).ok_or(Error::Rejected(
                        crate::RejectionReason::MechanismExtensions(
                            crate::MechanismExtensionsRejection::WrapAggregateStorageAccounting,
                        ),
                    ))?;
                    loop {
                        session
                            .snapshot
                            .check_authentication_unchanged(authentication)?;
                        let mut prepaid = crate::advanced::reserve_preparation_at_epoch(
                            session,
                            required,
                            &progress,
                            authentication,
                        )?;
                        let graph = super::graph::GraphStorage::allocate_input(request.parameters)?;
                        let revocation = shape.map(RevocationShape::allocate).transpose()?;
                        let revocation_bytes = revocation
                            .as_ref()
                            .map(|storage| storage.allocated_bytes())
                            .transpose()?
                            .unwrap_or(0);
                        let bytes = crate::symmetric::memory::UnboundBuffer::allocate(capacity)?;
                        // NativeFrame owns both the Wrap allocation and a separate
                        // session frame. Keep both credits until native ownership ends.
                        let enclosing = (size_of::<Wrap>() - size_of::<OwnedGraph>())
                            .checked_add(SessionFrame::<'_, Wrap>::allocation_bytes())
                            .ok_or(Error::Rejected(
                                crate::RejectionReason::MechanismExtensions(
                                    crate::MechanismExtensionsRejection::WrapFrameStorageAccounting,
                                ),
                            ))?;
                        let actual = graph
                            .allocated_bytes()?
                            .checked_add(bytes.allocated())
                            .and_then(|n| n.checked_add(enclosing))
                            .and_then(|n| n.checked_add(revocation_bytes))
                            .and_then(|n| n.checked_add(overhead))
                            .and_then(|n| n.checked_add(CompletionStorage::allocation_bytes()))
                            .ok_or(Error::Rejected(
                                crate::RejectionReason::MechanismExtensions(
                                    crate::MechanismExtensionsRejection::WrapStorageAccounting,
                                ),
                            ))?;
                        if actual > required {
                            drop(bytes);
                            drop(revocation);
                            drop(graph);
                            drop(prepaid);
                            required = actual;
                            continue;
                        }
                        prepaid.release(required - actual);
                        let diagnostic_credit =
                            prepaid.split(CompletionStorage::allocation_bytes())?;
                        let diagnostic = CompletionStorage::allocate()?;
                        let revocation = revocation
                            .map(|storage| storage.bind(&mut prepaid))
                            .transpose()?;
                        let prepared = Wrap {
                            mechanism: CK_MECHANISM {
                                mechanism: request.contract.mechanism,
                                pParameter: std::ptr::null_mut(),
                                ulParameterLen: 0,
                            },
                            graph: graph.bind(&mut prepaid)?,
                            bytes: bytes.bind(&mut prepaid)?,
                            length,
                            fixed_prefix,
                            _credit: prepaid.split(enclosing)?,
                        };
                        return Ok((
                            (diagnostic_credit, diagnostic, prepared, revocation),
                            prepaid,
                        ));
                    }
                },
            )?;
        session
            .snapshot
            .check_authentication_unchanged(authentication)?;
        let mutation = match revocation.as_mut() {
            Some(prepared_revocation) => match prepared_revocation.bind(&state)? {
                Some(targets) => Some(targets),
                None => {
                    // Registry growth occurred before exclusive possession. No C
                    // call happened: discard all private storage before replan.
                    drop(state);
                    drop(prepared);
                    drop(diagnostic);
                    drop(diagnostic_credit);
                    continue;
                }
            },
            None => None,
        };
        break (diagnostic_credit, diagnostic, prepared, mutation, state);
    };
    // The public facade retains this credit after every private adapter has
    // returned, separately from the possibly quarantined native frame.
    *diagnostic_root = Some(diagnostic_credit);
    session.entry(&state)?;
    let function = state.native.table.C_WrapKey.ok_or(Error::Unsupported(
        crate::UnsupportedReason::NativeFunction {
            function: "C_WrapKey",
        },
    ))?;
    session.native_object_handle(&state, key)?;
    if let Some(target) = target {
        session.native_object_handle(&state, target)?;
    }
    for source in sources.iter().flatten() {
        session.native_object_handle(&state, source)?;
    }
    let key_handle = session.native_object_handle(&state, key)?;
    let target_handle = target
        .map(|target| session.native_object_handle(&state, target))
        .transpose()?
        .unwrap_or(CK_INVALID_HANDLE);
    // This leaf is never passed to C. Its root-held credit therefore survives
    // frame destruction without being retained with an uncertain native frame.
    let diagnostic = diagnostic.bind("C_WrapKey");
    let mut frame = NativeFrame::session(state.clone(), prepared)?;
    {
        let (returned, body) = frame.session_parts();
        let access = &body.access;
        let data = &mut *body.data;
        let (pointer, length) = data.graph.projection();
        data.mechanism.pParameter = pointer;
        data.mechanism.ulParameterLen = length;
        let expected = (data.mechanism.mechanism, pointer, length);
        session.entry(access)?;
        access.native.record("C_WrapKey")?;
        if let Some(mutation) = mutation {
            drop(mutation.arm());
        }
        returned.arm();
        // SAFETY: exact declared function, stable owned graph and actual output
        // allocation. There is no size probe or automatic second native attempt.
        let rv = returned.observe(
            unsafe {
                function(
                    session.entry.handle,
                    &mut data.mechanism,
                    key_handle,
                    target_handle,
                    data.bytes.as_mut().as_mut_ptr(),
                    &mut data.length,
                )
            },
            &access.native,
        );
        let inspection = session.inspect_native_inputs(access, "C_WrapKey", rv, || {
            data.graph.unchanged()
                && data
                    .fixed_prefix
                    .map_or(true, |prefix| prefix.unchanged(&data.graph))
                && (
                    data.mechanism.mechanism,
                    data.mechanism.pParameter,
                    data.mechanism.ulParameterLen,
                ) == expected
        });
        let completed = inspection.memory_returned();
        let unchanged = !inspection.violated();
        let overflow = rv == CKR_OK && data.length as u128 > capacity as u128;
        let graph_bounds = if rv == CKR_OK && unchanged {
            data.graph.validate_output_bounds()
        } else {
            Ok(())
        };
        if !unchanged || overflow || graph_bounds.is_err() {
            returned.quarantine(&access.native);
        } else if completed {
            returned.terminated();
        } else {
            returned.recoverable();
            session.poison(access);
        }
        let observed_length = if matches!(rv, CKR_OK | CKR_BUFFER_TOO_SMALL) {
            data.length
        } else {
            0
        };
        let native = session
            .check_wrap_return(rv, "C_WrapKey", observed_length, capacity)
            .map_err(|cause| operation::effect(cause, mutates));
        if !unchanged || overflow {
            let cause = if overflow {
                Error::Rejected(crate::RejectionReason::KeyTransport(
                    crate::KeyTransportRejection::WrappedOutputExceedsCapacity,
                ))
            } else {
                Error::Rejected(crate::RejectionReason::MechanismExtensions(
                    crate::MechanismExtensionsRejection::WrapNativeInputChanged,
                ))
            };
            if completed && rv == CKR_BUFFER_TOO_SMALL {
                // Keep the returned scalar as an untrusted observation while
                // retaining the integrity failure and the frame's quarantine.
                return Err(diagnostic.output_failure(
                    rv,
                    observed_length as u64,
                    capacity,
                    cause,
                ));
            }
            return Err(diagnostic.boundary_failure(rv, cause));
        }
        if let Err(cause) = graph_bounds {
            return Err(diagnostic.boundary_failure(rv, cause));
        }
        native?;
        let output = bounds::final_length(data.length, capacity)
            .and_then(|length| data.bytes.set_length(length))
            .and_then(|()| data.graph.finish());
        if let Err(cause) = output {
            returned.quarantine(&access.native);
            return diagnostic.finish(Err(cause));
        }
    }
    let body = match frame.into_inner() {
        Ok(body) => body,
        Err(cause) => return diagnostic.finish(Err(cause)),
    };
    let data = body.data.into_inner();
    diagnostic.finish(session.public_result(
        &state,
        Ok(ExtensionResult {
            bytes: data.bytes,
            native_output_origin: 0,
            parameters: data.graph,
            provenance: request.contract.provenance(),
        }),
    ))
}

// One owned creation path for wrapping and KEM, with direction-specific data.
#[derive(Clone, Copy)]
pub(crate) enum CreationInput<'a> {
    Unwrap(&'a [u8]),
    Decapsulate(&'a [u8]),
    Encapsulate { capacity: usize },
}
impl CreationInput<'_> {
    pub(crate) fn check_function(self, state: &crate::module::State) -> Result<()> {
        let call = match self {
            Self::Unwrap(_) => MutationCall::Unwrap,
            Self::Decapsulate(_) => MutationCall::Decapsulate,
            Self::Encapsulate { .. } => MutationCall::Encapsulate,
        };
        CreationFunction::new(state, call).map(|_| ())
    }

    pub(crate) fn operation(self) -> ExtensionOperation {
        match self {
            Self::Unwrap(_) => ExtensionOperation::UnwrapKey,
            Self::Decapsulate(_) => ExtensionOperation::DecapsulateKey,
            Self::Encapsulate { .. } => ExtensionOperation::EncapsulateKey,
        }
    }
    fn allocation_bytes(self) -> Result<usize> {
        match self {
            Self::Unwrap(bytes) | Self::Decapsulate(bytes) => {
                bounds::ck_length(bytes.len())?;
                bytes.len().checked_mul(2).ok_or(Error::Rejected(
                    crate::RejectionReason::MechanismExtensions(
                        crate::MechanismExtensionsRejection::TransportInputAccounting,
                    ),
                ))
            }
            Self::Encapsulate { capacity } => {
                bounds::ck_length(capacity)?;
                Ok(capacity)
            }
        }
    }
}
enum CreationData {
    Unwrap(InputBytes),
    Decapsulate(InputBytes),
    Encapsulate { bytes: Buffer, length: CK_ULONG },
}
impl CreationData {
    fn call(&self) -> MutationCall {
        match self {
            Self::Unwrap(_) => MutationCall::Unwrap,
            Self::Decapsulate(_) => MutationCall::Decapsulate,
            Self::Encapsulate { .. } => MutationCall::Encapsulate,
        }
    }
    fn unchanged(&self) -> bool {
        match self {
            Self::Unwrap(bytes) | Self::Decapsulate(bytes) => bytes.unchanged(),
            Self::Encapsulate { .. } => true,
        }
    }
    fn output_overflow(&mut self) -> bool {
        match self {
            Self::Encapsulate { bytes, length } => {
                bounds::final_length(*length, bytes.as_mut().len()).is_err()
            }
            _ => false,
        }
    }
    fn finish(&mut self) -> Result<()> {
        if let Self::Encapsulate { bytes, length } = self {
            bounds::final_length(*length, bytes.as_mut().len())?;
            bytes.set_length(*length as usize)?;
        }
        Ok(())
    }
    fn ciphertext(self) -> Option<Buffer> {
        match self {
            Self::Encapsulate { bytes, .. } => Some(bytes),
            _ => None,
        }
    }
}
pub(crate) struct CreationOutput {
    pub(crate) parameters: OwnedGraph,
    pub(crate) ciphertext: Option<Buffer>,
}
enum CreationFunction {
    Unwrap(resolved::UnwrapKey),
    Encapsulate(resolved::EncapsulateKey),
    Decapsulate(resolved::DecapsulateKey),
}
impl CreationFunction {
    fn new(access: &crate::module::State, call: MutationCall) -> Result<Self> {
        let missing = || {
            Error::Unsupported(crate::UnsupportedReason::NativeFunction {
                function: call.function(),
            })
        };
        Ok(match call {
            MutationCall::Unwrap => {
                Self::Unwrap(access.native.table.C_UnwrapKey.ok_or_else(missing)?)
            }
            MutationCall::Encapsulate => Self::Encapsulate(
                access
                    .native
                    .kem
                    .and_then(|f| f.encapsulate)
                    .ok_or_else(missing)?,
            ),
            MutationCall::Decapsulate => Self::Decapsulate(
                access
                    .native
                    .kem
                    .and_then(|f| f.decapsulate)
                    .ok_or_else(missing)?,
            ),
            _ => return Err(missing()),
        })
    }
    unsafe fn dispatch(
        &self,
        session: CK_SESSION_HANDLE,
        call: &mut KeyCreation,
        key: CK_OBJECT_HANDLE,
    ) -> CK_RV {
        // SAFETY: the exact tuple is selected before creating effects. Every
        // pointer targets the stable frame; templates precede ciphertext for KEM.
        unsafe {
            match (self, &mut call.data) {
                (Self::Unwrap(f), CreationData::Unwrap(bytes)) => f(
                    session,
                    &mut call.mechanism,
                    key,
                    bytes.pointer(),
                    bytes.length(),
                    call.template.as_mut_ptr(),
                    call.template.count(),
                    &mut call.handle,
                ),
                (Self::Decapsulate(f), CreationData::Decapsulate(bytes)) => f(
                    session,
                    &mut call.mechanism,
                    key,
                    call.template.as_mut_ptr(),
                    call.template.count(),
                    bytes.pointer(),
                    bytes.length(),
                    &mut call.handle,
                ),
                (Self::Encapsulate(f), CreationData::Encapsulate { bytes, length }) => f(
                    session,
                    &mut call.mechanism,
                    key,
                    call.template.as_mut_ptr(),
                    call.template.count(),
                    bytes.as_mut().as_mut_ptr(),
                    length,
                    &mut call.handle,
                ),
                _ => unreachable!("creation function resolved from owned data before dispatch"),
            }
        }
    }
}

mod preparation;
pub(crate) use preparation::KeyCreationStorage;

pub(crate) struct KeyCreation {
    mechanism: CK_MECHANISM,
    graph: OwnedGraph,
    template: InputTemplate,
    data: CreationData,
    handle: CK_OBJECT_HANDLE,
    mutates: bool,
    _credit: Credit,
}
// SAFETY: parameter graph, template, blob and output handle are all retained
// with their session and creation reservation until native completion is known.
unsafe impl Send for KeyCreation {}
impl KeyCreation {
    /// Stable data plus SessionFrame, excluding separately credited owners.
    fn frame_bytes() -> usize {
        size_of::<Self>() + SessionFrame::<'_, Self>::allocation_bytes()
            - size_of::<OwnedGraph>()
            - size_of::<InputTemplate>()
    }
    pub(crate) fn allocation_bytes(
        request: &super::graph::recipe::Request<'_>,
        input: CreationInput<'_>,
    ) -> Result<usize> {
        let bytes = input.allocation_bytes()?;
        OwnedGraph::recipe_bytes(request.parameters.recipe())?
            .checked_add(Self::frame_bytes())
            .and_then(|n| n.checked_add(bytes))
            .ok_or(Error::Rejected(
                crate::RejectionReason::MechanismExtensions(
                    crate::MechanismExtensionsRejection::KeyTransportStorageAccounting,
                ),
            ))
    }
    pub(crate) fn execute_resident(
        self,
        session: &Session,
        access: &SessionAccess<'_>,
        diagnostic: crate::error::CompletionStorage,
        mut creation: crate::managed::PreparedCreation,
        key: CK_OBJECT_HANDLE,
        aliases: Option<RevocationTargets>,
        mutation: Option<RevocationTargets>,
        secondary_aliases: [Option<(CK_OBJECT_HANDLE, RevocationTargets)>; 4],
        cleanup: &mut crate::error::CleanupStorage,
    ) -> Result<(CompletedGeneration<1>, Result<CreationOutput>)> {
        self.execute_prepared(
            session,
            access,
            diagnostic,
            || creation.begin(),
            key,
            aliases,
            mutation,
            secondary_aliases,
            cleanup,
        )
    }
    fn execute_prepared(
        self,
        session: &Session,
        access: &SessionAccess<'_>,
        diagnostic: crate::error::CompletionStorage,
        begin: impl FnOnce() -> Result<crate::managed::CreationTicket>,
        key: CK_OBJECT_HANDLE,
        aliases: Option<RevocationTargets>,
        mutation: Option<RevocationTargets>,
        secondary_aliases: [Option<(CK_OBJECT_HANDLE, RevocationTargets)>; 4],
        cleanup: &mut crate::error::CleanupStorage,
    ) -> Result<(CompletedGeneration<1>, Result<CreationOutput>)> {
        let call = self.data.call();
        let function = CreationFunction::new(access, call)?;
        let diagnostic = diagnostic.bind(call.function());
        let mut frame = NativeFrame::session(access.clone(), self)?;
        // The frame allocation must not leave a pending creation on refusal.
        let creation = begin()?;
        let (handle, output_status) = {
            let (returned, body) = frame.session_parts();
            let state = &body.access;
            let data = &mut *body.data;
            let (pointer, length) = data.graph.projection();
            data.mechanism.pParameter = pointer;
            data.mechanism.ulParameterLen = length;
            let expected = (data.mechanism.mechanism, pointer, length);
            creation.prepare_dispatch(state, || {
                session.entry(state)?;
                state.native.record(call.function())
            })?;
            if let Some(mutation) = mutation {
                drop(mutation.arm());
            }
            returned.arm();
            // SAFETY: stable complete frame and exact native ABI; source key and
            // destination reservation stay live through known and uncertain returns.
            let rv = returned.observe(
                unsafe { function.dispatch(session.entry.handle, data, key) },
                &state.native,
            );
            let inspection = session.inspect_native_inputs(state, call.function(), rv, || {
                data.graph.unchanged() & data.data.unchanged() & data.template.unchanged()
                    && (
                        data.mechanism.mechanism,
                        data.mechanism.pParameter,
                        data.mechanism.ulParameterLen,
                    ) == expected
            });
            let completed = inspection.memory_returned();
            let unchanged = !inspection.violated();
            let overflow = rv == CKR_OK && data.data.output_overflow();
            let graph_bounds = if rv == CKR_OK && unchanged {
                data.graph.validate_output_bounds()
            } else {
                Ok(())
            };
            if !unchanged || overflow || graph_bounds.is_err() {
                returned.quarantine(&state.native);
            } else if completed {
                returned.terminated();
            } else {
                returned.recoverable();
                session.poison(state);
            }
            let native = inspection
                .check(!call.definite_object_refusal(rv))
                .map_err(|cause| operation::effect(cause, data.mutates));
            if native.is_err()
                && inspection.no_objects(
                    crate::native_return::protocol::CreationContract::Function(call),
                )
            {
                creation.refused(state, call, rv);
            }
            if completed && rv == CKR_BUFFER_TOO_SMALL {
                if let CreationData::Encapsulate { bytes, length } = &mut data.data {
                    // Preserve the returned scalar even when an independent
                    // input-integrity failure quarantines the native frame.
                    let local = (!unchanged).then(|| {
                        Error::Rejected(crate::RejectionReason::MechanismExtensions(
                            crate::MechanismExtensionsRejection::KeyTransportNativeInputOrOutputCapacityViolation,
                        ))
                    });
                    return Err(crate::error::encapsulation::capacity_failure(
                        *length,
                        bytes.as_mut().len(),
                        local,
                        diagnostic,
                        cleanup,
                    ));
                }
            }
            if !unchanged || overflow {
                return Err(cleanup.mark_remaining(diagnostic.boundary_failure(rv,
                    Error::Rejected(
                        crate::RejectionReason::MechanismExtensions(crate::MechanismExtensionsRejection::KeyTransportNativeInputOrOutputCapacityViolation),
                    ),
                )));
            }
            if let Err(cause) = graph_bounds {
                return Err(cleanup.mark_remaining(diagnostic.boundary_failure(rv, cause)));
            }
            native?;
            if data.handle == key && key != CK_INVALID_HANDLE {
                if let Some(aliases) = aliases {
                    drop(aliases.arm());
                }
                return diagnostic.finish(Err(cleanup.mark_remaining(Error::Rejected(
                    crate::RejectionReason::MechanismExtensions(
                        crate::MechanismExtensionsRejection::KeyTransportReturnedSourceHandle,
                    ),
                ))));
            }
            for (source, aliases) in secondary_aliases.into_iter().flatten() {
                if data.handle == source {
                    drop(aliases.arm());
                    return diagnostic.finish(Err(cleanup.mark_remaining(Error::Rejected(
                        crate::RejectionReason::MechanismExtensions(crate::MechanismExtensionsRejection::KeyTransportReturnedAuxiliarySourceHandle),
                    ))));
                }
            }
            if let Err(cause) = creation
                .handles_prepared(state, &[data.handle], |cause| cleanup.mark_remaining(cause))
            {
                return diagnostic.finish(Err(cause));
            }
            // A bounded parameter-output error does not hide the registered
            // object. The facade observes this error inside its cleanup boundary.
            (
                data.handle,
                data.data.finish().and_then(|()| data.graph.finish()),
            )
        };
        let graph = match frame.into_inner() {
            Ok(body) => output_status.map(|()| {
                let data = body.data.into_inner();
                CreationOutput {
                    parameters: data.graph,
                    ciphertext: data.data.ciphertext(),
                }
            }),
            Err(cause) => Err(cause),
        };
        Ok((
            CompletedGeneration::registered([handle], diagnostic, creation),
            graph,
        ))
    }
}
