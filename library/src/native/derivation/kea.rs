// SPDX-License-Identifier: Apache-2.0
//! Owned KEA input/output graph and explicit native creation effect.
use super::*;
use crate::{managed::Reservation, KeaMechanism, KeaRandoms, KeaRequest};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Phase {
    SenderRandom,
    ReceiverRandom,
    SenderEmail,
    ReceiverEmail,
    SenderFull,
    ReceiverFull,
}
impl Phase {
    pub(crate) fn from_request(request: &KeaRequest<'_>) -> Self {
        // The value, not the encoded width, chooses the normative KEA phase.
        let significant = request.random_b.iter().position(|v| *v != 0);
        match (request.sender, significant) {
            (true, None) => Self::SenderRandom,
            (false, None) => Self::ReceiverRandom,
            (true, Some(i)) if i + 1 == request.random_b.len() && request.random_b[i] == 1 => {
                Self::SenderEmail
            }
            (false, Some(i)) if i + 1 == request.random_b.len() && request.random_b[i] == 1 => {
                Self::ReceiverEmail
            }
            (true, Some(_)) => Self::SenderFull,
            (false, Some(_)) => Self::ReceiverFull,
        }
    }
    pub(crate) fn creates(self) -> bool {
        !matches!(self, Self::SenderRandom | Self::ReceiverRandom)
    }
    fn writes_a(self) -> bool {
        matches!(
            self,
            Self::SenderRandom | Self::SenderEmail | Self::SenderFull
        )
    }
    fn writes_b(self) -> bool {
        self == Self::ReceiverRandom
    }
    fn sender(self) -> CK_BBOOL {
        CK_BBOOL::from(self.writes_a())
    }
}
pub(crate) struct Kea {
    mechanism: CK_MECHANISM,
    kind: KeaMechanism,
    phase: Phase,
    raw: CK_KEA_DERIVE_PARAMS,
    a: InputBytes,
    b: InputBytes,
    peer: InputBytes,
    template: InputTemplate,
    handle: CK_OBJECT_HANDLE,
    _credit: Credit,
}
// SAFETY: the stable frame owns both mutable randoms, immutable peer bytes,
// native descriptors/template and the optional key output slot.
unsafe impl Send for Kea {}
pub(crate) struct KeaStorage {
    a: InputBytesStorage,
    b: InputBytesStorage,
    peer: InputBytesStorage,
}
impl KeaStorage {
    pub(crate) fn allocate(request: &KeaRequest<'_>) -> Result<Self> {
        Kea::allocation_bytes(request)?;
        Ok(Self {
            a: InputBytesStorage::allocate(request.random_a.len())?,
            b: InputBytesStorage::allocate(request.random_b.len())?,
            peer: InputBytesStorage::allocate(request.peer_public.len())?,
        })
    }
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        let a = self.a.allocated_bytes()?;
        let b = self.b.allocated_bytes()?;
        let peer = self.peer.allocated_bytes()?;
        Kea::frame_bytes()
            .checked_add(a)
            .and_then(|n| n.checked_add(b))
            .and_then(|n| n.checked_add(peer))
            .ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::KeaParameterAccounting,
            )))
    }
    pub(crate) fn bind(
        self,
        request: &KeaRequest<'_>,
        template: InputTemplate,
        credit: &mut Credit,
    ) -> Result<Kea> {
        Kea::from_storage(request, template, credit, self)
    }
}
impl Kea {
    /// Retain credit for CallData and SessionFrame outside the owned template.
    fn frame_bytes() -> usize {
        size_of::<Self>() + crate::native::frame::SessionFrame::<'_, Self>::allocation_bytes()
            - size_of::<InputTemplate>()
    }

    pub(crate) fn allocation_bytes(request: &KeaRequest<'_>) -> Result<usize> {
        if request.random_a.len() != request.random_b.len() {
            return Err(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::KeaSharedRandomLength,
            )));
        }
        let mut bytes = Self::frame_bytes();
        for len in [
            request.random_a.len(),
            request.random_b.len(),
            request.peer_public.len(),
        ] {
            bounds::ck_length(len)?;
            bytes = len
                .checked_mul(2)
                .and_then(|n| bytes.checked_add(n))
                .ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
                    crate::NativeDerivationRejection::KeaParameterAccounting,
                )))?;
        }
        Ok(bytes)
    }

    fn from_storage(
        request: &KeaRequest<'_>,
        template: InputTemplate,
        credit: &mut Credit,
        storage: KeaStorage,
    ) -> Result<Self> {
        Self::allocation_bytes(request)?;
        Ok(Self {
            mechanism: CK_MECHANISM {
                mechanism: request.mechanism.native(),
                pParameter: std::ptr::null_mut(),
                ulParameterLen: size_of::<CK_KEA_DERIVE_PARAMS>() as CK_ULONG,
            },
            kind: request.mechanism,
            phase: Phase::from_request(request),
            raw: CK_KEA_DERIVE_PARAMS {
                isSender: CK_BBOOL::from(request.sender),
                ulRandomLen: bounds::ck_length(request.random_a.len())?,
                pRandomA: std::ptr::null_mut(),
                pRandomB: std::ptr::null_mut(),
                ulPublicDataLen: bounds::ck_length(request.peer_public.len())?,
                pPublicData: std::ptr::null_mut(),
            },
            a: storage.a.bind(request.random_a, credit)?,
            b: storage.b.bind(request.random_b, credit)?,
            peer: storage.peer.bind(request.peer_public, credit)?,
            template,
            handle: CK_INVALID_HANDLE,
            _credit: credit.split(Self::frame_bytes())?,
        })
    }
    fn bind(&mut self) {
        self.raw.pRandomA = self.a.pointer();
        self.raw.pRandomB = self.b.pointer();
        self.raw.pPublicData = self.peer.pointer();
        self.mechanism.pParameter = (&mut self.raw as *mut CK_KEA_DERIVE_PARAMS).cast();
    }
    fn unchanged(&mut self) -> bool {
        self.mechanism.mechanism == self.kind.native()
            && self.mechanism.pParameter
                == (&self.raw as *const CK_KEA_DERIVE_PARAMS).cast_mut().cast()
            && self.mechanism.ulParameterLen == size_of::<CK_KEA_DERIVE_PARAMS>() as CK_ULONG
            && self.raw.isSender == self.phase.sender()
            && self.raw.ulRandomLen == self.a.length()
            && self.raw.pRandomA == self.a.expected_pointer()
            && self.raw.pRandomB == self.b.expected_pointer()
            && self.raw.pPublicData == self.peer.expected_pointer()
            && self.raw.ulPublicDataLen == self.peer.length()
            && (self.phase.writes_a() || self.a.unchanged())
            && (self.phase.writes_b() || self.b.unchanged())
            && self.peer.unchanged()
            && self.template.unchanged()
    }
    pub(crate) fn execute(
        self,
        session: &Session,
        access: &SessionAccess<'_>,
        diagnostic: crate::error::CompletionStorage,
        reservation: Option<&Reservation>,
        base: CK_OBJECT_HANDLE,
        aliases: RevocationTargets,
        cleanup: Option<&mut crate::error::CleanupStorage>,
    ) -> Result<Completed> {
        self.execute_prepared(
            session,
            access,
            diagnostic,
            reservation.is_some(),
            || reservation.map(|r| r.creation(session)).transpose(),
            base,
            aliases,
            cleanup,
        )
    }
    pub(crate) fn execute_resident(
        self,
        session: &Session,
        access: &SessionAccess<'_>,
        diagnostic: crate::error::CompletionStorage,
        mut creation: crate::managed::PreparedCreation,
        base: CK_OBJECT_HANDLE,
        aliases: RevocationTargets,
        cleanup: &mut crate::error::CleanupStorage,
    ) -> Result<Completed> {
        self.execute_prepared(
            session,
            access,
            diagnostic,
            true,
            || creation.begin().map(Some),
            base,
            aliases,
            Some(cleanup),
        )
    }
    fn execute_prepared(
        self,
        session: &Session,
        access: &SessionAccess<'_>,
        diagnostic: crate::error::CompletionStorage,
        has_creation: bool,
        begin: impl FnOnce() -> Result<Option<crate::managed::CreationTicket>>,
        base: CK_OBJECT_HANDLE,
        aliases: RevocationTargets,
        cleanup: Option<&mut crate::error::CleanupStorage>,
    ) -> Result<Completed> {
        let call = MutationCall::Derive;
        let native = access.native.table.C_DeriveKey.ok_or(Error::Rejected(
            crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::CDeriveKeyUnavailable,
            ),
        ))?;
        let creating = self.phase.creates();
        if creating != has_creation {
            return Err(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::KeaCreationScope,
            )));
        }
        if creating && cleanup.is_none() {
            return Err(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::KeaCreationDiagnosticsAbsent,
            )));
        }
        let diagnostic = diagnostic.bind(call.function());
        let mut frame = NativeFrame::session(access.clone(), self)?;
        let creation = begin()?;
        let (returned, body) = frame.session_parts();
        let state = &body.access;
        let data = &mut *body.data;
        data.bind();
        let handle = if creating {
            &mut data.handle as *mut CK_OBJECT_HANDLE
        } else {
            std::ptr::null_mut()
        };
        let prepare = || {
            session.entry(state)?;
            if creating {
                state.native.record(call.function())
            } else {
                state.native.record_derivation_without_objects()
            }
        };
        if let Some(creation) = &creation {
            creation.prepare_dispatch(state, prepare)?;
        } else {
            prepare()?;
        }
        // Random-only KEA phases still enter the creation family. Keep their
        // prior close coordination, without changing the no-object contract.
        session
            .entry
            .creation_attempted
            .store(true, std::sync::atomic::Ordering::Release);
        returned.arm();
        // SAFETY: owned buffers have the shared checked length. Random-only
        // phases supply no output-handle pointer, as no key is requested.
        let rv = returned.observe(
            unsafe {
                native(
                    session.entry.handle,
                    &mut data.mechanism,
                    base,
                    data.template.as_mut_ptr(),
                    data.template.count(),
                    handle,
                )
            },
            &state.native,
        );
        let inspection =
            session.inspect_native_inputs(state, call.function(), rv, || data.unchanged());
        let known = inspection.memory_returned();
        let unchanged = !inspection.violated();
        if !unchanged {
            returned.quarantine(&state.native);
        } else if known {
            returned.terminated();
        } else {
            returned.recoverable();
            session.poison(state);
        }
        let result = inspection.check(!call.definite_object_refusal(rv));
        let result = if !creating
            && inspection.no_objects(crate::native_return::protocol::CreationContract::NoObjects)
        {
            crate::error::check(rv, call.function(), false)
        } else {
            result
        };
        if result.is_err()
            && inspection.no_objects(crate::native_return::protocol::CreationContract::Function(
                call,
            ))
        {
            if let Some(creation) = &creation {
                creation.refused(state, call, rv);
            }
        }
        if !unchanged {
            let cause = diagnostic.boundary_failure(
                rv,
                Error::Rejected(crate::RejectionReason::NativeDerivation(
                    crate::NativeDerivationRejection::KeaNativeInputMutation,
                )),
            );
            return Err(if creating {
                // The creation route checked its cleanup owner before dispatch.
                match cleanup {
                    Some(storage) => storage.mark_remaining(cause),
                    None => cause,
                }
            } else {
                cause
            });
        }
        result?;
        let effect = match creation {
            None => Effect::Random(diagnostic),
            Some(creation) => {
                // The two callers bind begin to the same has_creation value:
                // a reservation maps to Some(ticket), resident creation is always
                // Some. Before C, creating == has_creation and cleanup is checked.
                // No intervening path can consume this exclusive diagnostic.
                let cleanup = cleanup.expect("creation diagnostics checked before dispatch");
                if data.handle == base {
                    drop(aliases.arm());
                    return diagnostic.finish(Err(cleanup.mark_remaining(Error::Rejected(
                        crate::RejectionReason::NativeDerivation(
                            crate::NativeDerivationRejection::KeaOutputAliasesSource,
                        ),
                    ))));
                }
                if let Err(cause) = creation
                    .handles_prepared(state, &[data.handle], |cause| cleanup.mark_remaining(cause))
                {
                    return diagnostic.finish(Err(cause));
                }
                Effect::Key(CompletedGeneration::registered(
                    [data.handle],
                    diagnostic,
                    creation,
                ))
            }
        };
        let randoms = KeaRandoms {
            a: data.a.value.take(),
            b: data.b.value.take(),
        };
        Ok(Completed { effect, randoms })
    }
}
enum Effect {
    Random(CompletionDiagnostic),
    Key(CompletedGeneration<1>),
}
pub(crate) struct Completed {
    effect: Effect,
    pub(crate) randoms: KeaRandoms,
}
impl Completed {
    pub(crate) fn into_created_parts(
        self,
    ) -> Result<(
        CK_OBJECT_HANDLE,
        KeaRandoms,
        crate::managed::CreationTicket,
        CompletionDiagnostic,
    )> {
        let Effect::Key(effect) = self.effect else {
            return Err(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::KeaCreationPhase,
            )));
        };
        let ([handle], creation, diagnostic) = effect.into_parts();
        Ok((handle, self.randoms, creation, diagnostic))
    }
    pub(crate) fn handle(&self) -> Option<CK_OBJECT_HANDLE> {
        match &self.effect {
            Effect::Random(_) => None,
            Effect::Key(v) => Some(v.handles()[0]),
        }
    }
    pub(crate) fn into_parts(self) -> (Completion, KeaRandoms) {
        (Completion(self.effect), self.randoms)
    }
}
pub(crate) struct Completion(Effect);
impl Completion {
    pub(crate) fn finish<T>(self, result: Result<T>) -> Result<T> {
        match self.0 {
            Effect::Random(v) => v.finish(result),
            Effect::Key(v) => v.finish(result),
        }
    }
}
