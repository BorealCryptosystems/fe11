// SPDX-License-Identifier: Apache-2.0
//! Explicit input injection into an initialized digest; no implicit replay.
use super::{DigestSelection, Step};
use crate::advanced::{
    poll, progress, AdvancedSession, AdvancedSessionMode, MessageRoute, NativeActivity,
    OperationBody, OperationPacing, OperationProgress, OperationTicket, ValidationCaptureMode,
};
use crate::native::frame::NativeFrame;
use crate::{
    bounds,
    error::check,
    module::State,
    symmetric::memory::{Buffer, ControlledReservation, Credit, UnboundBuffer},
    Error, Result, Session,
};
use fe11_sys::{CK_OBJECT_HANDLE, CK_ULONG};
use std::sync::{atomic::Ordering, Arc};


enum Input<'a> {
    Bytes(&'a [u8], crate::InputLimits),
    Key(&'a crate::NativeObjectRef),
}
impl Input<'_> {
    fn checked_bytes(&self, session: &Session) -> Result<usize> {
        match self {
            Self::Bytes(bytes, limits) => {
                limits.validate(session.inner.crypto_options.limits, &[bytes])?;
                bounds::ck_length(bytes.len())?;
                Ok(bytes.len())
            }
            Self::Key(_) => Ok(0),
        }
    }
}

enum OwnedInput {
    Bytes {
        input: Buffer,
        expected: Buffer,
        length: CK_ULONG,
    },
    Key {
        handle: CK_OBJECT_HANDLE,
        _permit: crate::registry::ReadPermit,
        _identity: Arc<crate::managed::NativeIdentity>,
    },
}
struct InputFrame {
    input: OwnedInput,
    _credit: Credit,
}
impl InputFrame {
    fn unchanged(&self) -> bool {
        match &self.input {
            OwnedInput::Bytes {
                input, expected, ..
            } => input.as_slice() == expected.as_slice(),
            OwnedInput::Key { .. } => true,
        }
    }
}

// Candidates have no native pointers. Byte copies are populated only after the
// entire aggregate has exact capacity credit; a key keeps caller-owned identity
// separate from its prepaid attribution slot and final native read permission.
enum PreparedInput {
    Bytes(InputFrame),
    Key {
        reader: crate::registry::PreparedReader,
        credit: Credit,
    },
}
impl PreparedInput {
    fn prepare(
        session: &Session,
        budget: &Arc<crate::symmetric::memory::Budget>,
        request: &Input<'_>,
        admission: &crate::ResourceAdmission,
        mut before: impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        let size = request.checked_bytes(session)?;
        let metadata = std::mem::size_of::<InputFrame>()
            + crate::native::frame::SessionFrame::<'_, InputFrame>::allocation_bytes();
        let mut required = size
            .checked_mul(2)
            .and_then(|n| n.checked_add(metadata))
            .ok_or(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DigestInjectionStorageSize,
            )))?;
        loop {
            let mut prepaid = match budget
                .reserve_controlled_retaining::<std::convert::Infallible>(
                    required,
                    crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
                    admission,
                    || {
                        before()?;
                        Ok(None)
                    },
                    || Ok(None),
                )? {
                ControlledReservation::Acquired(credit) => credit,
                ControlledReservation::Redirect(never) => match never {},
            };
            match request {
                Input::Bytes(bytes, _) => {
                    let input = UnboundBuffer::allocate(size)?;
                    let expected = UnboundBuffer::allocate(size)?;
                    let actual = input
                        .allocated()
                        .checked_add(expected.allocated())
                        .and_then(|n| n.checked_add(metadata))
                        .ok_or(Error::Rejected(crate::RejectionReason::DigestContinuation(
                            crate::DigestContinuationRejection::DigestInjectionStorageSize,
                        )))?;
                    if actual > required {
                        drop(input);
                        drop(expected);
                        drop(prepaid);
                        required = actual;
                        continue;
                    }
                    prepaid.release(required - actual);
                    let mut input = input.bind(&mut prepaid)?;
                    let mut expected = expected.bind(&mut prepaid)?;
                    input.as_mut().copy_from_slice(bytes);
                    expected.as_mut().copy_from_slice(bytes);
                    return Ok(Self::Bytes(InputFrame {
                        input: OwnedInput::Bytes {
                            input,
                            expected,
                            length: bounds::ck_length(size)?,
                        },
                        _credit: prepaid,
                    }));
                }
                Input::Key(key) => {
                    let reader = key.identity.activity()?.prepare_reader_checked(
                        session.uid,
                        admission,
                        &mut before,
                    )?;
                    return Ok(Self::Key {
                        reader,
                        credit: prepaid,
                    });
                }
            }
        }
    }

    fn read_permit(&self, retained: &mut Option<crate::registry::ReadPermit>) -> Result<()> {
        match self {
            Self::Bytes(_) => Ok(()),
            Self::Key { reader, .. } => {
                reader.acquire_into(&crate::admission_wait::current(), retained)
            }
        }
    }

    fn wait_available(
        &self,
        admission: &crate::ResourceAdmission,
        before: impl FnMut() -> Result<()>,
    ) -> Result<()> {
        match self {
            Self::Bytes(_) => Ok(()),
            Self::Key { reader, .. } => reader.wait_available_checked(admission, before),
        }
    }

    fn bind_retained(
        prepared: &mut Option<Self>,
        session: &Session,
        access: &State,
        request: &Input<'_>,
        permit: &mut Option<crate::registry::ReadPermit>,
        retired_reader: &mut Option<crate::registry::PreparedReader>,
    ) -> Result<InputFrame> {
        // All checks borrow the caller's retained slots. No error can consume
        // an admitted permit or preparation while the caller owns access.
        let key = match (prepared.as_ref(), request, permit.as_ref()) {
            (Some(Self::Bytes(_)), Input::Bytes(..), None) => None,
            (Some(Self::Key { .. }), Input::Key(key), Some(_)) => {
                if retired_reader.is_some() {
                    return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                        crate::DigestContinuationRejection::DigestReaderRetirementOccupied,
                    )));
                }
                Some((
                    session.native_object_handle(access, key)?,
                    key.identity.clone(),
                ))
            }
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::DigestInputPreparation,
                )))
            }
        };
        // Only infallible transfers remain. Keep attribution outside the
        // guards even after its permit has moved into the native input.
        Ok(
            match prepared.take().expect("validated digest preparation") {
                Self::Bytes(frame) => frame,
                Self::Key { reader, credit } => {
                    *retired_reader = Some(reader);
                    let (handle, identity) = key.expect("validated key input");
                    InputFrame {
                        input: OwnedInput::Key {
                            handle,
                            _permit: permit.take().expect("validated key permit"),
                            _identity: identity,
                        },
                        _credit: credit,
                    }
                }
            },
        )
    }
}

fn synchronous(session: &Session) -> Result<()> {
    if session.entry.mode != AdvancedSessionMode::Synchronous {
        return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
            crate::DigestContinuationRejection::CallerDrivenDigestRequiresASynchronousSession,
        )));
    }
    Ok(())
}

impl Session {
    /// Initialize a caller-driven native digest without submitting Final.
    /// Interleave digest_update and digest_key, then call finish_digest. The
    /// ticket reserves this session until completion or explicit session close.
    pub fn begin_digest(&self, algorithm: crate::HashAlgorithm) -> Result<OperationTicket> {
        let mut retired_owner = None;
        synchronous(self)?;
        super::start_open(
            self,
            &[],
            crate::InputLimits {
                maximum_parts: self.inner.crypto_options.limits.maximum_parts,
                maximum_total_bytes: self.inner.crypto_options.limits.maximum_total_bytes,
            },
            DigestSelection::Typed(algorithm),
            false,
            false,
            &mut 1,
            &mut retired_owner,
        )
    }
    /// Append bytes to an initialized digest. Limits apply to this call.
    /// No key bytes are read and no refused input is automatically replayed.
    pub fn digest_update(
        &self,
        ticket: &mut OperationTicket,
        bytes: &[u8],
        limits: crate::InputLimits,
    ) -> Result<()> {
        let mut retired_owner = None;
        let mut diagnostics = None;
        inject(
            self,
            ticket,
            Input::Bytes(bytes, limits),
            &mut diagnostics,
            &mut retired_owner,
        )
    }
    /// Append a secret key's native value to the initialized digest, without
    /// exporting CKA_VALUE. The module decides whether the key is digestible.
    /// Ordinary key refusals preserve the digest; this method never substitutes
    /// another key, retries, or finalizes it. Native errors remain identifiable.
    pub fn digest_key(
        &self,
        ticket: &mut OperationTicket,
        key: &crate::NativeObjectRef,
    ) -> Result<()> {
        let mut retired_owner = None;
        let mut diagnostics = None;
        inject(
            self,
            ticket,
            Input::Key(key),
            &mut diagnostics,
            &mut retired_owner,
        )
    }
    /// Complete the native digest once and consume its ticket on publication.
    /// An uncertain native return retains ownership and is never retried here.
    pub fn finish_digest(&self, ticket: &mut OperationTicket) -> Result<crate::PreparedDigest> {
        let mut retired_owner = None;
        match finish(self, ticket, ResultContract::Prehash, &mut retired_owner)? {
            OperationProgress::Digest(digest) => Ok(digest),
            _ => Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::CallerDrivenDigestResultOwner,
            ))),
        }
    }
}
impl AdvancedSession {
    /// Explicitly close a caller-driven typed digest and publish its result.
    /// Polling while the input is open never implies end of input.
    pub fn finish_digest(&self, ticket: &mut OperationTicket) -> Result<OperationProgress> {
        let mut retired_owner = None;
        finish(
            &self.session,
            ticket,
            ResultContract::Prehash,
            &mut retired_owner,
        )
    }

    /// Explicitly close a caller-driven native digest, including GOST, and
    /// publish its native-width result through the same operation owner.
    pub fn finish_native_digest(&self, ticket: &mut OperationTicket) -> Result<OperationProgress> {
        let mut retired_owner = None;
        finish(
            &self.session,
            ticket,
            ResultContract::Native,
            &mut retired_owner,
        )
    }

    /// Initialize a digest and return before Final, independently of pacing.
    /// Interleave digest_update/digest_key, then explicitly finish the digest.
    /// This caller-driven interface uses a synchronous native session.
    pub fn begin_digest(&self, algorithm: crate::HashAlgorithm) -> Result<OperationTicket> {
        let mut retired_owner = None;
        synchronous(&self.session)?;
        let capture = self.validation_capture == ValidationCaptureMode::Capture;
        super::start_open(
            &self.session,
            &[],
            crate::InputLimits {
                maximum_parts: self.session.inner.crypto_options.limits.maximum_parts,
                maximum_total_bytes: self.session.inner.crypto_options.limits.maximum_total_bytes,
            },
            DigestSelection::Typed(algorithm),
            false,
            capture,
            &mut 1,
            &mut retired_owner,
        )
    }
    /// Inject one update between planned digest steps, without advancing them.
    /// The explicit limits bound this call; native refusals are not replayed.
    pub fn digest_update(
        &self,
        ticket: &mut OperationTicket,
        bytes: &[u8],
        limits: crate::InputLimits,
    ) -> Result<()> {
        let mut retired_owner = None;
        let mut diagnostics = None;
        inject(
            &self.session,
            ticket,
            Input::Bytes(bytes, limits),
            &mut diagnostics,
            &mut retired_owner,
        )
    }
    /// Digest an admitted key through C_DigestKey, without reading its value.
    /// Ordinary key refusals leave the digest available to its caller. No key
    /// input is replayed when the opaque digest state is saved or restored.
    pub fn digest_key(
        &self,
        ticket: &mut OperationTicket,
        key: &crate::NativeObjectRef,
    ) -> Result<()> {
        let mut retired_owner = None;
        let mut diagnostics = None;
        inject(
            &self.session,
            ticket,
            Input::Key(key),
            &mut diagnostics,
            &mut retired_owner,
        )
    }
}

// Check the result shape before any native call or ticket consumption. This
// prevents a caller from accidentally discarding another digest API's result.
#[derive(Clone, Copy)]
enum ResultContract {
    Prehash,
    Native,
    Extension,
}
impl ResultContract {
    fn matches(self, selection: DigestSelection) -> bool {
        matches!(
            (self, selection),
            (Self::Prehash, DigestSelection::Typed(_))
                | (Self::Extension, DigestSelection::Extension { .. })
                | (
                    Self::Native,
                    DigestSelection::Native(_)
                        | DigestSelection::NativeSingle(_)
                        | DigestSelection::GostOid(_)
                )
        )
    }
}
fn finish(
    session: &Session,
    ticket: &mut OperationTicket,
    contract: ResultContract,
    retired_owner: &mut Option<Arc<crate::advanced::ledger::OperationCell>>,
) -> Result<OperationProgress> {
    synchronous(session)?;
    if !Arc::ptr_eq(&ticket.owner, &session.inner) || ticket.uid != session.uid || ticket.id == 0 {
        return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::ForeignOrConsumedDigestTicket,
        )));
    }
    let mut released = crate::advanced::poll::ReleasedInputs::default();
    let access = session.advanced_access()?;
    if session.entry.advanced_progress.retired(ticket.id)? {
        ticket.id = 0;
        return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::ForeignOrConsumedDigestTicket,
        )));
    }
    {
        let held = access.operations.get(session.uid)?;
        let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
        if operation.id != ticket.id {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::StaleDigestTicket,
            )));
        }
        operation.check_control_access(&session.entry)?;
        if operation.cancellation.is_withdrawn()
            || operation.cancel.is_submitted()
            || operation.state_io().is_some()
            || operation.transfer.as_ref().is_some()
            || operation.joined.is_some()
            || operation.continuation_status.is_frozen()
            || operation.validation_pending()
        {
            return Err(Error::Busy(crate::BusyReason::DigestContinuation(
                crate::DigestContinuationBusy::DigestControlInProgress,
            )));
        }
        match &mut operation.body {
            OperationBody::Digest(body)
                if contract.matches(body.frame.selection) && !body.validation_requested =>
            {
                body.input.close();
            }
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::DigestResultContractMismatch,
                )))
            }
        }
    }

    let result = poll::poll_with_access(
        session,
        ticket,
        &access,
        OperationPacing::Eager,
        &mut released,
    );
    *retired_owner = released.take_owner();
    result
}

impl Session {
    /// Start a native digest with a declared output bound without finalizing it. Use the same
    /// digest_update/digest_key methods as begin_digest, then finish_native_digest.
    /// The module decides algorithm support; no software fallback occurs.
    pub fn begin_native_digest(
        &self,
        algorithm: crate::NativeDigestAlgorithm,
    ) -> Result<OperationTicket> {
        let mut retired_owner = None;
        synchronous(self)?;
        super::start_open(
            self,
            &[],
            crate::InputLimits {
                maximum_parts: self.inner.crypto_options.limits.maximum_parts,
                maximum_total_bytes: self.inner.crypto_options.limits.maximum_total_bytes,
            },
            DigestSelection::Native(algorithm),
            false,
            false,
            &mut 1,
            &mut retired_owner,
        )
    }

    /// Hash the supplied fragments through the shared native digest owner.
    /// This does not create provenance for a signature prehash API.
    pub fn digest_native(
        &self,
        algorithm: crate::NativeDigestAlgorithm,
        parts: &[&[u8]],
        limits: crate::InputLimits,
    ) -> Result<crate::NativeDigest> {
        let mut diagnostic = None;
        let mut retired_owner = None;
        synchronous(self)?;
        super::batch::native(
            self,
            parts,
            limits,
            DigestSelection::Native(algorithm),
            None,
            &mut retired_owner,
            &mut diagnostic,
        )
    }

    /// Finalize and publish the native result once. A different digest result
    /// contract is rejected before a native call or ticket consumption.
    pub fn finish_native_digest(
        &self,
        ticket: &mut OperationTicket,
    ) -> Result<crate::NativeDigest> {
        let mut retired_owner = None;
        match finish(self, ticket, ResultContract::Native, &mut retired_owner)? {
            OperationProgress::NativeDigest(digest) => Ok(digest),
            _ => Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::NativeDigestResultOwner,
            ))),
        }
    }
}

impl AdvancedSession {
    /// Start a caller-driven native digest and return immediately after
    /// Init. digest_update/digest_key and poll share the ordinary digest owner.
    pub fn begin_native_digest(
        &self,
        algorithm: crate::NativeDigestAlgorithm,
    ) -> Result<OperationTicket> {
        let mut retired_owner = None;
        synchronous(&self.session)?;
        let capture = self.validation_capture == ValidationCaptureMode::Capture;
        super::start_open(
            &self.session,
            &[],
            crate::InputLimits {
                maximum_parts: self.session.inner.crypto_options.limits.maximum_parts,
                maximum_total_bytes: self.session.inner.crypto_options.limits.maximum_total_bytes,
            },
            DigestSelection::Native(algorithm),
            false,
            capture,
            &mut 1,
            &mut retired_owner,
        )
    }

    /// Submit a native digest with a declared output bound using this session's pacing.
    /// Poll publishes NativeDigest once; the exact mechanism survives capture
    /// and restoration without another Init or replay of a digested key.
    pub fn digest_native(
        &self,
        algorithm: crate::NativeDigestAlgorithm,
        parts: &[&[u8]],
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        let mut retired_owner = None;
        self.start_digest(
            parts,
            limits,
            DigestSelection::Native(algorithm),
            false,
            &mut retired_owner,
        )
    }

    /// As digest_native, with an explicit native validation observation before
    /// publication. Missing support is not interpreted as successful validation.
    pub fn digest_native_with_validation(
        &self,
        algorithm: crate::NativeDigestAlgorithm,
        parts: &[&[u8]],
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        let mut retired_owner = None;
        self.start_digest(
            parts,
            limits,
            DigestSelection::Native(algorithm),
            true,
            &mut retired_owner,
        )
    }
}

impl Session {
    /// Hash one input through C_DigestInit followed by C_Digest. No Update/Final
    /// substitution, length probe or automatic retry is performed. The shared
    /// owner retains the input/output and native effect until completion.
    pub fn digest_native_single(
        &self,
        algorithm: crate::NativeDigestAlgorithm,
        input: &[u8],
        limits: crate::InputLimits,
    ) -> Result<crate::NativeDigest> {
        let mut diagnostic = None;
        let mut retired_owner = None;
        synchronous(self)?;
        super::batch::native(
            self,
            &[input],
            limits,
            DigestSelection::NativeSingle(algorithm),
            None,
            &mut retired_owner,
            &mut diagnostic,
        )
    }
}
impl AdvancedSession {
    /// Native C_Digest route using this session's pacing and capture settings.
    /// A cooperative ticket can be captured after Init and resumed at C_Digest;
    /// no digest_update/digest_key injection is accepted on this route.
    pub fn digest_native_single(
        &self,
        algorithm: crate::NativeDigestAlgorithm,
        input: &[u8],
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        let mut retired_owner = None;
        self.start_digest(
            &[input],
            limits,
            DigestSelection::NativeSingle(algorithm),
            false,
            &mut retired_owner,
        )
    }
    /// C_Digest route with an explicit validation observation before publication.
    pub fn digest_native_single_with_validation(
        &self,
        algorithm: crate::NativeDigestAlgorithm,
        input: &[u8],
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        let mut retired_owner = None;
        self.start_digest(
            &[input],
            limits,
            DigestSelection::NativeSingle(algorithm),
            true,
            &mut retired_owner,
        )
    }
}

fn gost_selection(oid: Option<&[u8]>, route: MessageRoute) -> DigestSelection {
    if oid.is_some() {
        DigestSelection::GostOid(route)
    } else {
        match route {
            MessageRoute::Single => {
                DigestSelection::NativeSingle(crate::NativeDigestAlgorithm::GostR3411)
            }
            MessageRoute::Multipart => {
                DigestSelection::Native(crate::NativeDigestAlgorithm::GostR3411)
            }
        }
    }
}
impl Session {
    /// Execute GOST R34.11 with the exact optional DER OID parameter. None keeps
    /// the module's native default; Some(empty) remains a present empty parameter
    /// for the module to accept or refuse. No local OID/profile whitelist applies.
    /// Input limits count data fragments; OID storage follows the memory budget.
    pub fn digest_gost(
        &self,
        oid: Option<&[u8]>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: crate::InputLimits,
    ) -> Result<crate::NativeDigest> {
        let mut diagnostic = None;
        let mut retired_owner = None;
        synchronous(self)?;
        super::batch::native(
            self,
            parts,
            limits,
            gost_selection(oid, route),
            oid,
            &mut retired_owner,
            &mut diagnostic,
        )
    }
    /// Start multipart GOST; digest_update/digest_key and finish_native_digest
    /// use the common continuation owner, retaining this exact OID.
    pub fn begin_gost_digest(&self, oid: Option<&[u8]>) -> Result<OperationTicket> {
        let mut retired_owner = None;
        synchronous(self)?;
        super::start_open_with_oid(
            self,
            &[],
            crate::InputLimits {
                maximum_parts: self.inner.crypto_options.limits.maximum_parts,
                maximum_total_bytes: self.inner.crypto_options.limits.maximum_total_bytes,
            },
            gost_selection(oid, MessageRoute::Multipart),
            oid,
            false,
            false,
            &mut 1,
            &mut retired_owner,
        )
    }
}
impl AdvancedSession {
    /// GOST with exact optional OID, chosen native route and validation request.
    /// Capture/restore preserves the OID and never repeats DigestInit or DigestKey.
    pub fn digest_gost(
        &self,
        oid: Option<&[u8]>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: crate::InputLimits,
        validation_requested: bool,
    ) -> Result<OperationTicket> {
        let mut retired_owner = None;
        super::start_with_oid(
            &self.session,
            parts,
            limits,
            gost_selection(oid, route),
            oid,
            validation_requested,
            self.validation_capture == ValidationCaptureMode::Capture,
            &mut self.pacing.budget(),
            &mut retired_owner,
        )
    }
    /// Begin multipart GOST without finalization, for caller-driven injections.
    pub fn begin_gost_digest(&self, oid: Option<&[u8]>) -> Result<OperationTicket> {
        let mut retired_owner = None;
        synchronous(&self.session)?;
        super::start_open_with_oid(
            &self.session,
            &[],
            crate::InputLimits {
                maximum_parts: self.session.inner.crypto_options.limits.maximum_parts,
                maximum_total_bytes: self.session.inner.crypto_options.limits.maximum_total_bytes,
            },
            gost_selection(oid, MessageRoute::Multipart),
            oid,
            false,
            self.validation_capture == ValidationCaptureMode::Capture,
            &mut 1,
            &mut retired_owner,
        )
    }
}

fn begin_extension(
    session: &Session,
    request: crate::ExtensionRequest<'_>,
    output_capacity: usize,
    capture: bool,
    retired_owner: &mut Option<std::sync::Arc<crate::advanced::ledger::OperationCell>>,
) -> Result<OperationTicket> {
    synchronous(session)?;
    request
        .contract
        .check(&session.inner, crate::ExtensionOperation::DigestMultipart)?;
    super::start_with_input(
        session,
        &[],
        crate::InputLimits {
            maximum_parts: session.inner.crypto_options.limits.maximum_parts,
            maximum_total_bytes: session.inner.crypto_options.limits.maximum_total_bytes,
        },
        DigestSelection::Extension {
            mechanism: request.contract.native_mechanism(),
            capacity: output_capacity,
            route: MessageRoute::Multipart,
        },
        None,
        false,
        capture,
        &mut 1,
        crate::advanced::input::InputState::open(),
        Some(request.into()),
        retired_owner,
    )
}
impl OperationTicket {
    /// Return the native required size after a digest output refusal,
    /// without retrying or reading any provider-owned pending memory.
    pub fn digest_output_requirement(&self) -> Result<Option<usize>> {
        if self.id == 0 {
            return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::ConsumedDigestTicket,
            )));
        }
        let state = self.owner.read()?;
        let held = state.operations.get(self.uid)?;
        let operation = held.lock().map_err(|_| Error::Poisoned)?;
        if operation.id != self.id {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::StaleDigestTicket,
            )));
        }
        let OperationBody::Digest(body) = &operation.body else {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::DigestTicketRequired,
            )));
        };
        Ok(match body.step {
            Step::OutputRequired { required, .. } => Some(required),
            _ => None,
        })
    }

    /// Return the same native size observation for an extension digest.
    pub fn extension_digest_output_requirement(&self) -> Result<Option<usize>> {
        self.digest_output_requirement()
    }
}
impl Session {
    /// Retrieve once the continuation retained by a complete-input digest error.
    /// This transfers its ticket without replaying, finalizing or cancelling it.
    pub fn take_digest_ticket(&self) -> Result<OperationTicket> {
        let access = self.advanced_access()?;
        let held = access.operations.get(self.uid)?;
        let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
        let OperationBody::Digest(body) = &mut operation.body else {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::DigestTicketRequired,
            )));
        };
        if body.observer != super::Observer::Session {
            return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::DigestContinuationTicketUnavailable,
            )));
        }
        body.observer = super::Observer::Ticket;
        Ok(OperationTicket {
            owner: self.inner.clone(),
            uid: self.uid,
            id: operation.id,
            validation_report: None,
            state_provenance: None,
        })
    }
}
impl AdvancedSession {
    /// Retrieve the continuation retained by a synchronous digest facade error.
    pub fn take_digest_ticket(&self) -> Result<OperationTicket> {
        self.session.take_digest_ticket()
    }
}
impl Session {
    /// Initialize a caller-defined digest graph. Append with digest_update or
    /// digest_key, then explicitly finish. The graph and auxiliary outputs remain
    /// owned by the operation until result publication or confirmed native close.
    pub fn begin_extension_digest_stream(
        &self,
        request: crate::ExtensionRequest<'_>,
        output_capacity: usize,
    ) -> Result<OperationTicket> {
        let mut retired_owner = None;
        begin_extension(self, request, output_capacity, false, &mut retired_owner)
    }
    /// Replace retained digest output after BUFFER_TOO_SMALL.
    /// This allocates outside native guards and makes no native call. Finish or
    /// poll explicitly to resubmit the same retained terminal invocation.
    pub fn provide_digest_output_capacity(
        &self,
        ticket: &OperationTicket,
        capacity: usize,
    ) -> Result<()> {
        crate::advanced::output_preparation::replace(
            self,
            ticket,
            capacity,
            crate::advanced::output_preparation::Family::Digest,
        )
    }
    /// Replace retained extension output using the common digest owner.
    pub fn provide_extension_digest_output_capacity(
        &self,
        ticket: &OperationTicket,
        capacity: usize,
    ) -> Result<()> {
        self.provide_digest_output_capacity(ticket, capacity)
    }
    /// Close the input and return the native digest and parameter outputs.
    /// A native error leaves the ticket with the caller for explicit handling.
    pub fn finish_extension_digest_stream(
        &self,
        ticket: &mut OperationTicket,
    ) -> Result<crate::ExtensionResult> {
        let mut retired_owner = None;
        match finish(self, ticket, ResultContract::Extension, &mut retired_owner)? {
            OperationProgress::ExtensionDigest(result) => Ok(result),
            _ => Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::ExtensionDigestResultOwner,
            ))),
        }
    }
}
impl AdvancedSession {
    /// Initialize the same synchronous extension digest owner, with this facade's
    /// optional validation observation. Polling never closes an open input.
    pub fn begin_extension_digest_stream(
        &self,
        request: crate::ExtensionRequest<'_>,
        output_capacity: usize,
    ) -> Result<OperationTicket> {
        let mut retired_owner = None;
        begin_extension(
            &self.session,
            request,
            output_capacity,
            self.validation_capture == ValidationCaptureMode::Capture,
            &mut retired_owner,
        )
    }
    /// Admit replacement output storage without resubmitting a native call.
    pub fn provide_digest_output_capacity(
        &self,
        ticket: &OperationTicket,
        capacity: usize,
    ) -> Result<()> {
        self.session
            .provide_digest_output_capacity(ticket, capacity)
    }
    /// Admit replacement extension storage through the common digest owner.
    pub fn provide_extension_digest_output_capacity(
        &self,
        ticket: &OperationTicket,
        capacity: usize,
    ) -> Result<()> {
        self.session
            .provide_extension_digest_output_capacity(ticket, capacity)
    }
    /// Close caller input and publish the digest graph through OperationProgress.
    pub fn finish_extension_digest_stream(
        &self,
        ticket: &mut OperationTicket,
    ) -> Result<OperationProgress> {
        let mut retired_owner = None;
        finish(
            &self.session,
            ticket,
            ResultContract::Extension,
            &mut retired_owner,
        )
    }
}

mod injection;
use injection::inject;

