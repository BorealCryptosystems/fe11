// SPDX-License-Identifier: Apache-2.0
//! Classic sign/verify sequences with explicit input closure and retained calls.
//!
//! Recovery signatures have their own owner. This family never substitutes a
//! prehash or a message function. An explicit second classic Init follows the
//! module's reply; an accepted same-family Init replaces its previous ticket.
use super::{input::InputState, spend, NativeActivity};
use crate::mechanism_extension::{MechanismExtension, OwnedGraph};
use crate::module::{SessionEntry, State};
use crate::native::derivation::InputBytes;
use crate::native_return::protocol::{PendingInspection, SequencePhase};
use crate::native_return::sequence::{Completion, OutputRequest};
use crate::symmetric::memory::{Buffer, Credit};
use crate::{bounds, Error, ExtensionOperation, ExtensionResult, MessageRoute, Result};
use fe11_sys::*;
use std::sync::{atomic::Ordering, Arc};

mod api;
pub(crate) mod batch;
pub(super) mod binding;
pub(super) mod checkpoint;
mod competing_init;
mod preparation;
mod single;
use super::key_roles as roles;
pub(super) mod snapshot;

/// Output storage for a native signature. A size query does not end signing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureOutputPlan {
    /// Supply a non-NULL buffer, including a zero-capacity buffer.
    Buffer {
        /// Writable signature capacity, charged to the configured memory budget.
        capacity: usize,
    },
    /// Query the signature length; the caller subsequently supplies storage.
    LengthOnly,
}

/// A native size result, retaining the exact unfinished signing call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureBufferRequest {
    /// Exact native terminal function that reported the size.
    pub function: &'static str,
    /// CKR_OK for a query or CKR_BUFFER_TOO_SMALL for supplied storage.
    pub code: u64,
    /// Required bytes reported by the module, without clamping.
    pub required: usize,
    /// Capacity supplied in that call; zero for a length-only query.
    pub previous_capacity: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Sign,
    Verify,
    VerifySignature,
}
impl Kind {
    fn category(self) -> CK_FLAGS {
        match self {
            Self::Sign => (CKF_SIGN | CKF_SIGN_RECOVER) as CK_FLAGS,
            Self::Verify | Self::VerifySignature => (CKF_VERIFY | CKF_VERIFY_RECOVER) as CK_FLAGS,
        }
    }

    pub(super) fn operation(self, route: MessageRoute) -> ExtensionOperation {
        match (self, route) {
            (Self::Sign, MessageRoute::Single) => ExtensionOperation::Sign,
            (Self::Sign, MessageRoute::Multipart) => ExtensionOperation::SignMultipart,
            (Self::Verify, MessageRoute::Single) => ExtensionOperation::Verify,
            (Self::Verify, MessageRoute::Multipart) => ExtensionOperation::VerifyMultipart,
            (Self::VerifySignature, MessageRoute::Single) => ExtensionOperation::VerifySignature,
            (Self::VerifySignature, MessageRoute::Multipart) => {
                ExtensionOperation::VerifySignatureMultipart
            }
        }
    }
    fn init(self) -> &'static str {
        match self {
            Self::Sign => "C_SignInit",
            Self::Verify => "C_VerifyInit",
            Self::VerifySignature => "C_VerifySignatureInit",
        }
    }
    fn update(self) -> &'static str {
        match self {
            Self::Sign => "C_SignUpdate",
            Self::Verify => "C_VerifyUpdate",
            Self::VerifySignature => "C_VerifySignatureUpdate",
        }
    }
    fn terminal(self, route: MessageRoute) -> &'static str {
        match (self, route) {
            (Self::Sign, MessageRoute::Single) => "C_Sign",
            (Self::Sign, MessageRoute::Multipart) => "C_SignFinal",
            (Self::Verify, MessageRoute::Single) => "C_Verify",
            (Self::Verify, MessageRoute::Multipart) => "C_VerifyFinal",
            (Self::VerifySignature, MessageRoute::Single) => "C_VerifySignature",
            (Self::VerifySignature, MessageRoute::Multipart) => "C_VerifySignatureFinal",
        }
    }
    pub(super) fn check_functions(self, route: MessageRoute, state: &State) -> Result<()> {
        let table = &state.native.table;
        let present = match self {
            Kind::Sign => {
                table.C_SignInit.is_some()
                    && match route {
                        MessageRoute::Single => table.C_Sign.is_some(),
                        MessageRoute::Multipart => {
                            table.C_SignUpdate.is_some() && table.C_SignFinal.is_some()
                        }
                    }
            }
            Kind::Verify => {
                table.C_VerifyInit.is_some()
                    && match route {
                        MessageRoute::Single => table.C_Verify.is_some(),
                        MessageRoute::Multipart => {
                            table.C_VerifyUpdate.is_some() && table.C_VerifyFinal.is_some()
                        }
                    }
            }
            Kind::VerifySignature => state.native.verify_signature.as_ref().is_some_and(|table| {
                table.init.is_some()
                    && match route {
                        MessageRoute::Single => table.single.is_some(),
                        MessageRoute::Multipart => table.update.is_some() && table.finish.is_some(),
                    }
            }),
        };
        if present {
            Ok(())
        } else {
            Err(Error::Unsupported(
                crate::UnsupportedReason::SignatureContinuation(
                    crate::SignatureContinuationUnsupported::SignatureFunctionTuple,
                ),
            ))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Stage {
    Init,
    Ready,
    Update,
    Terminal,
    Waiting(SignatureBufferRequest),
    Complete,
    Failed,
}

/// No Inner or session guard is stored here. The operation ledger owns this
/// frame; the role lease holds only object exclusions and their actual credit.
// The observer is independent of the native stage. Synchronous wrappers can
// return an error while leaving exactly one ticket retrievable by the session.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Observer {
    Ticket,
    Session,
}

/// Established-return operands awaiting destruction outside all access guards.
/// A drive can consume at most one submitted fragment and one terminal signature;
/// a capacity refusal returns immediately with at most one displaced output.
#[derive(Default)]
pub(in crate::advanced) struct ReturnedOperands {
    fragment: Option<InputBytes>,
    signature: Option<InputBytes>,
    output: Option<Buffer>,
}

impl ReturnedOperands {
    fn is_empty(&self) -> bool {
        self.fragment.is_none() && self.signature.is_none() && self.output.is_none()
    }
}

pub(super) struct SignatureOperation {
    observer: Observer,
    key: Arc<crate::managed::NativeIdentity>,
    authentication: u64,
    _roles: roles::Roles,
    // Stateful signing invalidates the source's descriptive aliases before C.
    // This particular owner may continue under its retained exclusive writer;
    // it never reactivates the source reference or admits another operation.
    own_revocation: bool,
    revocation: Option<crate::managed::RevocationTargets>,
    contract: MechanismExtension,
    kind: Kind,
    route: MessageRoute,
    mechanism: Box<CK_MECHANISM>,
    parameters: Option<OwnedGraph>,
    fragment: Option<InputBytes>,
    signature: Option<InputBytes>,
    output: Option<Buffer>,
    output_offset: usize,
    returned: ReturnedOperands,
    length: Box<CK_ULONG>,
    plan: SignatureOutputPlan,
    maximum_output: usize,
    input: InputState,
    stage: Stage,
    activity: NativeActivity,
    // One terminal boundary failure consumes this leaf. The metadata credit
    // stays with the retained operation, including after the leaf is returned.
    completion_diagnostic: Option<crate::error::CompletionStorage>,
    _credit: Credit,
}
// SAFETY: the descriptor, graph, buffers and output length have stable owned
// storage. Access is serialized by the ledger. Unknown returns retain this
// entire owner rather than allowing its pointers to escape their lifetimes.
unsafe impl Send for SignatureOperation {}

pub(crate) fn output_alignment(mechanism: u64) -> usize {
    if matches!(mechanism, n if n == CKM_SECURID as u64 || n == CKM_HOTP as u64 || n == CKM_ACTI as u64)
    {
        std::mem::align_of::<CK_OTP_SIGNATURE_INFO>()
    } else {
        1
    }
}
pub(super) fn output_storage_bytes(mechanism: u64, capacity: usize) -> Result<usize> {
    capacity
        .checked_add(output_alignment(mechanism) - 1)
        .ok_or(Error::Rejected(
            crate::RejectionReason::SignatureContinuation(
                crate::SignatureContinuationRejection::SignatureOutputAlignmentAccounting,
            ),
        ))
}
pub(super) fn output_offset(mechanism: u64, output: &mut Buffer) -> Result<usize> {
    let alignment = output_alignment(mechanism);
    let offset = output.as_mut().as_mut_ptr().align_offset(alignment);
    if offset >= alignment {
        return Err(Error::Rejected(
            crate::RejectionReason::SignatureContinuation(
                crate::SignatureContinuationRejection::SignatureOutputAlignment,
            ),
        ));
    }
    Ok(offset)
}

impl SignatureOperation {
    pub(super) fn replacement_kind(&self) -> Kind {
        self.kind
    }

    pub(super) fn replacement_authentication(&self) -> u64 {
        self.authentication
    }

    /// The native Init is complete; the signature sequence is now active.
    /// Complete-input single calls proceed to C_Sign/C_Verify, not another Init.
    fn accept_initialization(&mut self) {
        self.activity = NativeActivity::Active;
        self.stage = if self.route == MessageRoute::Single && !self.input.is_open() {
            Stage::Terminal
        } else {
            Stage::Ready
        };
    }

    pub(in crate::advanced) fn take_returned_operands(&mut self) -> ReturnedOperands {
        std::mem::take(&mut self.returned)
    }

    fn retire_fragment(&mut self) {
        if let Some(fragment) = self.fragment.take() {
            // A successful Update stops at Ready; a following Final has no
            // fragment. Never overwrite a retired Update with an absent input.
            debug_assert!(self.returned.fragment.is_none());
            self.returned.fragment = Some(fragment);
        }
    }

    fn retire_signature(&mut self) {
        if let Some(signature) = self.signature.take() {
            debug_assert!(self.returned.signature.is_none());
            self.returned.signature = Some(signature);
        }
    }

    fn retire_output(&mut self) {
        if let Some(output) = self.output.take() {
            debug_assert!(self.returned.output.is_none());
            self.returned.output = Some(output);
        }
    }

    pub(super) fn exclusive_continuation(&self) -> bool {
        self.contract.mutates_key()
    }
    pub(super) fn check_key(&self, entry: &SessionEntry) -> Result<()> {
        if !self.own_revocation && self.key.revoked.load(Ordering::Acquire) {
            return Err(Error::Rejected(
                crate::RejectionReason::SignatureContinuation(
                    crate::SignatureContinuationRejection::RevokedSignatureKey,
                ),
            ));
        }
        crate::managed::check_creator(self.key.creator())?;
        // Logout changes authorization, not the lifetime of this owned frame.
        // Keep hard invalidation checks; let the module decide whether its
        // initialized operation still permits Update/Sign/Verify/Final.
        entry.snapshot.check()
    }
    pub(super) fn complete(&self) -> bool {
        self.stage == Stage::Complete
    }

    /// A mutating Init invalidates prior observations even when the module
    /// refuses it. Both installed operations and conflicting attempts must
    /// publish this transition before dispatch, without rebinding the key.
    fn revoke_before_init(&mut self) {
        if let Some(revocation) = self.revocation.take() {
            self.own_revocation = true;
            drop(revocation.arm());
        }
    }
    pub(super) fn pending(&self) -> bool {
        self.activity.pending()
    }
    pub(super) fn initialization_refused(&self) -> bool {
        self.activity == NativeActivity::InitializationRefused
    }

    pub(super) fn native_inactive(&self) -> bool {
        self.activity.inactive()
    }
    pub(super) fn active_categories(&self) -> CK_FLAGS {
        if self.activity.locally_retirable() {
            0
        } else if self.kind == Kind::Sign {
            CKF_SIGN
        } else {
            CKF_VERIFY
        }
    }
    pub(super) fn buffer_request(&self) -> Option<SignatureBufferRequest> {
        match self.stage {
            Stage::Waiting(request) => Some(request),
            _ => None,
        }
    }
    pub(super) fn next_function(&self) -> Option<&'static str> {
        match self.stage {
            Stage::Init => Some(self.kind.init()),
            Stage::Ready if self.route == MessageRoute::Single => {
                Some(self.kind.terminal(self.route))
            }
            Stage::Ready | Stage::Update => Some(self.kind.update()),
            Stage::Terminal => Some(self.kind.terminal(self.route)),
            _ => None,
        }
    }
    pub(super) fn validation_point(&self) -> Option<super::validation::Point> {
        ((self.stage == Stage::Terminal || self.stage == Stage::Ready && !self.input.is_open())
            && (self.kind != Kind::Sign || matches!(self.plan, SignatureOutputPlan::Buffer { .. })))
        .then_some(super::validation::Point {
            function: self.kind.terminal(self.route),
            message_index: None,
        })
    }

    fn unchanged(&mut self) -> bool {
        let Some(parameters) = self.parameters.as_mut() else {
            return false;
        };
        let (pointer, length) = parameters.projection();
        self.mechanism.mechanism == self.contract.native_mechanism()
            && self.mechanism.pParameter == pointer
            && self.mechanism.ulParameterLen == length
            && parameters.unchanged()
            && self.fragment.as_ref().map_or(true, InputBytes::unchanged)
            && self.signature.as_ref().map_or(true, InputBytes::unchanged)
    }

    /// Advance only calls whose operands are already retained. Ready is a real
    /// input boundary, not permission to Final while the input remains open.
    pub(super) fn drive(
        &mut self,
        state: &State,
        entry: &SessionEntry,
        remaining: &mut usize,
    ) -> Result<()> {
        if self.pending() {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::SignatureAsynchronousModeUnavailable,
                ),
            ));
        }
        loop {
            if self.stage == Stage::Ready && !self.input.is_open() {
                if self.kind != Kind::Sign && self.signature.is_none() {
                    return Err(Error::Rejected(
                        crate::RejectionReason::SignatureContinuation(
                            crate::SignatureContinuationRejection::VerificationSignatureNotSupplied,
                        ),
                    ));
                }
                self.stage = Stage::Terminal;
            }
            if self.stage == Stage::Ready {
                return Ok(());
            }
            let Some(function) = self.next_function() else {
                return Ok(());
            };
            self.check_key(entry)?;
            let submitted = self.stage == Stage::Update
                || self.stage == Stage::Terminal && self.route == MessageRoute::Single;
            let submission = if submitted {
                let fragment = self.fragment.as_ref().ok_or(Error::Rejected(
                    crate::RejectionReason::SignatureContinuation(
                        crate::SignatureContinuationRejection::SignatureInputAbsent,
                    ),
                ))?;
                Some(self.input.submission(fragment.bytes().len(), false)?)
            } else {
                None
            };
            let capacity = match self.plan {
                SignatureOutputPlan::Buffer { capacity } => capacity,
                SignatureOutputPlan::LengthOnly => 0,
            };
            if self.stage == Stage::Terminal && self.kind == Kind::Sign {
                self.input.produced(capacity)?;
                *self.length = bounds::ck_length(capacity)?;
            }
            if !spend(remaining) {
                return Ok(());
            }
            let native_call =
                resolved_call::Call::resolve(&state.native, self.kind, self.stage, self.route)?;
            state.native.record(function)?;
            if self.stage == Stage::Init {
                self.revoke_before_init();
            }
            if let Some(submission) = &submission {
                self.input = submission.issued;
            }
            let stage = self.stage;
            self.activity = NativeActivity::Active;
            // SAFETY: tuple availability, native widths and all owned pointer
            // targets are established before dispatch. Each pointer remains
            // live on every return, including PENDING and uncertain failures.
            let rv = unsafe { self.dispatch(native_call, entry) };
            let version = state.native.table.version;
            let output_request = if self.kind != Kind::Sign {
                OutputRequest::Unspecified
            } else if matches!(self.plan, SignatureOutputPlan::LengthOnly) {
                OutputRequest::LengthOnly
            } else {
                OutputRequest::Buffer
            };
            let phase = if stage == Stage::Init {
                SequencePhase::Initialize
            } else {
                SequencePhase::Continue(output_request)
            };
            let inspected = PendingInspection::returned(function, rv, |scope| {
                state.apply_session_failure(entry, rv, scope);
            })
            .inspect(|| {
                if !self.unchanged() {
                    return Err(Error::Rejected(
                        crate::RejectionReason::SignatureContinuation(
                            crate::SignatureContinuationRejection::SignatureNativeInputMutation,
                        ),
                    ));
                }
                if rv == CKR_OK
                    && self.kind == Kind::Sign
                    && stage == Stage::Terminal
                    && matches!(self.plan, SignatureOutputPlan::Buffer { .. })
                {
                    bounds::final_length(*self.length, capacity)?;
                }
                Ok(())
            });
            let size = if self.kind == Kind::Sign && stage == Stage::Terminal {
                crate::NativeOutputSize::buffer_refusal(function, rv, capacity, || *self.length)
            } else {
                None
            };
            let initialization_refused =
                inspected.initialization_refused((version.major, version.minor), phase);
            let completion = inspected.completion((version.major, version.minor), phase);
            let result = inspected.resolve(|result, cause| {
                self.activity = NativeActivity::Active;
                self.stage = Stage::Failed;
                state.native.mark_uncertain();
                if result.code() == CKR_OK {
                    cause
                } else {
                    self.completion_diagnostic
                        .take()
                        .expect("one terminal signature boundary failure")
                        .bind(result.function())
                        .boundary_with_output(result.code(), size, cause)
                }
            })?;
            if completion == Completion::Uncertain {
                self.activity = if rv == CKR_PENDING {
                    NativeActivity::Pending
                } else {
                    NativeActivity::Active
                };
                self.stage = Stage::Failed;
                state.native.mark_uncertain();
                entry.poisoned.store(true, Ordering::Release);
                return result.check(true).and(Err(Error::Rejected(
                    crate::RejectionReason::SignatureContinuation(
                        crate::SignatureContinuationRejection::SignatureNativeTerminationUncertain,
                    ),
                )));
            }
            self.activity = if initialization_refused {
                NativeActivity::InitializationRefused
            } else if completion == Completion::Terminated {
                NativeActivity::Inactive
            } else {
                NativeActivity::Active
            };
            if self.kind == Kind::Sign
                && stage == Stage::Terminal
                && (rv == CKR_BUFFER_TOO_SMALL
                    || rv == CKR_OK && matches!(self.plan, SignatureOutputPlan::LengthOnly))
            {
                let required = usize::try_from(*self.length).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SignatureContinuation(
                        crate::SignatureContinuationRejection::SignatureNativeLengthWidth,
                    ))
                })?;
                self.retire_output();
                self.stage = Stage::Waiting(SignatureBufferRequest {
                    function,
                    code: rv as u64,
                    required,
                    previous_capacity: capacity,
                });
                return Ok(());
            }
            if rv != CKR_OK {
                self.stage = Stage::Failed;
                if self.activity.locally_retirable() {
                    self.input.retained_submission = false;
                    self.retire_fragment();
                } else {
                    entry.poisoned.store(true, Ordering::Release);
                }
                return result.check(self.contract.mutates_key());
            }
            match stage {
                Stage::Init => {
                    self.accept_initialization();
                }
                Stage::Update => {
                    self.input = submission.expect("checked update submission").completed;
                    self.retire_fragment();
                    self.stage = Stage::Ready;
                }
                Stage::Terminal => {
                    if let Some(submission) = submission {
                        self.input = submission.completed;
                    }
                    if self.kind == Kind::Sign {
                        let length = match bounds::final_length(*self.length, capacity) {
                            Ok(length) => length,
                            Err(error) => {
                                self.activity = NativeActivity::Active;
                                self.stage = Stage::Failed;
                                state.native.mark_uncertain();
                                return Err(error);
                            }
                        };
                        let output = self.output.as_mut().expect("prepared signature output");
                        output
                            .as_mut()
                            .copy_within(self.output_offset..self.output_offset + length, 0);
                        output.set_length(length)?;
                        self.input = self.input.produced(length)?;
                    }
                    if let Err(error) = self.parameters.as_mut().expect("owned parameters").finish()
                    {
                        self.activity = NativeActivity::Active;
                        self.stage = Stage::Failed;
                        state.native.mark_uncertain();
                        return Err(error);
                    }
                    self.retire_fragment();
                    self.retire_signature();
                    self.stage = Stage::Complete;
                }
                _ => unreachable!("dispatchable signature stage"),
            }
        }
    }

    unsafe fn dispatch(&mut self, call: resolved_call::Call, entry: &SessionEntry) -> CK_RV {
        let mut input = self
            .fragment
            .as_mut()
            .map_or((std::ptr::null_mut(), 0), |input| {
                (input.pointer(), input.length())
            });
        // OTP single calls use absent data, represented by NULL at length zero.
        // Preserve Update's distinct empty-fragment representation.
        if self.stage == Stage::Terminal
            && self.route == MessageRoute::Single
            && input.1 == 0
            && matches!(self.mechanism.mechanism, CKM_SECURID | CKM_HOTP | CKM_ACTI)
        {
            input.0 = std::ptr::null_mut();
        }
        let signature = self
            .signature
            .as_mut()
            .map_or((std::ptr::null_mut(), 0), |input| {
                (input.pointer(), input.length())
            });
        let output = match self.plan {
            SignatureOutputPlan::LengthOnly => std::ptr::null_mut(),
            SignatureOutputPlan::Buffer { .. } => self
                .output
                .as_mut()
                .expect("prepared signature output")
                .as_mut()[self.output_offset..]
                .as_mut_ptr(),
        };
        // SAFETY: caller has checked this exact tuple and retained all referents.
        unsafe {
            match call {
                resolved_call::Call::Init(call) => {
                    call(entry.handle, &mut *self.mechanism, self.key.handle)
                }
                resolved_call::Call::SignatureInit(call) => call(
                    entry.handle,
                    &mut *self.mechanism,
                    self.key.handle,
                    signature.0,
                    signature.1,
                ),
                resolved_call::Call::Input(call) => call(entry.handle, input.0, input.1),
                resolved_call::Call::Sign(call) => {
                    call(entry.handle, input.0, input.1, output, &mut *self.length)
                }
                resolved_call::Call::SignFinal(call) => {
                    call(entry.handle, output, &mut *self.length)
                }
                resolved_call::Call::Verify(call) => {
                    call(entry.handle, input.0, input.1, signature.0, signature.1)
                }
                resolved_call::Call::VerifyFinal(call) => {
                    call(entry.handle, signature.0, signature.1)
                }
                resolved_call::Call::Final(call) => call(entry.handle),
            }
        }
    }

    pub(super) fn output_preparation(&self, capacity: usize) -> Result<SignatureBufferRequest> {
        let request = self.buffer_request().ok_or(Error::Rejected(
            crate::RejectionReason::SignatureContinuation(
                crate::SignatureContinuationRejection::SignatureIsNotWaitingForStorage,
            ),
        ))?;
        bounds::ck_length(capacity)?;
        if capacity > self.maximum_output {
            return Err(Error::Rejected(
                crate::RejectionReason::SignatureContinuation(
                    crate::SignatureContinuationRejection::SignatureOutputCeiling,
                ),
            ));
        }
        Ok(request)
    }
    pub(super) fn output_storage_bytes(&self, capacity: usize) -> Result<usize> {
        output_storage_bytes(self.contract.mechanism_number(), capacity)
    }
    pub(super) fn attach_output(
        &mut self,
        capacity: usize,
        mut output: Buffer,
    ) -> Result<Option<Buffer>> {
        self.output_preparation(capacity)?;
        if output.as_slice().len() != self.output_storage_bytes(capacity)? {
            return Err(Error::Rejected(
                crate::RejectionReason::SignatureContinuation(
                    crate::SignatureContinuationRejection::SignaturePreparedOutputWidth,
                ),
            ));
        }
        self.output_offset = output_offset(self.contract.mechanism_number(), &mut output)?;
        output.set_length(0)?;
        let old = self.output.replace(output);
        self.plan = SignatureOutputPlan::Buffer { capacity };
        self.stage = Stage::Terminal;
        Ok(old)
    }
    pub(super) fn result(&mut self, _entry: &SessionEntry) -> Result<super::OperationProgress> {
        // Completed owned output remains evidence of that call, even if
        // the key or context was withdrawn before local publication.
        if !self.complete() {
            return Err(Error::Rejected(
                crate::RejectionReason::SignatureContinuation(
                    crate::SignatureContinuationRejection::SignatureResultIncomplete,
                ),
            ));
        }
        let mut bytes = self.output.take().ok_or(Error::Rejected(
            crate::RejectionReason::SignatureContinuation(
                crate::SignatureContinuationRejection::SignatureResultAlreadyPublished,
            ),
        ))?;
        let native_output_origin = bytes.as_mut().as_mut_ptr() as usize + self.output_offset;
        let result = ExtensionResult {
            bytes,
            native_output_origin,
            parameters: self
                .parameters
                .take()
                .expect("unpublished signature parameters"),
            provenance: self.contract.provenance(),
        };
        Ok(if self.kind == Kind::Sign {
            super::OperationProgress::NativeSignature(result)
        } else {
            super::OperationProgress::NativeVerification(result)
        })
    }
}

impl crate::symmetric::memory::RetainedStorage for ReturnedOperands {
    fn retain_credits(&self, retained: &mut crate::symmetric::memory::RetainedBytes) -> Result<()> {
        self.fragment.retain_credits(retained)?;
        self.signature.retain_credits(retained)?;
        self.output.retain_credits(retained)?;
        Ok(())
    }
}

impl crate::symmetric::memory::RetainedStorage for SignatureOperation {
    fn retain_credits(&self, retained: &mut crate::symmetric::memory::RetainedBytes) -> Result<()> {
        self.key.retain_identity_credit(retained)?;
        roles::Roles::retain_unique(Some(&self._roles), [], retained)?;
        self.revocation.retain_credits(retained)?;
        self.parameters.retain_credits(retained)?;
        self.fragment.retain_credits(retained)?;
        self.signature.retain_credits(retained)?;
        self.output.retain_credits(retained)?;
        self.returned.retain_credits(retained)?;
        self._credit.retain_credits(retained)?;
        Ok(())
    }
}

mod resolved_call;
