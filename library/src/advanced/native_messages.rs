// SPDX-License-Identifier: Apache-2.0
//! Generic message process ownership, including per-call ABI output graphs.
//!
//! Input fragments belong to the retained call, not to the result history.
//! Parameter graphs remain owned through parent Final under their ABI contract.
//! The synchronous ledger driver, admission and capture paths share this owner.
use super::{input::InputState, NativeActivity, SignatureBufferRequest};
use crate::mechanism_extension::{message::initialization::Initialization, OwnedGraph};
use crate::native::{derivation::InputBytes, message_signature as dispatch};
use crate::symmetric::memory::{Buffer, Credit};
use crate::{Error, MessageRoute, Result};
use fe11_sys::{CKM_ACTI, CKM_HOTP, CKM_SECURID, CK_MECHANISM_TYPE, CK_ULONG, CK_VOID_PTR};

mod api;
mod batch;
mod binding;
pub(crate) use batch::{execute, Invocation};
pub(in crate::advanced) mod checkpoint;
mod driver;
mod input;
mod output;
mod preparation;
mod resolved_call;
mod result;
pub use result::{NativeMessageRejection, NativeMessageResults};
pub(in crate::advanced) mod restoration;
pub(in crate::advanced) mod snapshot;
mod start;
pub(in crate::advanced) use binding::Binding;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DataKind {
    Single,
    Update,
    Last,
}
impl DataKind {
    fn terminal(self) -> bool {
        self != Self::Update
    }
}

struct DataCall {
    message: usize,
    part: usize,
    kind: DataKind,
    bytes: InputBytes,
    // Present only for a terminal Verify call. It is not a past result.
    signature: Option<InputBytes>,
}

enum Phase {
    Init,
    Ready,
    Begin(usize),
    Receive(usize),
    Data(DataCall),
    Capacity {
        call: DataCall,
        request: SignatureBufferRequest,
        storage: CapacityStorage,
    },
    Final,
    Complete,
}

enum CapacityStorage {
    Missing,
    Prepared,
}

/// A failure does not replace Phase: the last operands must survive uncertainty.
/// Ordinary message refusals leave the parent open after memory has returned.
enum Execution {
    Running,
    // A reconstructed capture cannot issue C until its destination bindings
    // and native state have been restored. Preserve future-write intent even
    // when the source had not yet armed its revocation targets.
    Captured,
    Failed,
}

struct SignatureOutput {
    bytes: Buffer,
    offset: usize,
    // The module may retain this address; vector movement must not move it.
    length: Box<CK_ULONG>,
    capacity: usize,
    produced: Option<usize>,
}
impl SignatureOutput {
    fn capacity(&self) -> Result<usize> {
        self.offset
            .checked_add(self.capacity)
            .filter(|end| *end <= self.bytes.capacity())
            .map(|_| self.capacity)
            .ok_or(Error::Rejected(crate::RejectionReason::NativeMessages(
                crate::NativeMessagesRejection::MessageSignatureOutputOffset,
            )))
    }
}

enum MessageOutput {
    // A multipart Begin needs no output capacity chosen for its later Last.
    Sign(Option<SignatureOutput>),
    Verify { verdict: Option<fe11_sys::CK_RV> },
}

struct Message {
    begin: Option<Parameters>,
    parts: Vec<Parameters>,
    output: MessageOutput,
    // A returned refusal is distinct from an invalid signature verdict. Keep
    // lent graph/output allocations stable until parent Final, but never publish
    // this row's bytes as a successful result.
    rejection: Option<NativeMessageRejection>,
    // Covers row/vector/length-cell metadata, not the separately credited graphs.
    _metadata: Credit,
}
impl Message {
    fn unchanged(&self) -> bool {
        self.begin.as_ref().map_or(true, Parameters::unchanged)
            && self.parts.iter().all(Parameters::unchanged)
    }
}

/// Preserve each call's declaration as well as its bytes: its effect and ABI
/// provenance cannot be reconstructed from an opaque graph or a native handle.
struct Parameters {
    // The graph's own credit covers its boxed header. Vector capacity then
    // charges only Parameters slots, with no active/unused-header discount.
    graph: Box<OwnedGraph>,
    contract: Option<crate::MechanismExtension>,
}
impl Parameters {
    fn unchanged(&self) -> bool {
        self.graph.unchanged()
    }

    fn mutates_key(&self) -> bool {
        self.contract
            .as_ref()
            .is_some_and(|contract| contract.mutates_key())
    }
}

/// Extracted by the poll boundary, then dropped after session possession ends.
/// One call can retire at most one input/signature pair before waiting for input.
#[derive(Default)]
pub(super) struct ReleasedInput {
    call: Option<DataCall>,
    output: Option<Buffer>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Observer {
    Ticket,
    Session,
}

// The Box pointer is included in the owner; its allocation is separately
// admitted so post-call diagnostics never need memory allocation under guards.
const DIAGNOSTIC_BYTES: usize = std::mem::size_of::<Error>();
fn prepared_diagnostic() -> Box<Error> {
    Box::new(Error::Rejected(crate::RejectionReason::NativeMessages(
        crate::NativeMessagesRejection::GenericMessageDiagnosticNotUsed,
    )))
}

pub(super) struct NativeMessageOperation {
    observer: Observer,
    binding: Binding,
    // None only after the completed payload has been published.
    initialization: Option<Box<Initialization>>,
    expected: (CK_MECHANISM_TYPE, CK_VOID_PTR, CK_ULONG),
    route: MessageRoute,
    verify: bool,
    phase: Phase,
    execution: Execution,
    activity: NativeActivity,
    input: InputState,
    invalid_seen: bool,
    messages: Vec<Message>,
    released: ReleasedInput,
    // Taken at most once, after marking the operation Failed/uncertain.
    diagnostic: Option<Box<Error>>,
    _metadata: Credit,
}
// SAFETY: the boxed descriptor, graph blocks, inputs, output buffers and boxed
// lengths have stable owned addresses. The ledger serializes their use; Phase
// retains every operand on a pending or otherwise uncertain native return.
// The prepared diagnostic holds only a static placeholder while in this owner;
// it is moved out after marking execution Failed, before attaching the local error.
unsafe impl Send for NativeMessageOperation {}

impl NativeMessageOperation {
    // Constructors retain this owner through every runnable/captured phase.
    // Only result() takes it, after Complete; dispatch, capture and submission
    // reject that phase before reaching this accessor.
    fn initialization(&self) -> &Initialization {
        self.initialization
            .as_deref()
            .expect("retained initialization")
    }

    fn data(&self) -> Option<&DataCall> {
        match &self.phase {
            Phase::Data(call) | Phase::Capacity { call, .. } => Some(call),
            _ => None,
        }
    }

    fn unchanged(&self) -> bool {
        self.initialization().unchanged(self.expected)
            && self.messages.iter().all(Message::unchanged)
            && self.data().map_or(true, |call| {
                call.bytes.unchanged()
                    && call.signature.as_ref().map_or(true, InputBytes::unchanged)
            })
    }

    pub(super) fn check_key(&self, entry: &crate::module::SessionEntry) -> Result<()> {
        self.binding.check(entry)
    }

    pub(super) fn complete(&self) -> bool {
        matches!(self.phase, Phase::Complete)
            && !matches!(
                self.execution,
                Execution::Failed | Execution::Captured { .. }
            )
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

    pub(super) fn buffer_request(&self) -> Option<SignatureBufferRequest> {
        match &self.phase {
            Phase::Capacity {
                request,
                storage: CapacityStorage::Missing,
                ..
            } => Some(*request),
            _ => None,
        }
    }

    pub(super) fn take_released_input(&mut self) -> ReleasedInput {
        std::mem::take(&mut self.released)
    }

    pub(super) fn next_function(&self) -> Option<&'static str> {
        if matches!(
            self.execution,
            Execution::Failed | Execution::Captured { .. }
        ) {
            return None;
        }
        match (&self.phase, self.verify) {
            (Phase::Init, false) => Some("C_MessageSignInit"),
            (Phase::Init, true) => Some("C_MessageVerifyInit"),
            (Phase::Begin(_), false) => Some("C_SignMessageBegin"),
            (Phase::Begin(_), true) => Some("C_VerifyMessageBegin"),
            (
                Phase::Data(call)
                | Phase::Capacity {
                    call,
                    storage: CapacityStorage::Prepared,
                    ..
                },
                false,
            ) => Some(if call.kind == DataKind::Single {
                "C_SignMessage"
            } else {
                "C_SignMessageNext"
            }),
            (
                Phase::Data(call)
                | Phase::Capacity {
                    call,
                    storage: CapacityStorage::Prepared,
                    ..
                },
                true,
            ) => Some(if call.kind == DataKind::Single {
                "C_VerifyMessage"
            } else {
                "C_VerifyMessageNext"
            }),
            (Phase::Final, false) => Some("C_MessageSignFinal"),
            (Phase::Final, true) => Some("C_MessageVerifyFinal"),
            // Capacity needs explicit replacement storage. Neither absent input
            // nor a size request silently dispatches an extra call or Final.
            _ => None,
        }
    }

    pub(super) fn active_categories(&self) -> fe11_sys::CK_FLAGS {
        if self.activity.locally_retirable() {
            0
        } else if self.verify {
            fe11_sys::CKF_MESSAGE_VERIFY
        } else {
            fe11_sys::CKF_MESSAGE_SIGN
        }
    }

    pub(super) fn message_count(&self) -> usize {
        self.messages.len()
    }

    pub(super) fn input_progress(&self) -> (crate::StreamInputStatus, crate::StreamProgress) {
        (self.input.status, self.input.progress)
    }

    pub(super) fn observation_allowed(&self) -> bool {
        matches!(self.execution, Execution::Running) && self.buffer_request().is_none()
    }

    pub(super) fn validation_point(&self) -> Result<Option<super::validation::Point>> {
        let message_index = self
            .data()
            .filter(|call| call.kind.terminal())
            .map(|call| call.message);
        if self.observation_allowed()
            && (message_index.is_some() || matches!(self.phase, Phase::Final))
        {
            Ok(self
                .next_function()
                .map(|function| super::validation::Point {
                    function,
                    message_index,
                }))
        } else {
            Ok(None)
        }
    }

    fn operands(&mut self, native: resolved_call::Call) -> Result<dispatch::Call<'_>> {
        use resolved_call::{Call, SignatureFunction};
        match (&mut self.phase, native) {
            (Phase::Init, Call::Init(native)) => Ok(dispatch::Call::Init {
                native,
                mechanism: self
                    .initialization
                    .as_deref_mut()
                    .expect("retained initialization")
                    .descriptor(),
                key: self.binding.primary.key.handle,
            }),
            (Phase::Begin(index), Call::Begin(native)) => {
                let message = self.messages.get_mut(*index).ok_or_else(invalid)?;
                Ok(dispatch::Call::Begin {
                    native,
                    parameters: message
                        .begin
                        .as_mut()
                        .map(|parameters| parameters.graph.as_mut()),
                })
            }
            (Phase::Data(call), Call::Data(native)) => {
                let message = self.messages.get_mut(call.message).ok_or_else(invalid)?;
                let parameters = message.parts.get_mut(call.part).ok_or_else(invalid)?;
                let input_length = call.bytes.length();
                let input = if input_length == 0
                    && matches!(
                        self.initialization
                            .as_deref()
                            .expect("retained initialization")
                            .kind(),
                        CKM_SECURID | CKM_HOTP | CKM_ACTI
                    ) {
                    None
                } else {
                    Some(call.bytes.as_mut())
                };
                let signature = match (&mut message.output, call.kind.terminal(), native) {
                    (MessageOutput::Sign(Some(output)), true, SignatureFunction::Sign(native)) => {
                        dispatch::Signature::Produce {
                            native,
                            output: Some((
                                &mut output.bytes.as_mut()
                                    [output.offset..output.offset + output.capacity],
                                &mut output.length,
                            )),
                        }
                    }
                    (MessageOutput::Sign(_), false, SignatureFunction::Sign(native)) => {
                        dispatch::Signature::Produce {
                            native,
                            output: None,
                        }
                    }
                    (MessageOutput::Verify { .. }, true, SignatureFunction::Verify(native)) => {
                        let signature = call.signature.as_mut().ok_or_else(invalid)?;
                        let length = signature.length();
                        dispatch::Signature::Verify {
                            native,
                            signature: Some((signature.as_mut(), length)),
                        }
                    }
                    (MessageOutput::Verify { .. }, false, SignatureFunction::Verify(native)) => {
                        dispatch::Signature::Verify {
                            native,
                            signature: None,
                        }
                    }
                    _ => return Err(invalid()),
                };
                Ok(dispatch::Call::Data {
                    parameters: Some(parameters.graph.as_mut()),
                    input,
                    input_length,
                    signature,
                })
            }
            (Phase::Final, Call::Final(native)) => Ok(dispatch::Call::Final { native }),
            _ => Err(invalid()),
        }
    }

    /// Infallible commit after all fallible return/counter checks. Its caller
    /// must have established native memory return before replacing Phase.
    fn returned_to(&mut self, next: Phase) {
        assert!(
            !matches!(self.phase, Phase::Data(_) | Phase::Capacity { .. })
                || self.released.call.is_none(),
            "message input retirement pending"
        );
        let previous = std::mem::replace(&mut self.phase, next);
        match previous {
            Phase::Data(call) | Phase::Capacity { call, .. } => {
                self.released.call = Some(call);
            }
            _ => {}
        }
    }
}

fn invalid() -> Error {
    Error::Rejected(crate::RejectionReason::NativeMessages(
        crate::NativeMessagesRejection::GenericMessageOwnerShape,
    ))
}

impl crate::symmetric::memory::RetainedStorage for DataCall {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        self.bytes.retain_credits(retained)?;
        self.signature.retain_credits(retained)?;
        Ok(())
    }
}

impl crate::symmetric::memory::RetainedStorage for SignatureOutput {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        self.bytes.retain_credits(retained)?;
        Ok(())
    }
}

impl crate::symmetric::memory::RetainedStorage for Parameters {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        self.graph.retain_credits(retained)?;
        Ok(())
    }
}

impl crate::symmetric::memory::RetainedStorage for ReleasedInput {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        self.call.retain_credits(retained)?;
        self.output.retain_credits(retained)?;
        Ok(())
    }
}

impl crate::symmetric::memory::RetainedStorage for Message {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        self.begin.retain_credits(retained)?;
        self.parts.retain_credits(retained)?;
        self.output.retain_credits(retained)?;
        self._metadata.retain_credits(retained)?;
        Ok(())
    }
}

impl crate::symmetric::memory::RetainedStorage for NativeMessageOperation {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        self.binding.retain_credits(retained)?;
        self.initialization.retain_credits(retained)?;
        self.phase.retain_credits(retained)?;
        self.messages.retain_credits(retained)?;
        self.released.retain_credits(retained)?;
        self._metadata.retain_credits(retained)?;
        Ok(())
    }
}

impl crate::symmetric::memory::RetainedStorage for MessageOutput {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        match self {
            Self::Sign(output) => output.retain_credits(retained),
            Self::Verify { .. } => Ok(()),
        }
    }
}

impl crate::symmetric::memory::RetainedStorage for Phase {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        match self {
            Self::Data(call) | Self::Capacity { call, .. } => call.retain_credits(retained),
            Self::Init
            | Self::Ready
            | Self::Begin(_)
            | Self::Receive(_)
            | Self::Final
            | Self::Complete => Ok(()),
        }
    }
}
