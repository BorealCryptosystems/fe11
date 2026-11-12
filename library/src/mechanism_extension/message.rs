// SPDX-License-Identifier: Apache-2.0
//! Public message operands and whole-process facade over the shared stream owner.
use super::{ExtensionOperation, ExtensionRequest, MechanismLayoutProvenance};
use crate::Result;
pub(crate) mod initialization;

/// One Message data call. A parameter graph requires an explicit ABI assertion
/// for the same module, mechanism and message route as the initialization.
/// `None` passes NULL/0; it does not discover or select a provider layout.
#[derive(Clone, Copy)]
pub struct NativeMessagePart<'a> {
    /// Exact bytes, copied before the native data call.
    pub data: &'a [u8],
    /// Parameters for this call alone, owned through parent termination.
    pub parameters: Option<ExtensionRequest<'a>>,
}
/// One complete message inside an explicitly terminated native process.
pub enum NativeMessageRoute<'a> {
    /// One SignMessage or VerifyMessage call.
    Single(NativeMessagePart<'a>),
    /// Begin, zero or more intermediate Next calls, and one terminal Next.
    /// `last` is explicit even for an empty message; no data call is invented.
    Multipart {
        /// Parameters for Begin, independently of parameters for each Next.
        begin: Option<ExtensionRequest<'a>>,
        /// Intermediate parts, each passed with a NULL signature output/input.
        updates: &'a [NativeMessagePart<'a>],
        /// Last part, with the actual signature output/input.
        last: NativeMessagePart<'a>,
    },
}
/// Signature direction and storage. Capacities are caller allocation bounds;
/// the native module decides which signature size or algorithm is admissible.
pub enum NativeMessageAction<'a> {
    /// Produce a signature without a size query or a retry.
    Sign {
        /// Caller-selected maximum output bytes; no automatic size probe or retry.
        output_capacity: usize,
    },
    /// Verify these exact bytes; native refusal is returned unchanged.
    Verify {
        /// Exact signature bytes supplied to native verification.
        signature: &'a [u8],
    },
}
/// Owned outputs published only after the native parent has terminated.
/// Consumed data has already been erased by the stream owner. Result parameter
/// graphs and signatures remain owned and erased on drop. No Debug or Clone.
pub struct NativeMessageResult {
    body: crate::NativeMessageResults,
}
impl NativeMessageResult {
    pub(crate) fn from_messages(body: crate::NativeMessageResults) -> Result<Self> {
        if body.len() != 1 {
            return Err(crate::Error::Rejected(
                crate::RejectionReason::MechanismExtensions(
                    crate::MechanismExtensionsRejection::SingleMessageFacadeResultShape,
                ),
            ));
        }
        Ok(Self { body })
    }
    /// Signature bytes, or an empty slice after successful verification.
    pub fn as_bytes(&self) -> &[u8] {
        self.body.signature(0).unwrap_or(&[])
    }
    /// Output from the initialization mechanism's graph.
    pub fn parameter_output(&self, index: usize) -> Option<&[u8]> {
        self.body.parameter_output(index)
    }
    /// Output from the multipart Begin graph (absent for a single call).
    pub fn begin_parameter_output(&self, index: usize) -> Option<&[u8]> {
        self.body.begin_parameter_output(0, index)
    }
    /// Output from a data call's graph, in input order.
    pub fn part_parameter_output(&self, part: usize, index: usize) -> Option<&[u8]> {
        self.body.part_parameter_output(0, part, index)
    }
    /// Caller assertion propagates from any per-call or initialization graph.
    pub fn provenance(&self) -> MechanismLayoutProvenance {
        self.body.provenance()
    }
}

pub(crate) fn execute<'a>(
    session: &crate::Session,
    request: impl Into<super::graph::recipe::Request<'a>>,
    key: &crate::NativeObjectRef,
    route: NativeMessageRoute<'_>,
    action: NativeMessageAction<'_>,
    limits: crate::InputLimits,
    authentication: Option<crate::ContextAuthentication>,
    parameter_keys: super::parameter_keys::ParameterKeys<'_>,
    root: &mut crate::advanced::NativeMessageInvocation,
) -> Result<NativeMessageResult> {
    crate::advanced::execute_native_message(
        session,
        request.into(),
        key,
        route,
        action,
        limits,
        authentication,
        parameter_keys,
        root,
    )
}

pub(crate) fn operation_kind(signing: bool, multipart: bool) -> ExtensionOperation {
    match (signing, multipart) {
        (true, false) => ExtensionOperation::SignMessage,
        (true, true) => ExtensionOperation::SignMessageMultipart,
        (false, false) => ExtensionOperation::VerifyMessage,
        (false, true) => ExtensionOperation::VerifyMessageMultipart,
    }
}
