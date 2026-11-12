// SPDX-License-Identifier: Apache-2.0
//! Caller-declared initialization for the GCM-compatible message interface.
use super::{initialization, InitBinding, MessageKey, Outputs};
use crate::mechanism_extension::OwnedGraph;
use crate::{
    AdvancedSession, Error, ExtensionParameters, MechanismLayoutProvenance, MessageRoute, Module,
    NativeObjectRef, OperationProgress, OperationTicket, Result, Session,
};
use fe11_sys::{CK_MECHANISM, CK_MECHANISM_TYPE, CK_ULONG, CK_VOID_PTR};
use std::sync::{Arc, Weak};

/// An explicit initialization ABI for one module, direction and message route.
/// Subsequent calls use the standard CK_GCM_MESSAGE_PARAMS representation.
/// This declaration is not an observation of native support or a certification.
#[derive(Clone)]
pub struct GcmMessageExtension {
    owner: Weak<crate::module::Inner>,
    pub(super) mechanism: CK_MECHANISM_TYPE,
    pub(super) route: MessageRoute,
    pub(super) decrypt: bool,
}

impl Module {
    /// Declare a GCM-compatible message mechanism with independently owned Init
    /// parameters. Neither loading nor discovery guesses this representation.
    ///
    /// # Safety
    /// The caller must establish the selected module's complete ABI and native
    /// semantics for this identifier and direction (`decrypt` selects decryption).
    /// The declaration establishes the Init ABI and allowed graph representation.
    /// Each begin call additionally asserts the validity of its actual parameters. No hidden pointer may
    /// be encoded as scalar bytes. Parameters may remain borrowed until parent
    /// Final, but not after established termination. The key is read-only.
    ///
    /// Message calls must implement the CK_GCM_MESSAGE_PARAMS ABI and GCM message
    /// semantics: separate tag, equal total input/output data lengths, IV generator
    /// rules, authentication failures and PKCS#11 continuation/termination rules.
    /// Memory writes must stay inside supplied extents. This contract does not
    /// assert native availability; a refusal is returned without fallback.
    /// Other per-message ABIs require their own representation, not a cast.
    pub unsafe fn declare_gcm_message_extension(
        &self,
        mechanism: u64,
        route: MessageRoute,
        decrypt: bool,
    ) -> Result<GcmMessageExtension> {
        let mechanism = CK_MECHANISM_TYPE::try_from(mechanism).map_err(|_| {
            Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::MessageExtensionMechanismAbiWidth,
            ))
        })?;
        let _state = self.inner.read()?;
        Ok(GcmMessageExtension {
            owner: Arc::downgrade(&self.inner),
            mechanism,
            route,
            decrypt,
        })
    }
}

impl GcmMessageExtension {
    pub(super) fn check(&self, session: &Session) -> Result<()> {
        if !self.owner.ptr_eq(&Arc::downgrade(&session.inner)) {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::ForeignGcmMessageDeclaration,
            )));
        }
        Ok(())
    }

    /// Exact identifier supplied to MessageEncryptInit/MessageDecryptInit.
    pub fn mechanism_number(&self) -> u64 {
        self.mechanism as u64
    }
}

pub(super) struct DeclaredInit {
    pub(super) contract: GcmMessageExtension,
    graph: OwnedGraph,
    pointer: CK_VOID_PTR,
    length: CK_ULONG,
    // Admitted by initialization with the operation metadata, before Init.
    // A failed final projection transfers this leaf to the public error.
    completion_diagnostic: Option<crate::error::CompletionStorage>,
}

impl DeclaredInit {
    pub(super) fn new(
        contract: GcmMessageExtension,
        mut graph: OwnedGraph,
        completion_diagnostic: crate::error::CompletionStorage,
    ) -> Self {
        let (pointer, length) = graph.projection();
        Self {
            contract,
            graph,
            pointer,
            length,
            completion_diagnostic: Some(completion_diagnostic),
        }
    }

    pub(super) fn bind(&self, mechanism: &mut CK_MECHANISM) {
        mechanism.mechanism = self.contract.mechanism;
        mechanism.pParameter = self.pointer;
        mechanism.ulParameterLen = self.length;
    }

    /// Parent Final defines the declared graph's output extents. Inspect them
    /// before crediting native termination; this does not publish the regions.
    pub(super) fn validate_output_bounds(&self) -> Result<()> {
        self.graph.validate_output_bounds()
    }

    pub(super) fn finish(&mut self) -> Result<()> {
        match self.graph.finish() {
            Ok(()) => Ok(()),
            Err(cause) => {
                let function = if self.contract.decrypt {
                    "C_MessageDecryptFinal"
                } else {
                    "C_MessageEncryptFinal"
                };
                self.completion_diagnostic
                    .take()
                    .expect("first declared GCM final projection failure")
                    .bind(function)
                    .finish(Err(cause))
            }
        }
    }

    pub(super) fn unchanged(&self, mechanism: &CK_MECHANISM) -> bool {
        mechanism.mechanism == self.contract.mechanism
            && mechanism.pParameter == self.pointer
            && mechanism.ulParameterLen == self.length
            && self.graph.unchanged()
    }
}

/// Results of a caller-declared GCM-compatible process, after parent termination.
/// Kept distinct from standard GCM results so caller assertion is never promoted
/// to a standard-layout or native-support verdict. No Debug or Clone for bytes.
pub struct DeclaredGcmMessage<'a> {
    /// Ciphertext when encrypting, plaintext when decrypting.
    pub data: &'a [u8],
    /// IV returned for this message.
    pub nonce: &'a [u8],
    /// Separate tag returned for this message.
    pub tag: &'a [u8],
    /// Number of meaningful tag bits.
    pub tag_bits: u64,
}

/// Owns completed message outputs and the independent Init parameter graph.
pub struct DeclaredGcmMessages {
    outputs: Outputs,
    contract: GcmMessageExtension,
    initialization: OwnedGraph,
}

impl DeclaredGcmMessages {
    /// Exact mechanism identifier used for the completed process.
    pub fn mechanism_number(&self) -> u64 {
        self.contract.mechanism_number()
    }

    /// Whether the native process decrypted its input.
    pub fn decrypting(&self) -> bool {
        self.contract.decrypt
    }

    /// Representation provenance; never a capability or security verdict.
    pub fn provenance(&self) -> MechanismLayoutProvenance {
        MechanismLayoutProvenance::CallerAssertedLayout
    }

    /// Number of submitted messages, including refused entries.
    pub fn len(&self) -> usize {
        self.outputs.entries.len()
    }

    /// Whether the parent completed without any submitted message.
    pub fn is_empty(&self) -> bool {
        self.outputs.entries.is_empty()
    }

    /// Completed ciphertext or plaintext with associated IV and tag. Refused
    /// entries have no readable bytes. A zero-bit tag provides no authentication.
    pub fn get(&self, index: usize) -> Option<DeclaredGcmMessage<'_>> {
        self.outputs
            .entries
            .get(index)
            .filter(|output| output.disposition.candidate())
            .map(|output| DeclaredGcmMessage {
                data: output.bytes.as_slice(),
                nonce: output.nonce.as_slice(),
                tag: output.tag.as_slice(),
                tag_bits: output.tag_bits,
            })
    }

    /// Exact native refusal associated with a submitted message.
    pub fn rejection(&self, index: usize) -> Option<crate::MessageAeadRejection> {
        self.outputs
            .entries
            .get(index)
            .and_then(|output| output.disposition.rejection())
    }

    /// A declared output region of the independent Init graph. Pointer fields
    /// never escape through this projection. Storage is erased on release.
    pub fn initialization_output(&self, index: usize) -> Option<&[u8]> {
        self.initialization.output(index)
    }
}

pub(super) fn result(outputs: Outputs, initialization: DeclaredInit) -> OperationProgress {
    // The live descriptor cache has no purpose after established termination.
    // Discard its raw pointer; the completed graph owns only Send allocations,
    // so the public result keeps automatic Send without a new unsafe impl.
    let DeclaredInit {
        contract, graph, ..
    } = initialization;
    OperationProgress::DeclaredGcmMessages(DeclaredGcmMessages {
        outputs,
        contract,
        initialization: graph,
    })
}

fn start(
    session: &Session,
    key: &NativeObjectRef,
    contract: &GcmMessageExtension,
    parameters: ExtensionParameters<'_>,
    capture: bool,
) -> Result<OperationTicket> {
    contract.check(session)?;
    initialization::start_declared(
        session,
        MessageKey::Native(key),
        contract,
        parameters,
        capture,
    )
}

impl Session {
    /// Begin a declared GCM-compatible process. Init parameters are independent
    /// of every message's standard GCM parameters and can include declared output
    /// regions. Use poll_aead, then the existing submit/begin/update/finish APIs.
    /// State capture/export is unsupported for this declared representation; it
    /// is never serialized as a standard GCM mechanism. Standard paths are unchanged.
    ///
    /// # Safety
    /// For this request, every scalar, block, alignment, extent, relocation and
    /// output-length field in `parameters` must satisfy `contract` and the native
    /// module ABI. No pointer may be hidden in scalar bytes. The module must not
    /// access outside declared storage or retain it beyond parent termination.
    /// A mechanism declaration alone does not validate this particular graph.
    pub unsafe fn begin_gcm_extension_message_stream(
        &self,
        key: &NativeObjectRef,
        contract: &GcmMessageExtension,
        parameters: ExtensionParameters<'_>,
    ) -> Result<OperationTicket> {
        start(self, key, contract, parameters, false)
    }
}

impl AdvancedSession {
    /// Begin the same declared process with this session's validation-capture
    /// choice. Use poll and the existing caller-fed AEAD message operations.
    ///
    /// # Safety
    /// For this request, every scalar, block, alignment, extent, relocation and
    /// output-length field in `parameters` must satisfy `contract` and the native
    /// module ABI. No pointer may be hidden in scalar bytes. The module must not
    /// access outside declared storage or retain it beyond parent termination.
    /// A mechanism declaration alone does not validate this particular graph.
    pub unsafe fn begin_gcm_extension_message_stream(
        &self,
        key: &NativeObjectRef,
        contract: &GcmMessageExtension,
        parameters: ExtensionParameters<'_>,
    ) -> Result<OperationTicket> {
        start(
            &self.session,
            key,
            contract,
            parameters,
            self.validation_capture == crate::ValidationCaptureMode::Capture,
        )
    }
}

pub(super) fn ensure_standard(init: &InitBinding) -> Result<()> {
    match init {
        InitBinding::Declared(_) => {
            Err(Error::Unsupported(crate::UnsupportedReason::AeadMessages(
                crate::AeadMessagesUnsupported::DeclaredGcmMessageStateCapture,
            )))
        }
        _ => Ok(()),
    }
}

impl crate::symmetric::memory::RetainedStorage for DeclaredInit {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        self.graph.retain_credits(retained)?;
        Ok(())
    }
}
