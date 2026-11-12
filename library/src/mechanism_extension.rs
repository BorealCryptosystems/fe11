// SPDX-License-Identifier: Apache-2.0
//! Explicit ABI contracts for mechanisms without a complete typed representation.
use crate::{Error, Result};
use fe11_sys::{
    CKM_HSS, CKM_X2RATCHET_DECRYPT, CKM_X2RATCHET_ENCRYPT, CKM_XMSS, CKM_XMSSMT, CK_MECHANISM_TYPE,
};
use std::sync::{Arc, Weak};

pub(crate) mod graph;
pub(crate) mod message;
pub(crate) mod nested;
pub(crate) mod operation;
pub(crate) mod parameter_keys;
pub(crate) mod transport;
pub(crate) use graph::{GraphStorage, OwnedGraph};

/// Function tuple covered by a mechanism contract. A declaration for one route
/// never authorizes another function or an automatic fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtensionOperation {
    /// One C_GenerateKey call with one native object and declared parameter outputs.
    GenerateKey,
    /// One C_GenerateKeyPair call with two native objects and parameter outputs.
    GenerateKeyPair,
    /// MessageSignInit, SignMessage, MessageSignFinal.
    SignMessage,
    /// MessageSignInit, SignMessageBegin/Next, MessageSignFinal.
    SignMessageMultipart,
    /// MessageVerifyInit, VerifyMessage, MessageVerifyFinal.
    VerifyMessage,
    /// MessageVerifyInit, VerifyMessageBegin/Next, MessageVerifyFinal.
    VerifyMessageMultipart,
    /// C_EncryptInit followed by one C_Encrypt with an actual output buffer.
    Encrypt,
    /// C_EncryptInit, exact Update fragments, then C_EncryptFinal.
    EncryptMultipart,
    /// C_DecryptInit followed by one C_Decrypt; output is withheld until success.
    Decrypt,
    /// C_DecryptInit, exact Update fragments, then C_DecryptFinal.
    DecryptMultipart,
    /// C_SignInit followed by one C_Sign.
    Sign,
    /// C_SignRecoverInit followed by C_SignRecover.
    SignRecover,
    /// C_SignInit, explicitly supplied C_SignUpdate calls, then C_SignFinal.
    SignMultipart,
    /// C_VerifyInit followed by one C_Verify with the supplied signature.
    Verify,
    /// C_VerifyRecoverInit followed by C_VerifyRecover.
    VerifyRecover,
    /// C_VerifyInit, explicitly supplied C_VerifyUpdate calls, then C_VerifyFinal.
    VerifyMultipart,
    /// PKCS#11 3.2 signature-bearing Init, followed by C_VerifySignature.
    VerifySignature,
    /// Signature-bearing Init, explicit Updates, then C_VerifySignatureFinal.
    VerifySignatureMultipart,
    /// C_DigestInit followed by one C_Digest.
    Digest,
    /// C_DigestInit, exact Update fragments, then C_DigestFinal.
    DigestMultipart,
    /// One C_WrapKey call with a caller-sized output buffer.
    WrapKey,
    /// One C_UnwrapKey call creating exactly one object.
    UnwrapKey,
    /// PKCS#11 3.2 C_EncapsulateKey, creating one key and bounded ciphertext.
    EncapsulateKey,
    /// PKCS#11 3.2 C_DecapsulateKey, creating one key from exact ciphertext.
    DecapsulateKey,
    /// C_DeriveKey creating exactly one object, with optional declared byte outputs.
    DeriveKey,
}

/// Provenance of a representation, not a normative or capability verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MechanismLayoutProvenance {
    /// Representation explicitly asserted by the integrator under an unsafe contract.
    CallerAssertedLayout,
    /// Owned representation constructed by Fe11 from its typed standard inputs.
    StandardLayout,
}

/// An integrator assertion bound to one live Module and its immutable selected
/// interface. Reloading even the same binary requires a new declaration.
#[derive(Clone)]
pub struct MechanismExtension {
    owner: Weak<crate::module::Inner>,
    mechanism: CK_MECHANISM_TYPE,
    operation: ExtensionOperation,
    edition: (u8, u8),
    mutates_key: bool,
    provenance: MechanismLayoutProvenance,
}
impl MechanismExtension {
    pub(crate) fn native_mechanism(&self) -> CK_MECHANISM_TYPE {
        self.mechanism
    }

    /// Exact native mechanism identifier, without a discovery claim.
    pub fn mechanism_number(&self) -> u64 {
        self.mechanism as u64
    }
    /// Exact operation authorized by the declaration.
    pub fn operation(&self) -> ExtensionOperation {
        self.operation
    }
    /// Constants/specification edition explicitly selected by the integrator.
    pub fn constants_edition(&self) -> (u8, u8) {
        self.edition
    }
    /// The representation is caller asserted, including for a standard identifier.
    pub fn provenance(&self) -> MechanismLayoutProvenance {
        self.provenance
    }
    pub(crate) fn check(
        &self,
        inner: &Arc<crate::module::Inner>,
        operation: ExtensionOperation,
    ) -> Result<()> {
        if !Weak::ptr_eq(&self.owner, &Arc::downgrade(inner)) || self.operation != operation {
            return Err(Error::Rejected(
                crate::RejectionReason::MechanismExtensions(
                    crate::MechanismExtensionsRejection::MechanismExtensionModuleFunctionMismatch,
                ),
            ));
        }
        Ok(())
    }
    pub(crate) fn standard(
        inner: &Arc<crate::module::Inner>,
        mechanism: CK_MECHANISM_TYPE,
        operation: ExtensionOperation,
    ) -> Self {
        Self {
            owner: Arc::downgrade(inner),
            mechanism,
            operation,
            edition: (3, 2),
            mutates_key: false,
            provenance: MechanismLayoutProvenance::StandardLayout,
        }
    }
    /// Preserve an ABI assertion already carried by a typed unsafe parameter.
    /// This changes provenance only; it grants no new native capability.
    pub(crate) fn with_asserted_layout(mut self) -> Self {
        self.provenance = MechanismLayoutProvenance::CallerAssertedLayout;
        self
    }
    pub(crate) fn with_nested_contract(mut self, nested: &Self) -> Self {
        self.mutates_key |= nested.mutates_key();
        if nested.provenance == MechanismLayoutProvenance::CallerAssertedLayout {
            self.provenance = MechanismLayoutProvenance::CallerAssertedLayout;
        }
        self
    }
    pub(crate) fn mutates_key(&self) -> bool {
        // PKCS#11 3.2 X2RATCHET effects cannot be weakened by a declaration.
        self.mutates_key
            || matches!(
                self.mechanism,
                CKM_X2RATCHET_ENCRYPT | CKM_X2RATCHET_DECRYPT
            )
            || (matches!(
                self.operation,
                ExtensionOperation::Sign
                    | ExtensionOperation::SignMultipart
                    | ExtensionOperation::SignMessage
                    | ExtensionOperation::SignMessageMultipart
            ) && matches!(
                self.mechanism,
                CKM_HSS
                    | CKM_XMSS
                    | CKM_XMSSMT
                    | fe11_sys::CKM_SECURID
                    | fe11_sys::CKM_HOTP
                    | fe11_sys::CKM_ACTI
            ))
    }
}
impl crate::Module {
    /// Declare a mechanism representation for this module and one exact route.
    /// The identifier may be standard with an incomplete published contract.
    /// No native call, provider-name rule or ABI discovery occurs here.
    ///
    /// # Safety
    /// The caller must establish the complete ABI for this module instance,
    /// its selected interface, constants edition, operation, current OS,
    /// architecture, calling convention and CK_ULONG width. Every request used
    /// with the declaration must match that contract: sizes, alignment, packing,
    /// scalar validity, NULL/length rules, pointer graph, capacities, aliases,
    /// input/output directions and termination/effects. Flat bytes must contain
    /// no pointer, even encoded as an integer; all pointers must be declared as
    /// graph relocations to owned blocks. Native code must respect these extents,
    /// initialize every byte claimed as output and obey the selected PKCS#11
    /// function's retention/termination rules. Unknown/PENDING returns retain
    /// storage, but cannot make a false assertion memory safe. No module may
    /// retain references after the established sequence has terminated.
    ///
    /// Set `mutates_key` for any mechanism that may alter its input key, even
    /// on refusal. Known Ratchet effects are enforced independently. Coordination
    /// with other libraries/processes remains the application's responsibility.
    /// DeriveKey asserts exactly one new object. Declared auxiliary byte outputs
    /// are allowed; hidden object handles or unrepresented object creation are
    /// not. Use a typed multi-output derivation for additional object outputs. This declaration grants
    /// no claim of normative correctness, support or cryptographic suitability.
    pub unsafe fn declare_mechanism_extension(
        &self,
        mechanism: u64,
        constants_edition: (u8, u8),
        operation: ExtensionOperation,
        mutates_key: bool,
    ) -> Result<MechanismExtension> {
        let mechanism = CK_MECHANISM_TYPE::try_from(mechanism).map_err(|_| {
            Error::Rejected(crate::RejectionReason::MechanismExtensions(
                crate::MechanismExtensionsRejection::ExtensionMechanismAbiWidth,
            ))
        })?;
        if matches!(
            operation,
            ExtensionOperation::Digest | ExtensionOperation::DigestMultipart
        ) && mutates_key
        {
            return Err(Error::Rejected(
                crate::RejectionReason::MechanismExtensions(
                    crate::MechanismExtensionsRejection::DigestExtensionHasNoKey,
                ),
            ));
        }
        if (mechanism == CKM_X2RATCHET_ENCRYPT
            && !matches!(
                operation,
                ExtensionOperation::Encrypt | ExtensionOperation::WrapKey
            ))
            || (mechanism == CKM_X2RATCHET_DECRYPT
                && !matches!(
                    operation,
                    ExtensionOperation::Decrypt | ExtensionOperation::UnwrapKey
                ))
        {
            return Err(Error::Rejected(
                crate::RejectionReason::MechanismExtensions(
                    crate::MechanismExtensionsRejection::RatchetMechanismFunctionMismatch,
                ),
            ));
        }
        Ok(MechanismExtension {
            owner: Arc::downgrade(&self.inner),
            mechanism,
            operation,
            edition: constants_edition,
            mutates_key,
            provenance: MechanismLayoutProvenance::CallerAssertedLayout,
        })
    }
}

/// Native access to a block. All owned blocks are erased, irrespective of their
/// declared sensitivity; the library does not rely on a caller's secret label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtensionDirection {
    /// The complete block, including all pointer relocations, must be unchanged.
    Input,
    /// Writable native storage. Only explicitly declared output regions escape.
    Output,
    /// Initialized input/output storage, with pointers still immutable.
    InOut,
}
/// One pointer-free initialized block. Pointer fields in `initial` must be zero
/// placeholders covered by a relocation; no native pointer is accepted here.
pub struct ExtensionBlock<'a> {
    /// Exact initial bytes; length is the exact logical native allocation size.
    pub initial: &'a [u8],
    /// ABI alignment, a power of two; Fe11 also satisfies pointer/CK_ULONG alignment.
    pub alignment: usize,
    /// Native read/write contract.
    pub direction: ExtensionDirection,
}
/// An owned target for a pointer field, including explicit NULL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtensionPointerTarget {
    /// Write a native null pointer.
    Null,
    /// Point into one owned block. Offset equal to its length permits an empty span.
    Block {
        /// Index into the request's owned block array.
        block: usize,
        /// Byte offset within that block; checked against its declared extent.
        offset: usize,
    },
}
/// Replace one pointer placeholder with an address derived solely from an owner.
/// Unaligned fields are supported for explicitly asserted packed ABIs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtensionPointer {
    /// Block containing the pointer field.
    pub block: usize,
    /// Byte offset of a native pointer-width field; overlapping fields are rejected.
    pub offset: usize,
    /// Exact owned referent or NULL.
    pub target: ExtensionPointerTarget,
}
/// Length of a declared output region after successful terminal completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtensionOutputLength {
    /// The contract guarantees that all `capacity` bytes are valid on success.
    Fixed,
    /// Read one native-endian CK_ULONG from an owned block, bounded by capacity.
    NativeUnsigned {
        /// Index into the request's owned block array.
        block: usize,
        /// Byte offset within that block; checked against its declared extent.
        offset: usize,
    },
}
/// Only these ranges can be published; pointer fields can never be exported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtensionOutputRegion {
    /// Owned block containing output bytes.
    pub block: usize,
    /// Beginning of the region in that block.
    pub offset: usize,
    /// Maximum output bytes, chosen from the actual asserted ABI.
    pub capacity: usize,
    /// Fixed extent or explicit native length field.
    pub length: ExtensionOutputLength,
}
/// Borrowed construction recipe copied before any native access. `None` is a
/// NULL mechanism parameter; a present empty root remains non-NULL with length 0.
#[derive(Clone, Copy)]
pub struct ExtensionParameters<'a> {
    /// Owned allocations, including the parameter root and all nested referents.
    pub blocks: &'a [ExtensionBlock<'a>],
    /// Pointer fields constructed after all allocations have stable addresses.
    pub pointers: &'a [ExtensionPointer],
    /// Root block for CK_MECHANISM.pParameter, or None for NULL/0.
    pub root: Option<usize>,
    /// Explicit output extents, published only after successful completion.
    pub outputs: &'a [ExtensionOutputRegion],
}
/// Exact declaration and parameter recipe; neither implies native support.
#[derive(Clone, Copy)]
pub struct ExtensionRequest<'a> {
    /// Module/function-bound ABI assertion.
    pub(crate) contract: &'a MechanismExtension,
    /// Owned graph recipe conforming to that assertion.
    pub(crate) parameters: ExtensionParameters<'a>,
}
impl<'a> ExtensionRequest<'a> {
    /// Bind this exact graph to an established module/function ABI.
    ///
    /// # Safety
    /// The caller must verify that every block, scalar, pointer relocation,
    /// extent, access direction and output-length field of `parameters` matches
    /// `contract` for this request's actual inputs. Fe11 checks ownership/ranges,
    /// not the meaning of opaque bytes. No encoded pointer may remain in initial
    /// bytes. Native code must not write outside declared writable storage or
    /// retain it past the function sequence's established completion. This
    /// per-request assertion is required even with a previously declared ABI.
    pub unsafe fn new(
        contract: &'a MechanismExtension,
        parameters: ExtensionParameters<'a>,
    ) -> Self {
        Self {
            contract,
            parameters,
        }
    }
}
/// Native output and auxiliary parameter outputs, with memory credit retained.
/// No Debug/Clone leaks or silently duplicates secret storage.
pub struct ExtensionResult {
    pub(crate) bytes: crate::symmetric::memory::Buffer,
    pub(crate) native_output_origin: usize,
    pub(crate) parameters: OwnedGraph,
    pub(crate) provenance: MechanismLayoutProvenance,
}
impl ExtensionResult {
    /// Returned cipher/signature/digest bytes. Empty for successful verification.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
    /// A declared auxiliary output; None means an invalid output index.
    pub fn parameter_output(&self, index: usize) -> Option<&[u8]> {
        self.parameters.output(index)
    }
    /// Representation provenance, established by construction rather than success.
    pub fn provenance(&self) -> MechanismLayoutProvenance {
        self.provenance
    }
}

/// Data route for one asserted native operation. Output capacities are allocation
/// ceilings chosen by the caller, not required execution sizes or crypto policy.
pub enum ExtensionInput<'a> {
    /// Exact multipart digest route; no fragment substitution or retry.
    DigestMultipart {
        /// Ordered fragments, including explicit empty Updates.
        parts: &'a [&'a [u8]],
        /// Total output storage selected by the caller.
        output_capacity: usize,
    },

    /// Exact multipart encrypt route; no fragment substitution or retry.
    EncryptMultipart {
        /// Native key bound to the session and module.
        key: &'a crate::NativeObjectRef,
        /// Ordered fragments, including explicit empty Updates.
        parts: &'a [&'a [u8]],
        /// Total output storage selected by the caller.
        output_capacity: usize,
    },

    /// Exact multipart decrypt route; no fragment substitution or retry.
    DecryptMultipart {
        /// Native key bound to the session and module.
        key: &'a crate::NativeObjectRef,
        /// Ordered fragments, including explicit empty Updates.
        parts: &'a [&'a [u8]],
        /// Total output storage selected by the caller.
        output_capacity: usize,
    },

    /// PKCS#11 3.2 verification with the signature supplied at Init.
    VerifySignature {
        /// Native object reference used by this operation; its module/session binding is preserved.
        key: &'a crate::NativeObjectRef,

        /// Exact input bytes for the selected native operation, copied before dispatch.
        input: &'a [u8],

        /// Exact signature bytes supplied to native verification.
        signature: &'a [u8],
    },
    /// PKCS#11 3.2 multipart verification with the signature retained from Init.
    VerifySignatureMultipart {
        /// Native object reference used by this operation; its module/session binding is preserved.
        key: &'a crate::NativeObjectRef,

        /// Ordered input chunks; their boundaries are preserved in native Update calls.
        parts: &'a [&'a [u8]],

        /// Exact signature bytes supplied to native verification.
        signature: &'a [u8],
    },
    /// Signature with message recovery, using exactly the native recovery functions.
    SignRecover {
        /// Native object reference used by this operation; its module/session binding is preserved.
        key: &'a crate::NativeObjectRef,

        /// Exact input bytes for the selected native operation, copied before dispatch.
        input: &'a [u8],

        /// Caller-selected maximum output bytes; no automatic size probe or retry.
        output_capacity: usize,
    },
    /// Verify and recover the signed message into bounded owned output.
    VerifyRecover {
        /// Native object reference used by this operation; its module/session binding is preserved.
        key: &'a crate::NativeObjectRef,

        /// Exact signature bytes supplied to native verification.
        signature: &'a [u8],

        /// Caller-selected maximum output bytes; no automatic size probe or retry.
        output_capacity: usize,
    },
    /// Sign with explicit C_SignUpdate calls preserving the caller's chunks.
    SignMultipart {
        /// Native object reference used by this operation; its module/session binding is preserved.
        key: &'a crate::NativeObjectRef,

        /// Ordered input chunks; their boundaries are preserved in native Update calls.
        parts: &'a [&'a [u8]],

        /// Caller-selected maximum output bytes; no automatic size probe or retry.
        output_capacity: usize,
    },
    /// Verify with explicit C_VerifyUpdate calls and one C_VerifyFinal.
    VerifyMultipart {
        /// Native object reference used by this operation; its module/session binding is preserved.
        key: &'a crate::NativeObjectRef,

        /// Ordered input chunks; their boundaries are preserved in native Update calls.
        parts: &'a [&'a [u8]],

        /// Exact signature bytes supplied to native verification.
        signature: &'a [u8],
    },
    /// Encrypt exactly these bytes, without automatic chunking or retries.
    Encrypt {
        /// Native object reference used by this operation; its module/session binding is preserved.
        key: &'a crate::NativeObjectRef,

        /// Exact input bytes for the selected native operation, copied before dispatch.
        input: &'a [u8],

        /// Caller-selected maximum output bytes; no automatic size probe or retry.
        output_capacity: usize,
    },
    /// Decrypt and withhold all plaintext until native success.
    Decrypt {
        /// Native object reference used by this operation; its module/session binding is preserved.
        key: &'a crate::NativeObjectRef,

        /// Exact input bytes for the selected native operation, copied before dispatch.
        input: &'a [u8],

        /// Caller-selected maximum output bytes; no automatic size probe or retry.
        output_capacity: usize,
    },
    /// Sign exactly these bytes; Fe11 performs no implicit prehash.
    Sign {
        /// Native object reference used by this operation; its module/session binding is preserved.
        key: &'a crate::NativeObjectRef,

        /// Exact input bytes for the selected native operation, copied before dispatch.
        input: &'a [u8],

        /// Caller-selected maximum output bytes; no automatic size probe or retry.
        output_capacity: usize,
    },
    /// Verify the supplied signature against the exact input.
    Verify {
        /// Native object reference used by this operation; its module/session binding is preserved.
        key: &'a crate::NativeObjectRef,

        /// Exact input bytes for the selected native operation, copied before dispatch.
        input: &'a [u8],

        /// Exact signature bytes supplied to native verification.
        signature: &'a [u8],
    },
    /// Digest without a key or implicit algorithm replacement.
    Digest {
        /// Exact input bytes for the selected native operation, copied before dispatch.
        input: &'a [u8],

        /// Caller-selected maximum output bytes; no automatic size probe or retry.
        output_capacity: usize,
    },
}
impl crate::Session {
    /// Execute one caller-asserted operation. All input/parameter/output storage
    /// is admitted before native access; no output-length probe or retry occurs.
    /// A BUFFER_TOO_SMALL leaves its owner retained for explicit session closure;
    /// this route deliberately performs no replay of a possibly stateful call.
    ///
    /// Optional context authentication occurs once between Init and use. Native
    /// refusals are preserved. Stateful-key observations are invalidated before
    /// Init and are never revived after refusal; reacquire a fresh observation
    /// explicitly before further use. This exclusion covers this Fe11 instance,
    /// not independent libraries/processes. A failure after success is reported
    /// as OperationCompleted, without publishing partial output.
    pub fn execute_extension(
        &self,
        request: ExtensionRequest<'_>,
        input: ExtensionInput<'_>,
        limits: crate::InputLimits,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<ExtensionResult> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.execute_extension_with_diagnostics(
            request,
            input,
            limits,
            authentication,
            &mut extension_diagnostics,
        )
    }

    // Internal callers supply their outer publication owner; no helper
    // return may release the credit of an error still being projected.
    pub(crate) fn execute_extension_with_diagnostics(
        &self,
        request: ExtensionRequest<'_>,
        input: ExtensionInput<'_>,
        limits: crate::InputLimits,
        authentication: Option<crate::ContextAuthentication>,
        extension_diagnostics: &mut crate::mechanism_extension::operation::Invocation,
    ) -> Result<ExtensionResult> {
        operation::execute(
            self,
            request,
            input,
            limits,
            authentication,
            extension_diagnostics,
        )
    }
}
impl crate::AdvancedSession {
    /// Synchronous route through the same owner. No native asynchronous mode or hidden thread.
    pub fn execute_extension(
        &self,
        request: ExtensionRequest<'_>,
        input: ExtensionInput<'_>,
        limits: crate::InputLimits,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<ExtensionResult> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.session.execute_extension_with_diagnostics(
            request,
            input,
            limits,
            authentication,
            &mut extension_diagnostics,
        )
    }
}

/// A newly unwrapped object and any bounded mechanism-parameter outputs.
/// No byte from the wrapped blob is exposed as locally decrypted key material.
pub struct NativeUnwrappedObject {
    /// Native reference and optional descriptive observation, as for creation.
    pub object: crate::NativeObjectView,
    pub(crate) parameters: OwnedGraph,
    pub(crate) provenance: MechanismLayoutProvenance,
}
impl NativeUnwrappedObject {
    /// Mechanism-defined output region, available only after complete success.
    pub fn parameter_output(&self, index: usize) -> Option<&[u8]> {
        self.parameters.output(index)
    }
    /// Provenance of the native parameter representation used for this call.
    pub fn provenance(&self) -> MechanismLayoutProvenance {
        self.provenance
    }
}

/// Declared parameter outputs from a completed native mechanism invocation.
/// The aligned graph and its memory credit remain owned and erased on drop.
pub struct ExtensionParameterOutputs {
    pub(crate) graph: OwnedGraph,
    pub(crate) provenance: MechanismLayoutProvenance,
}
impl ExtensionParameterOutputs {
    /// Read a declared output region after all native extents were validated.
    pub fn output(&self, index: usize) -> Option<&[u8]> {
        self.graph.output(index)
    }
    /// The ABI assertion's provenance, without a capability or security verdict.
    pub fn provenance(&self) -> MechanismLayoutProvenance {
        self.provenance
    }
}
