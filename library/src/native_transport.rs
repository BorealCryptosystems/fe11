// SPDX-License-Identifier: Apache-2.0
//! Native key transport with explicit standard parameter layouts.
use crate::mechanism_extension::parameter_keys::{ParameterKey, ParameterKeys};
use crate::symmetric::gcm_legacy::GcmWithoutIvBits;
use crate::{
    mechanism_extension::{self, MechanismExtension},
    Error, ExtensionBlock, ExtensionDirection, ExtensionOperation, ExtensionOutputLength,
    ExtensionOutputRegion, ExtensionParameters, ExtensionPointer, ExtensionPointerTarget,
    ExtensionRequest, ExtensionResult, GenerationTemplate, ManagedClass, NativeObjectRef,
    NativeUnwrappedObject, Result, Session,
};
use fe11_sys::*;
use std::mem::{align_of, offset_of, size_of};

/// Closed standard mechanism selection for absent or fixed byte parameters.
/// This specifies the ABI, not native support, permissions or algorithm policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeTransportMechanism {
    kind: CK_MECHANISM_TYPE,
    bytes: usize,
    optional: bool,
}

/// Exact OAEP scalars and optional source bytes. No hash, MGF, label or key-size
/// policy is imposed. `None` and a present empty source retain distinct pointers.
#[derive(Clone, Copy)]
pub struct NativeOaepParameters<'a> {
    /// Native hash mechanism identifier.
    pub hash: u64,
    /// Native mask generation function identifier.
    pub mgf: u64,
    /// Native source selector, normally CKZ_DATA_SPECIFIED.
    pub source: u64,
    /// Exact source data; copied into the retained graph.
    pub data: Option<&'a [u8]>,
}

/// Historical private wrapping inputs. P and G share one native length, so
/// their allocated spans must agree; no mathematical relation is checked.
pub struct NativeSkipjackPrivate<'a> {
    /// Exact password bytes, copied and erased by the native owner.
    pub password: &'a [u8],
    /// Exact public data for this wrapping context.
    pub public_data: &'a [u8],
    /// Exact random bytes for this wrapping context.
    pub random: &'a [u8],
    /// P encoded as the native mechanism expects.
    pub prime: &'a [u8],
    /// G encoded in the same number of bytes as P.
    pub base: &'a [u8],
    /// Q encoded as the native mechanism expects.
    pub subprime: &'a [u8],
}
/// Historical relay input, preserving old and new wrapping contexts verbatim.
pub struct NativeSkipjackRelay<'a> {
    /// Previously wrapped private-key blob.
    pub wrapped: &'a [u8],
    /// Password of the original wrapping context.
    pub old_password: &'a [u8],
    /// Public data of the original wrapping context.
    pub old_public_data: &'a [u8],
    /// Random data of the original wrapping context.
    pub old_random: &'a [u8],
    /// Password of the destination wrapping context.
    pub new_password: &'a [u8],
    /// Public data of the destination wrapping context.
    pub new_public_data: &'a [u8],
    /// Random data of the destination wrapping context.
    pub new_random: &'a [u8],
}

/// Layouts shared by encryption and target-key transport. Targetless relay uses
/// `Session::relay_skipjack_key` and its separate `NativeSkipjackRelay` recipe.
/// Layout selection is explicit. In particular a PKCS#11 3.2 wrapping structure
/// is not substituted for a historical encryption structure or a Message ABI.
pub enum NativeTransportParameters<'a> {
    /// Absent or fixed byte parameter. The selected ABI checks only its extent.
    Fixed {
        /// Exact fixed-layout mechanism selection.
        mechanism: NativeTransportMechanism,
        /// Exact parameter bytes, or an explicitly absent parameter.
        bytes: Option<&'a [u8]>,
    },
    /// CKM_RSA_PKCS_OAEP and CK_RSA_PKCS_OAEP_PARAMS.
    RsaOaep(NativeOaepParameters<'a>),
    /// CKM_RSA_AES_KEY_WRAP, retaining a nested OAEP structure.
    RsaAes {
        /// Requested temporary AES key size, in bits.
        aes_key_bits: u64,
        /// Exact nested OAEP tuple.
        oaep: NativeOaepParameters<'a>,
    },
    /// CKM_ECDH_AES_KEY_WRAP with caller-selected KDF and shared data.
    EcdhAes {
        /// Requested temporary AES key size, in bits.
        aes_key_bits: u64,
        /// Native key derivation function identifier.
        kdf: u64,
        /// Optional exact shared data; absent and present empty are distinct.
        shared: Option<&'a [u8]>,
    },
    /// CKM_ECDH_COF_AES_KEY_WRAP with the same native parameter structure.
    EcdhAesCofactor {
        /// Requested temporary AES key size, in bits.
        aes_key_bits: u64,
        /// Native key derivation function identifier.
        kdf: u64,
        /// Optional exact shared data; absent and present empty are distinct.
        shared: Option<&'a [u8]>,
    },
    /// CKM_ECDH_X_AES_KEY_WRAP with the same native parameter structure.
    EcdhAesMontgomery {
        /// Requested temporary AES key size, in bits.
        aes_key_bits: u64,
        /// Native key derivation function identifier.
        kdf: u64,
        /// Optional exact shared data; absent and present empty are distinct.
        shared: Option<&'a [u8]>,
    },
    /// Historical CKM_KEY_WRAP_SET_OAEP.
    SetOaep {
        /// Native block-contents byte.
        block_contents: u8,
        /// Optional extra SET data.
        extra: Option<&'a [u8]>,
    },
    /// CKM_GOSTR3410_KEY_WRAP, with its additional managed key retained.
    GostR3410 {
        /// Optional DER-encoded wrapping-parameter OID.
        oid: Option<&'a [u8]>,
        /// Optional user keying material.
        ukm: Option<&'a [u8]>,
        /// Additional key referenced by the mechanism, retained until completion.
        key: &'a NativeObjectRef,
    },
    /// RC2 ECB/CBC/CBC_PAD; scalar values are delegated to the module.
    Rc(crate::RcCipherParameters<'a>),
    /// CKM_AES_CTR with a complete initial counter block.
    AesCtr {
        /// Exact low-order counter width in bits, passed to the module.
        counter_bits: u64,
        /// Exact 16-byte initial block.
        counter_block: [u8; 16],
    },
    /// ChaCha20/Salsa20 native counter/nonce tuple, copied before dispatch.
    Stream(&'a crate::StreamCipherParameters),
    /// PKCS#11 3.2 CK_GCM_WRAP_PARAMS. A generated IV is parameter output 0.
    GcmWrap {
        /// Exact IV bytes, copied before native access.
        iv: &'a [u8],
        /// Number of high-order IV/nonce bits preserved by the native generator.
        fixed_bits: u64,
        /// Native generator identifier; no implicit generator is selected.
        generator: u64,
        /// Exact additional authenticated data; absent and present empty are distinct.
        aad: Option<&'a [u8]>,
        /// Authentication tag length, in bits.
        tag_bits: u64,
    },
    /// PKCS#11 3.2 CK_CCM_WRAP_PARAMS. A generated nonce is parameter output 0.
    CcmWrap {
        /// Native data-length field, in bytes; the caller selects its exact value.
        data_bytes: u64,
        /// Exact nonce bytes, copied before native access.
        nonce: &'a [u8],
        /// Number of high-order IV/nonce bits preserved by the native generator.
        fixed_bits: u64,
        /// Native generator identifier; no implicit generator is selected.
        generator: u64,
        /// Exact additional authenticated data; absent and present empty are distinct.
        aad: Option<&'a [u8]>,
        /// Authentication tag length, in bytes.
        mac_bytes: u64,
    },
    /// CK_GCM_PARAMS, retaining the explicit historical ulIvBits field.
    /// The caller must explicitly establish this historical wrapping ABI for
    /// the selected module/function. Success retains CallerAssertedLayout provenance.
    GcmClassic {
        /// Explicit unsafe module/function ABI assertion for historical wrapping.
        contract: &'a MechanismExtension,
        /// Exact IV bytes, copied before native access.
        iv: &'a [u8],
        /// Exact historical IV bit-length field; not silently recomputed.
        iv_bits: u64,
        /// Exact additional authenticated data; absent and present empty are distinct.
        aad: Option<&'a [u8]>,
        /// Authentication tag length, in bits.
        tag_bits: u64,
    },
    /// Historical GCM wrapping ABI without ulIvBits, explicitly asserted for
    /// this module and function; never selected through probing or fallback.
    GcmClassicWithoutIvBits {
        /// Per-module, per-function ABI assertion.
        contract: &'a MechanismExtension,
        /// Exact IV bytes.
        iv: &'a [u8],
        /// Exact AAD; absent and present empty remain distinct.
        aad: Option<&'a [u8]>,
        /// Appended tag length in bits.
        tag_bits: u64,
    },
    /// CK_CCM_PARAMS, without token nonce generation fields.
    CcmClassic {
        /// Explicit unsafe module/function ABI assertion for historical wrapping.
        contract: &'a MechanismExtension,
        /// Native data-length field, in bytes; the caller selects its exact value.
        data_bytes: u64,
        /// Exact nonce bytes, copied before native access.
        nonce: &'a [u8],
        /// Exact additional authenticated data; absent and present empty are distinct.
        aad: Option<&'a [u8]>,
        /// Authentication tag length, in bytes.
        mac_bytes: u64,
    },
    /// Historical CK_SKIPJACK_PRIVATE_WRAP_PARAMS.
    SkipjackPrivate(NativeSkipjackPrivate<'a>),
}

// Storage is bounded by the largest actual standard structure used below.
// Scalar serialization writes initialized bytes, never reads C-struct padding.
struct Recipe<'a> {
    root: [u8; size_of::<CK_SKIPJACK_RELAYX_PARAMS>()],
    nested: [u8; size_of::<CK_RSA_PKCS_OAEP_PARAMS>()],
    length: usize,
    raw_root: Option<Option<&'a [u8]>>,
    fields: [(usize, Option<&'a [u8]>, ExtensionDirection); 8],
    count: usize,
    nested_oaep: bool,
    source: Option<ParameterKey<'a>>,
    assertion: Option<&'a MechanismExtension>,
}

impl Session {
    /// Invoke C_WrapKey once, with owned standard parameters and an explicit
    /// output capacity. No local exportability/key-size policy or sizing replay.
    /// Generated wrapping IVs/nonces are available as parameter output 0.
    /// NativeOutputAndLocalFailure preserves a size refusal accompanied by an
    /// integrity failure. No partial output or automatic retry is provided.
    pub fn wrap_native_key(
        &self,
        wrapping_key: &crate::NativeObjectRef,
        target: &crate::NativeObjectRef,
        parameters: NativeTransportParameters<'_>,
        output_capacity: usize,
    ) -> Result<ExtensionResult> {
        let mut diagnostic = None;
        self.wrap_native_key_with_diagnostic(
            wrapping_key,
            target,
            parameters,
            output_capacity,
            &mut diagnostic,
        )
    }

    fn wrap_native_key_with_diagnostic(
        &self,
        wrapping_key: &crate::NativeObjectRef,
        target: &crate::NativeObjectRef,
        parameters: NativeTransportParameters<'_>,
        output_capacity: usize,
        diagnostic: &mut Option<crate::symmetric::memory::Credit>,
    ) -> Result<ExtensionResult> {
        let fixed_prefix =
            mechanism_extension::transport::fixed_prefix::from_transport(&parameters, 0)?;
        with_parameters(
            self,
            parameters,
            ExtensionOperation::WrapKey,
            |request, sources| {
                mechanism_extension::transport::wrap_with_fixed_prefix(
                    self,
                    request,
                    wrapping_key,
                    Some(target),
                    output_capacity,
                    sources,
                    fixed_prefix,
                    diagnostic,
                )
            },
        )
    }
    /// Invoke C_UnwrapKey with exact attributes and caller-selected observations.
    /// Native refusals remain errors; only a proven new object is a cleanup target.
    pub fn unwrap_native_key(
        &self,
        unwrapping_key: &crate::NativeObjectRef,
        blob: &[u8],
        parameters: NativeTransportParameters<'_>,
        class: ManagedClass,
        template: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<NativeUnwrappedObject>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.unwrap_native_key_selected(
            unwrapping_key,
            blob,
            parameters,
            class,
            template,
            &mut diagnostics,
        )
    }

    fn unwrap_native_key_selected(
        &self,
        unwrapping_key: &crate::NativeObjectRef,
        blob: &[u8],
        parameters: NativeTransportParameters<'_>,
        class: ManagedClass,
        template: GenerationTemplate<'_>,
        diagnostics: &mut crate::error::PreparedCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<NativeUnwrappedObject>> {
        with_parameters(
            self,
            parameters,
            ExtensionOperation::UnwrapKey,
            |request, sources| {
                self.unwrap_key_with_sources(
                    unwrapping_key,
                    blob,
                    request,
                    class,
                    template,
                    sources,
                    diagnostics,
                )
            },
        )
    }
}
impl crate::AdvancedSession {
    /// Synchronous native wrapping through the common owner.
    pub fn wrap_native_key(
        &self,
        wrapping_key: &crate::NativeObjectRef,
        target: &crate::NativeObjectRef,
        parameters: NativeTransportParameters<'_>,
        output_capacity: usize,
    ) -> Result<ExtensionResult> {
        let mut diagnostic = None;
        self.session.wrap_native_key_with_diagnostic(
            wrapping_key,
            target,
            parameters,
            output_capacity,
            &mut diagnostic,
        )
    }
    /// Synchronous native unwrapping through the common creation owner.
    pub fn unwrap_native_key(
        &self,
        unwrapping_key: &crate::NativeObjectRef,
        blob: &[u8],
        parameters: NativeTransportParameters<'_>,
        class: ManagedClass,
        template: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<NativeUnwrappedObject>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.session.unwrap_native_key_selected(
            unwrapping_key,
            blob,
            parameters,
            class,
            template,
            &mut diagnostics,
        )
    }
}

impl Session {
    /// Rewrap the blob embedded in the historical relay parameters. PKCS#11
    /// explicitly requires hKey=CK_INVALID_HANDLE for this mechanism; no
    /// fictitious target object or dummy managed reference is constructed.
    pub fn relay_skipjack_key(
        &self,
        wrapping_key: &crate::NativeObjectRef,
        parameters: NativeSkipjackRelay<'_>,
        output_capacity: usize,
    ) -> Result<ExtensionResult> {
        let mut diagnostic = None;
        self.relay_skipjack_key_with_diagnostic(
            wrapping_key,
            parameters,
            output_capacity,
            &mut diagnostic,
        )
    }

    fn relay_skipjack_key_with_diagnostic(
        &self,
        wrapping_key: &crate::NativeObjectRef,
        parameters: NativeSkipjackRelay<'_>,
        output_capacity: usize,
        diagnostic: &mut Option<crate::symmetric::memory::Credit>,
    ) -> Result<ExtensionResult> {
        with_relay_parameters(
            self,
            parameters,
            ExtensionOperation::WrapKey,
            |request, sources| {
                mechanism_extension::transport::wrap_with_sources(
                    self,
                    request,
                    wrapping_key,
                    None,
                    output_capacity,
                    sources,
                    diagnostic,
                )
            },
        )
    }
}
impl crate::AdvancedSession {
    /// Same synchronous relay route, with the normative absent target handle.
    pub fn relay_skipjack_key(
        &self,
        wrapping_key: &crate::NativeObjectRef,
        parameters: NativeSkipjackRelay<'_>,
        output_capacity: usize,
    ) -> Result<ExtensionResult> {
        let mut diagnostic = None;
        self.session.relay_skipjack_key_with_diagnostic(
            wrapping_key,
            parameters,
            output_capacity,
            &mut diagnostic,
        )
    }
}

mod encoding;
mod parameters;

pub(crate) use encoding::with_bound_parameters;
pub(crate) use encoding::with_parameters;
pub(crate) use encoding::with_relay_parameters;
