// SPDX-License-Identifier: Apache-2.0
//! Exact native generation parameters; no local key mathematics or strength policy.
use crate::{KeyGenerator, ManagedClass, NativeObjectView};
use fe11_sys::*;
/// Native password-based generator. Legacy algorithms remain explicit choices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordKeyGenerator {
    /// CKM_PBE_MD2_DES_CBC.
    Md2Des,
    /// CKM_PBE_MD5_DES_CBC.
    Md5Des,
    /// CKM_PBE_MD5_CAST_CBC.
    Md5Cast,
    /// CKM_PBE_MD5_CAST3_CBC.
    Md5Cast3,
    /// CKM_PBE_MD5_CAST128_CBC (CAST5 is its numeric alias).
    Md5Cast128,
    /// CKM_PBE_SHA1_CAST128_CBC (CAST5 is its numeric alias).
    Sha1Cast128,
    /// CKM_PBE_SHA1_RC4_128.
    Sha1Rc4_128,
    /// CKM_PBE_SHA1_RC4_40.
    Sha1Rc4_40,
    /// CKM_PBE_SHA1_DES3_EDE_CBC.
    Sha1Des3,
    /// CKM_PBE_SHA1_DES2_EDE_CBC.
    Sha1Des2,
    /// CKM_PBE_SHA1_RC2_128_CBC.
    Sha1Rc2_128,
    /// CKM_PBE_SHA1_RC2_40_CBC.
    Sha1Rc2_40,
    /// CKM_PBA_SHA1_WITH_SHA1_HMAC; no IV.
    Sha1Hmac,
}
impl PasswordKeyGenerator {
    pub(crate) fn native(self) -> CK_MECHANISM_TYPE {
        match self {
            Self::Md2Des => CKM_PBE_MD2_DES_CBC,
            Self::Md5Des => CKM_PBE_MD5_DES_CBC,
            Self::Md5Cast => CKM_PBE_MD5_CAST_CBC,
            Self::Md5Cast3 => CKM_PBE_MD5_CAST3_CBC,
            Self::Md5Cast128 => CKM_PBE_MD5_CAST128_CBC,
            Self::Sha1Cast128 => CKM_PBE_SHA1_CAST128_CBC,
            Self::Sha1Rc4_128 => CKM_PBE_SHA1_RC4_128,
            Self::Sha1Rc4_40 => CKM_PBE_SHA1_RC4_40,
            Self::Sha1Des3 => CKM_PBE_SHA1_DES3_EDE_CBC,
            Self::Sha1Des2 => CKM_PBE_SHA1_DES2_EDE_CBC,
            Self::Sha1Rc2_128 => CKM_PBE_SHA1_RC2_128_CBC,
            Self::Sha1Rc2_40 => CKM_PBE_SHA1_RC2_40_CBC,
            Self::Sha1Hmac => CKM_PBA_SHA1_WITH_SHA1_HMAC,
        }
    }
    pub(crate) fn has_iv(self) -> bool {
        !matches!(self, Self::Sha1Rc4_128 | Self::Sha1Rc4_40 | Self::Sha1Hmac)
    }
}
/// PBKDF2 layout selected by the integrator; never inferred from module identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pbkdf2Layout {
    /// Current CK_PKCS5_PBKD2_PARAMS2 with an inline password length.
    Current,
    /// Historical CK_PKCS5_PBKD2_PARAMS with a pointer to password length.
    Historical,
}
/// Domain-parameter generation supplies a seed output, or consumes one for G.
pub enum DsaDomainGeneration<'a> {
    /// CKM_DSA_PROBABILISTIC_PARAMETER_GEN. Capacity is caller selected, no probe.
    Probabilistic {
        /// Caller-selected native hash mechanism identifier (CKM); no implicit hashing substitution.
        hash: u64,

        /// Maximum native output seed bytes, allocated before the call; no size probe.
        seed_capacity: usize,

        /// Exact native generation index; interpretation belongs to the selected mechanism.
        index: u64,
    },
    /// CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN. Index is passed unchanged though ignored.
    ShaweTaylor {
        /// Caller-selected native hash mechanism identifier (CKM); no implicit hashing substitution.
        hash: u64,

        /// Maximum native output seed bytes, allocated before the call; no size probe.
        seed_capacity: usize,

        /// Exact native generation index; interpretation belongs to the selected mechanism.
        index: u64,
    },
    /// CKM_DSA_FIPS_G_GEN consumes the exact seed and index.
    Base {
        /// Caller-selected native hash mechanism identifier (CKM); no implicit hashing substitution.
        hash: u64,

        /// Exact seed bytes, copied before native dispatch.
        seed: &'a [u8],

        /// Exact native generation index; interpretation belongs to the selected mechanism.
        index: u64,
    },
}
/// Native C_GenerateKey request, including mechanisms with auxiliary output.
pub enum NativeKeyGeneration<'a> {
    /// Caller-asserted ABI graph for C_GenerateKey. The requested class selects
    /// an optional descriptive view only; no CKA_CLASS is injected or verified
    /// when observation is absent. The module receives the exact template.
    Extension {
        /// Module/function-bound graph assertion, including in/out regions.
        request: crate::ExtensionRequest<'a>,
        /// Class for explicitly requested metadata observation.
        class: ManagedClass,
    },
    /// Existing parameterless key or domain generator.
    Simple(KeyGenerator),
    /// CKM_SSL3_PRE_MASTER_KEY_GEN; native CK_VERSION input.
    Ssl3PreMaster {
        /// Major protocol version byte in the native CK_VERSION.
        major: u8,
        /// Minor protocol version byte in the native CK_VERSION.
        minor: u8,
    },
    /// CKM_TLS_PRE_MASTER_KEY_GEN; native CK_VERSION input.
    TlsPreMaster {
        /// Major protocol version byte in the native CK_VERSION.
        major: u8,
        /// Minor protocol version byte in the native CK_VERSION.
        minor: u8,
    },
    /// CKM_WTLS_PRE_MASTER_KEY_GEN; native CK_BYTE input.
    WtlsPreMaster {
        /// Exact single-byte WTLS protocol version.
        version: u8,
    },
    /// CK_PBE_PARAMS. Password/salt are exact bytes, without terminator or recoding.
    Password {
        /// Native password-based generation mechanism, without substitution.
        generator: PasswordKeyGenerator,

        /// Exact password bytes, copied into protected native storage without text recoding.
        password: &'a [u8],

        /// Exact salt bytes; no salt generation or implicit encoding.
        salt: &'a [u8],

        /// Native iteration count selected by the caller; no local work-factor policy.
        iterations: u64,
    },
    /// CKM_PKCS5_PBKD2 with CKZ_SALT_SPECIFIED. PRF uses CKP, not CKM, values.
    /// Optional PRF bytes carry the GOST DER OID; absence remains NULL.
    Pbkdf2 {
        /// Explicit native parameter layout; never selected by provider identity.
        layout: Pbkdf2Layout,

        /// Exact password bytes, copied into protected native storage without text recoding.
        password: &'a [u8],

        /// Exact salt bytes; no salt generation or implicit encoding.
        salt: &'a [u8],

        /// Native iteration count selected by the caller; no local work-factor policy.
        iterations: u64,

        /// Native PBKDF2 PRF identifier (CKP, not CKM).
        prf: u64,

        /// Optional native PRF parameter bytes; None preserves a NULL pointer.
        prf_data: Option<&'a [u8]>,
    },
    /// Native domain generation only; Fe11 performs no primality validation.
    Dsa(DsaDomainGeneration<'a>),
}
impl NativeKeyGeneration<'_> {
    pub(crate) fn native(&self) -> CK_MECHANISM_TYPE {
        match self {
            Self::Extension { request, .. } => request.contract.native_mechanism(),
            Self::Simple(v) => v.native(),
            Self::Ssl3PreMaster { .. } => CKM_SSL3_PRE_MASTER_KEY_GEN,
            Self::TlsPreMaster { .. } => CKM_TLS_PRE_MASTER_KEY_GEN,
            Self::WtlsPreMaster { .. } => CKM_WTLS_PRE_MASTER_KEY_GEN,
            Self::Password { generator, .. } => generator.native(),
            Self::Pbkdf2 { .. } => CKM_PKCS5_PBKD2,
            Self::Dsa(DsaDomainGeneration::Probabilistic { .. }) => {
                CKM_DSA_PROBABILISTIC_PARAMETER_GEN
            }
            Self::Dsa(DsaDomainGeneration::ShaweTaylor { .. }) => {
                CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN
            }
            Self::Dsa(DsaDomainGeneration::Base { .. }) => CKM_DSA_FIPS_G_GEN,
        }
    }
    pub(crate) fn object_class(&self) -> ManagedClass {
        match self {
            Self::Extension { class, .. } => *class,
            Self::Simple(v) => v.object_class(),
            Self::Dsa(_) => ManagedClass::DomainParameters,
            _ => ManagedClass::SecretKey,
        }
    }
}
/// Owned auxiliary bytes, retained under the caller's memory budget and erased
/// on drop. Caller-created copies are outside this erasure guarantee.
pub struct NativeGenerationBytes(pub(crate) crate::symmetric::memory::Buffer);
impl NativeGenerationBytes {
    /// Exact native output after checked length publication.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}
/// Auxiliary output of the selected generator.
pub enum NativeGenerationOutput {
    /// Output regions declared by the caller's owned extension ABI.
    Extension(crate::ExtensionParameterOutputs),
    /// No auxiliary output is defined.
    None,
    /// Eight-byte initialization vector produced by a PBE generator.
    InitializationVector(NativeGenerationBytes),
    /// Seed returned by a DSA probabilistic or Shawe-Taylor generator.
    DomainSeed(NativeGenerationBytes),
}
/// Newly observed object and its native auxiliary output.
pub struct NativeGeneratedObject {
    /// Object observed according to the caller's generation template.
    pub object: NativeObjectView,
    /// Output produced by the selected mechanism; no local math validation.
    pub output: NativeGenerationOutput,
}
