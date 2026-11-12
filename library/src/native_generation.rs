// SPDX-License-Identifier: Apache-2.0
//! Typed, parameterless native generation. Algorithms and templates remain
//! caller choices; availability and mathematical suitability are module decisions.
use crate::{
    AttributeInput, AttributeTemplateLimits, ContentObservation, DestinationPlan, ManagedClass,
    NativeObjectView, ObjectAdmission,
};
use fe11_sys::CK_MECHANISM_TYPE;

/// Inputs and explicitly selected observations for one generated object.
/// No attributes, key sizes, usage flags or cryptographic profiles are added.
/// The template is copied into erased storage before native dispatch; caller
/// buffers remain outside that erasure guarantee. Duplicate attributes retain
/// their order and are submitted to the module unchanged.
pub struct GenerationTemplate<'a> {
    /// Exact standard or explicitly declared extension attributes.
    pub attributes: &'a [AttributeInput<'a>],
    /// Bounds selected by the caller for this template's complete tree.
    pub limits: AttributeTemplateLimits,
    /// Optional descriptive work after native creation. None performs no
    /// attribute read and returns a generic native reference.
    pub observation: Option<CreationObservation>,
    /// Optional destination observation or requirement.
    pub destination: DestinationPlan,
}

/// Explicit descriptive work associated with a native creation convenience call.
pub struct CreationObservation {
    /// Metadata attributes and read resources chosen by the caller.
    pub admission: ObjectAdmission,
    /// Explicit content reading, independent of the native creation's success.
    pub content: ContentObservation,
}

impl GenerationTemplate<'_> {
    pub(crate) fn into_content(self) -> ContentObservation {
        self.observation
            .map_or(ContentObservation::NotRequested, |value| value.content)
    }
}

/// Pair of native references with caller-selected observations. This does not assert a locally
/// verified mathematical relationship or silently export either key's material.
pub struct NativeKeyPair {
    /// Declared parameter output for an extension; None for parameterless generators.
    pub output: crate::NativeGenerationOutput,
    /// Native public-key reference; CKA_PRIVATE is observed only when requested.
    pub public: NativeObjectView,
    /// Native private-key reference; CKA_PRIVATE is observed only when requested.
    pub private: NativeObjectView,
}

/// Standard C_GenerateKey mechanisms whose parameter is NULL.
/// Domain-parameter and OTP generators retain their distinct object classes.
/// Attributes carry the requested algorithm inputs; Fe11 performs no local
/// primality, strength or key-size policy checks. Deprecated names remain usable
/// for compatibility, without a recommendation to use their algorithms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyGenerator {
    mechanism: CK_MECHANISM_TYPE,
    class: ManagedClass,
}
impl KeyGenerator {
    /// CKM_AES_XTS_KEY_GEN; no mechanism parameter.
    pub const AES_XTS_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_AES_XTS_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_POLY1305_KEY_GEN; no mechanism parameter.
    pub const POLY1305_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_POLY1305_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_HKDF_KEY_GEN; size and attributes come from the caller template.
    pub const HKDF_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_HKDF_KEY_GEN,
        class: ManagedClass::SecretKey,
    };

    /// CKM_RC2_KEY_GEN; no mechanism parameter.
    pub const RC2_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_RC2_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_RC4_KEY_GEN; no mechanism parameter.
    pub const RC4_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_RC4_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_DES_KEY_GEN; no mechanism parameter.
    pub const DES_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_DES_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_DES2_KEY_GEN; no mechanism parameter.
    pub const DES2_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_DES2_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_DES3_KEY_GEN; no mechanism parameter.
    pub const DES3_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_DES3_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_CDMF_KEY_GEN; no mechanism parameter.
    pub const CDMF_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_CDMF_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_SECURID_KEY_GEN; no mechanism parameter.
    pub const SECURID_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_SECURID_KEY_GEN,
        class: ManagedClass::OtpKey,
    };
    /// CKM_HOTP_KEY_GEN; no mechanism parameter.
    pub const HOTP_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_HOTP_KEY_GEN,
        class: ManagedClass::OtpKey,
    };
    /// CKM_ACTI_KEY_GEN; no mechanism parameter.
    pub const ACTI_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_ACTI_KEY_GEN,
        class: ManagedClass::OtpKey,
    };
    /// CKM_SHA3_256_KEY_GEN; no mechanism parameter.
    pub const SHA3_256_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_SHA3_256_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_SHA3_224_KEY_GEN; no mechanism parameter.
    pub const SHA3_224_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_SHA3_224_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_SHA3_384_KEY_GEN; no mechanism parameter.
    pub const SHA3_384_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_SHA3_384_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_SHA3_512_KEY_GEN; no mechanism parameter.
    pub const SHA3_512_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_SHA3_512_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_CAST_KEY_GEN; no mechanism parameter.
    pub const CAST_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_CAST_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_CAST3_KEY_GEN; no mechanism parameter.
    pub const CAST3_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_CAST3_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_CAST5_KEY_GEN; no mechanism parameter.
    pub const CAST5_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_CAST5_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_CAST128_KEY_GEN; no mechanism parameter.
    pub const CAST128_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_CAST128_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_RC5_KEY_GEN; no mechanism parameter.
    pub const RC5_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_RC5_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_IDEA_KEY_GEN; no mechanism parameter.
    pub const IDEA_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_IDEA_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_GENERIC_SECRET_KEY_GEN; no mechanism parameter.
    pub const GENERIC_SECRET_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_GENERIC_SECRET_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_CAMELLIA_KEY_GEN; no mechanism parameter.
    pub const CAMELLIA_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_CAMELLIA_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_ARIA_KEY_GEN; no mechanism parameter.
    pub const ARIA_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_ARIA_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_SEED_KEY_GEN; no mechanism parameter.
    pub const SEED_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_SEED_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_SKIPJACK_KEY_GEN; no mechanism parameter.
    pub const SKIPJACK_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_SKIPJACK_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_BATON_KEY_GEN; no mechanism parameter.
    pub const BATON_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_BATON_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_JUNIPER_KEY_GEN; no mechanism parameter.
    pub const JUNIPER_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_JUNIPER_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_AES_KEY_GEN; no mechanism parameter.
    pub const AES_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_AES_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_BLOWFISH_KEY_GEN; no mechanism parameter.
    pub const BLOWFISH_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_BLOWFISH_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_TWOFISH_KEY_GEN; no mechanism parameter.
    pub const TWOFISH_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_TWOFISH_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_GOST28147_KEY_GEN; no mechanism parameter.
    pub const GOST28147_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_GOST28147_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_CHACHA20_KEY_GEN; no mechanism parameter.
    pub const CHACHA20_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_CHACHA20_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_DSA_PARAMETER_GEN; no mechanism parameter.
    pub const DSA_PARAMETER_GEN: Self = Self {
        mechanism: fe11_sys::CKM_DSA_PARAMETER_GEN,
        class: ManagedClass::DomainParameters,
    };
    /// CKM_DH_PKCS_PARAMETER_GEN; no mechanism parameter.
    pub const DH_PKCS_PARAMETER_GEN: Self = Self {
        mechanism: fe11_sys::CKM_DH_PKCS_PARAMETER_GEN,
        class: ManagedClass::DomainParameters,
    };
    /// CKM_X9_42_DH_PARAMETER_GEN; no mechanism parameter.
    pub const X9_42_DH_PARAMETER_GEN: Self = Self {
        mechanism: fe11_sys::CKM_X9_42_DH_PARAMETER_GEN,
        class: ManagedClass::DomainParameters,
    };
    /// CKM_SHA_1_KEY_GEN; no mechanism parameter.
    pub const SHA_1_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_SHA_1_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_SHA224_KEY_GEN; no mechanism parameter.
    pub const SHA224_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_SHA224_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_SHA256_KEY_GEN; no mechanism parameter.
    pub const SHA256_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_SHA256_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_SHA384_KEY_GEN; no mechanism parameter.
    pub const SHA384_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_SHA384_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_SHA512_KEY_GEN; no mechanism parameter.
    pub const SHA512_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_SHA512_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_SHA512_224_KEY_GEN; no mechanism parameter.
    pub const SHA512_224_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_SHA512_224_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_SHA512_256_KEY_GEN; no mechanism parameter.
    pub const SHA512_256_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_SHA512_256_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_SHA512_T_KEY_GEN; no mechanism parameter.
    pub const SHA512_T_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_SHA512_T_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_BLAKE2B_160_KEY_GEN; no mechanism parameter.
    pub const BLAKE2B_160_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_BLAKE2B_160_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_BLAKE2B_256_KEY_GEN; no mechanism parameter.
    pub const BLAKE2B_256_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_BLAKE2B_256_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_BLAKE2B_384_KEY_GEN; no mechanism parameter.
    pub const BLAKE2B_384_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_BLAKE2B_384_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_BLAKE2B_512_KEY_GEN; no mechanism parameter.
    pub const BLAKE2B_512_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_BLAKE2B_512_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// CKM_SALSA20_KEY_GEN; no mechanism parameter.
    pub const SALSA20_KEY_GEN: Self = Self {
        mechanism: fe11_sys::CKM_SALSA20_KEY_GEN,
        class: ManagedClass::SecretKey,
    };
    /// All named selectors, including standard aliases sharing one number.
    pub const ALL: &'static [Self] = &[
        Self::AES_XTS_KEY_GEN,
        Self::POLY1305_KEY_GEN,
        Self::HKDF_KEY_GEN,
        Self::RC2_KEY_GEN,
        Self::RC4_KEY_GEN,
        Self::DES_KEY_GEN,
        Self::DES2_KEY_GEN,
        Self::DES3_KEY_GEN,
        Self::CDMF_KEY_GEN,
        Self::SECURID_KEY_GEN,
        Self::HOTP_KEY_GEN,
        Self::ACTI_KEY_GEN,
        Self::SHA3_256_KEY_GEN,
        Self::SHA3_224_KEY_GEN,
        Self::SHA3_384_KEY_GEN,
        Self::SHA3_512_KEY_GEN,
        Self::CAST_KEY_GEN,
        Self::CAST3_KEY_GEN,
        Self::CAST5_KEY_GEN,
        Self::CAST128_KEY_GEN,
        Self::RC5_KEY_GEN,
        Self::IDEA_KEY_GEN,
        Self::GENERIC_SECRET_KEY_GEN,
        Self::CAMELLIA_KEY_GEN,
        Self::ARIA_KEY_GEN,
        Self::SEED_KEY_GEN,
        Self::SKIPJACK_KEY_GEN,
        Self::BATON_KEY_GEN,
        Self::JUNIPER_KEY_GEN,
        Self::AES_KEY_GEN,
        Self::BLOWFISH_KEY_GEN,
        Self::TWOFISH_KEY_GEN,
        Self::GOST28147_KEY_GEN,
        Self::CHACHA20_KEY_GEN,
        Self::DSA_PARAMETER_GEN,
        Self::DH_PKCS_PARAMETER_GEN,
        Self::X9_42_DH_PARAMETER_GEN,
        Self::SHA_1_KEY_GEN,
        Self::SHA224_KEY_GEN,
        Self::SHA256_KEY_GEN,
        Self::SHA384_KEY_GEN,
        Self::SHA512_KEY_GEN,
        Self::SHA512_224_KEY_GEN,
        Self::SHA512_256_KEY_GEN,
        Self::SHA512_T_KEY_GEN,
        Self::BLAKE2B_160_KEY_GEN,
        Self::BLAKE2B_256_KEY_GEN,
        Self::BLAKE2B_384_KEY_GEN,
        Self::BLAKE2B_512_KEY_GEN,
        Self::SALSA20_KEY_GEN,
    ];
    /// Exact PKCS#11 mechanism identifier.
    pub const fn mechanism_number(self) -> u64 {
        self.mechanism as u64
    }
    /// Structural class defined by the generating mechanism, not visibility.
    pub const fn object_class(self) -> ManagedClass {
        self.class
    }
    pub(crate) const fn native(self) -> CK_MECHANISM_TYPE {
        self.mechanism
    }
}

/// Standard C_GenerateKeyPair mechanisms whose parameter is NULL.
/// Every selector creates public/private objects using exactly the two supplied
/// templates. The module validates their algorithm-specific contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyPairGenerator(CK_MECHANISM_TYPE);
impl KeyPairGenerator {
    /// CKM_RSA_PKCS_KEY_PAIR_GEN; no mechanism parameter.
    pub const RSA_PKCS_KEY_PAIR_GEN: Self = Self(fe11_sys::CKM_RSA_PKCS_KEY_PAIR_GEN);
    /// CKM_RSA_X9_31_KEY_PAIR_GEN; no mechanism parameter.
    pub const RSA_X9_31_KEY_PAIR_GEN: Self = Self(fe11_sys::CKM_RSA_X9_31_KEY_PAIR_GEN);
    /// CKM_DSA_KEY_PAIR_GEN; no mechanism parameter.
    pub const DSA_KEY_PAIR_GEN: Self = Self(fe11_sys::CKM_DSA_KEY_PAIR_GEN);
    /// CKM_DH_PKCS_KEY_PAIR_GEN; no mechanism parameter.
    pub const DH_PKCS_KEY_PAIR_GEN: Self = Self(fe11_sys::CKM_DH_PKCS_KEY_PAIR_GEN);
    /// CKM_X9_42_DH_KEY_PAIR_GEN; no mechanism parameter.
    pub const X9_42_DH_KEY_PAIR_GEN: Self = Self(fe11_sys::CKM_X9_42_DH_KEY_PAIR_GEN);
    /// CKM_KEA_KEY_PAIR_GEN; no mechanism parameter.
    pub const KEA_KEY_PAIR_GEN: Self = Self(fe11_sys::CKM_KEA_KEY_PAIR_GEN);
    /// CKM_ECDSA_KEY_PAIR_GEN; no mechanism parameter.
    pub const ECDSA_KEY_PAIR_GEN: Self = Self(fe11_sys::CKM_ECDSA_KEY_PAIR_GEN);
    /// CKM_EC_KEY_PAIR_GEN; no mechanism parameter.
    pub const EC_KEY_PAIR_GEN: Self = Self(fe11_sys::CKM_EC_KEY_PAIR_GEN);
    /// CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS; no mechanism parameter.
    pub const EC_KEY_PAIR_GEN_W_EXTRA_BITS: Self = Self(fe11_sys::CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS);
    /// CKM_GOSTR3410_KEY_PAIR_GEN; no mechanism parameter.
    pub const GOSTR3410_KEY_PAIR_GEN: Self = Self(fe11_sys::CKM_GOSTR3410_KEY_PAIR_GEN);
    /// CKM_EC_EDWARDS_KEY_PAIR_GEN; no mechanism parameter.
    pub const EC_EDWARDS_KEY_PAIR_GEN: Self = Self(fe11_sys::CKM_EC_EDWARDS_KEY_PAIR_GEN);
    /// CKM_EC_MONTGOMERY_KEY_PAIR_GEN; no mechanism parameter.
    pub const EC_MONTGOMERY_KEY_PAIR_GEN: Self = Self(fe11_sys::CKM_EC_MONTGOMERY_KEY_PAIR_GEN);
    /// CKM_HSS_KEY_PAIR_GEN; no mechanism parameter.
    pub const HSS_KEY_PAIR_GEN: Self = Self(fe11_sys::CKM_HSS_KEY_PAIR_GEN);
    /// CKM_XMSS_KEY_PAIR_GEN; no mechanism parameter.
    pub const XMSS_KEY_PAIR_GEN: Self = Self(fe11_sys::CKM_XMSS_KEY_PAIR_GEN);
    /// CKM_XMSSMT_KEY_PAIR_GEN; no mechanism parameter.
    pub const XMSSMT_KEY_PAIR_GEN: Self = Self(fe11_sys::CKM_XMSSMT_KEY_PAIR_GEN);
    /// CKM_ML_KEM_KEY_PAIR_GEN; no mechanism parameter.
    pub const ML_KEM_KEY_PAIR_GEN: Self = Self(fe11_sys::CKM_ML_KEM_KEY_PAIR_GEN);
    /// CKM_ML_DSA_KEY_PAIR_GEN; no mechanism parameter.
    pub const ML_DSA_KEY_PAIR_GEN: Self = Self(fe11_sys::CKM_ML_DSA_KEY_PAIR_GEN);
    /// CKM_SLH_DSA_KEY_PAIR_GEN; no mechanism parameter.
    pub const SLH_DSA_KEY_PAIR_GEN: Self = Self(fe11_sys::CKM_SLH_DSA_KEY_PAIR_GEN);
    /// All named selectors, including ECDSA/EC aliases.
    pub const ALL: &'static [Self] = &[
        Self::RSA_PKCS_KEY_PAIR_GEN,
        Self::RSA_X9_31_KEY_PAIR_GEN,
        Self::DSA_KEY_PAIR_GEN,
        Self::DH_PKCS_KEY_PAIR_GEN,
        Self::X9_42_DH_KEY_PAIR_GEN,
        Self::KEA_KEY_PAIR_GEN,
        Self::ECDSA_KEY_PAIR_GEN,
        Self::EC_KEY_PAIR_GEN,
        Self::EC_KEY_PAIR_GEN_W_EXTRA_BITS,
        Self::GOSTR3410_KEY_PAIR_GEN,
        Self::EC_EDWARDS_KEY_PAIR_GEN,
        Self::EC_MONTGOMERY_KEY_PAIR_GEN,
        Self::HSS_KEY_PAIR_GEN,
        Self::XMSS_KEY_PAIR_GEN,
        Self::XMSSMT_KEY_PAIR_GEN,
        Self::ML_KEM_KEY_PAIR_GEN,
        Self::ML_DSA_KEY_PAIR_GEN,
        Self::SLH_DSA_KEY_PAIR_GEN,
    ];
    /// Exact PKCS#11 mechanism identifier.
    pub const fn mechanism_number(self) -> u64 {
        self.0 as u64
    }
    pub(crate) const fn native(self) -> CK_MECHANISM_TYPE {
        self.0
    }
}
