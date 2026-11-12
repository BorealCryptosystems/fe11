// SPDX-License-Identifier: Apache-2.0
//! Generic derivation inputs: explicit native algorithm parameters, no key profile.
use crate::{ManagedClass, NativeObjectRef};
use fe11_sys::*;

/// Digest-based secret-key derivation without a mechanism parameter. The module
/// chooses/checks the output type and size from the exact supplied template.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyDerivationHash(CK_MECHANISM_TYPE);
impl KeyDerivationHash {
    /// CKM_SHA512_224_KEY_DERIVATION.
    pub const SHA512_224_KEY_DERIVATION: Self = Self(fe11_sys::CKM_SHA512_224_KEY_DERIVATION);
    /// CKM_SHA512_256_KEY_DERIVATION.
    pub const SHA512_256_KEY_DERIVATION: Self = Self(fe11_sys::CKM_SHA512_256_KEY_DERIVATION);
    /// CKM_MD5_KEY_DERIVATION.
    pub const MD5_KEY_DERIVATION: Self = Self(fe11_sys::CKM_MD5_KEY_DERIVATION);
    /// CKM_MD2_KEY_DERIVATION.
    pub const MD2_KEY_DERIVATION: Self = Self(fe11_sys::CKM_MD2_KEY_DERIVATION);
    /// CKM_SHA1_KEY_DERIVATION.
    pub const SHA1_KEY_DERIVATION: Self = Self(fe11_sys::CKM_SHA1_KEY_DERIVATION);
    /// CKM_SHA256_KEY_DERIVATION.
    pub const SHA256_KEY_DERIVATION: Self = Self(fe11_sys::CKM_SHA256_KEY_DERIVATION);
    /// CKM_SHA384_KEY_DERIVATION.
    pub const SHA384_KEY_DERIVATION: Self = Self(fe11_sys::CKM_SHA384_KEY_DERIVATION);
    /// CKM_SHA512_KEY_DERIVATION.
    pub const SHA512_KEY_DERIVATION: Self = Self(fe11_sys::CKM_SHA512_KEY_DERIVATION);
    /// CKM_SHA224_KEY_DERIVATION.
    pub const SHA224_KEY_DERIVATION: Self = Self(fe11_sys::CKM_SHA224_KEY_DERIVATION);
    /// CKM_SHA3_256_KEY_DERIVATION.
    pub const SHA3_256_KEY_DERIVATION: Self = Self(fe11_sys::CKM_SHA3_256_KEY_DERIVATION);
    /// CKM_SHA3_224_KEY_DERIVATION.
    pub const SHA3_224_KEY_DERIVATION: Self = Self(fe11_sys::CKM_SHA3_224_KEY_DERIVATION);
    /// CKM_SHA3_384_KEY_DERIVATION.
    pub const SHA3_384_KEY_DERIVATION: Self = Self(fe11_sys::CKM_SHA3_384_KEY_DERIVATION);
    /// CKM_SHA3_512_KEY_DERIVATION.
    pub const SHA3_512_KEY_DERIVATION: Self = Self(fe11_sys::CKM_SHA3_512_KEY_DERIVATION);
    /// CKM_SHAKE_128_KEY_DERIVATION.
    pub const SHAKE_128_KEY_DERIVATION: Self = Self(fe11_sys::CKM_SHAKE_128_KEY_DERIVATION);
    /// CKM_SHAKE_256_KEY_DERIVATION.
    pub const SHAKE_256_KEY_DERIVATION: Self = Self(fe11_sys::CKM_SHAKE_256_KEY_DERIVATION);
    /// CKM_BLAKE2B_160_KEY_DERIVE; explicit parameter-absent representation.
    pub const BLAKE2B_160_KEY_DERIVE: Self = Self(fe11_sys::CKM_BLAKE2B_160_KEY_DERIVE);
    /// CKM_BLAKE2B_256_KEY_DERIVE; explicit parameter-absent representation.
    pub const BLAKE2B_256_KEY_DERIVE: Self = Self(fe11_sys::CKM_BLAKE2B_256_KEY_DERIVE);
    /// CKM_BLAKE2B_384_KEY_DERIVE; explicit parameter-absent representation.
    pub const BLAKE2B_384_KEY_DERIVE: Self = Self(fe11_sys::CKM_BLAKE2B_384_KEY_DERIVE);
    /// CKM_BLAKE2B_512_KEY_DERIVE; explicit parameter-absent representation.
    pub const BLAKE2B_512_KEY_DERIVE: Self = Self(fe11_sys::CKM_BLAKE2B_512_KEY_DERIVE);
    /// CKM_SHA512_T_KEY_DERIVATION; explicit parameter-absent representation.
    pub const SHA512_T_KEY_DERIVATION: Self = Self(fe11_sys::CKM_SHA512_T_KEY_DERIVATION);
    /// All declared parameterless digest derivations, without a support probe.
    pub const ALL: &'static [Self] = &[
        Self::BLAKE2B_160_KEY_DERIVE,
        Self::BLAKE2B_256_KEY_DERIVE,
        Self::BLAKE2B_384_KEY_DERIVE,
        Self::BLAKE2B_512_KEY_DERIVE,
        Self::SHA512_T_KEY_DERIVATION,
        Self::SHA512_224_KEY_DERIVATION,
        Self::SHA512_256_KEY_DERIVATION,
        Self::MD5_KEY_DERIVATION,
        Self::MD2_KEY_DERIVATION,
        Self::SHA1_KEY_DERIVATION,
        Self::SHA256_KEY_DERIVATION,
        Self::SHA384_KEY_DERIVATION,
        Self::SHA512_KEY_DERIVATION,
        Self::SHA224_KEY_DERIVATION,
        Self::SHA3_256_KEY_DERIVATION,
        Self::SHA3_224_KEY_DERIVATION,
        Self::SHA3_384_KEY_DERIVATION,
        Self::SHA3_512_KEY_DERIVATION,
        Self::SHAKE_128_KEY_DERIVATION,
        Self::SHAKE_256_KEY_DERIVATION,
    ];
    /// Exact PKCS#11 mechanism identifier.
    pub const fn mechanism_number(self) -> u64 {
        self.0 as u64
    }
}

/// Order of the caller's bytes relative to the base key's native value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DerivationDataPlacement {
    /// CKM_CONCATENATE_BASE_AND_DATA.
    AfterBase,
    /// CKM_CONCATENATE_DATA_AND_BASE.
    BeforeBase,
}

/// Salt representation passed exactly to CK_HKDF_PARAMS.
#[derive(Clone, Copy)]
pub enum NativeHkdfSalt<'a> {
    /// CKF_HKDF_SALT_NULL; no salt bytes or key handle.
    Null,
    /// CKF_HKDF_SALT_DATA; exact caller bytes, including empty.
    Data(&'a [u8]),
    /// CKF_HKDF_SALT_KEY; retain this admitted native object through the call.
    Key(&'a NativeObjectRef),
}
/// Native HKDF output function contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeHkdfOutput {
    /// CKM_HKDF_DERIVE produces a secret-key object.
    Key,
    /// CKM_HKDF_DATA produces a data object; no implicit value export follows.
    Data,
}

/// Complete HKDF parameter selection, including an absent info pointer.
/// Phase selection and parameter validity remain decisions of the caller/module.
#[derive(Clone, Copy)]
pub struct NativeHkdfParameters<'a> {
    /// Exact bExtract selection.
    pub extract: bool,
    /// Exact bExpand selection, independent of info presence.
    pub expand: bool,
    /// Exact base hash CKM identifier, without HMAC substitution.
    pub hash: u64,
    /// Native absent/data/key salt representation.
    pub salt: NativeHkdfSalt<'a>,
    /// None encodes NULL/0; Some(empty) encodes a present zero-length input.
    pub info: Option<&'a [u8]>,
    /// Select CKM_HKDF_DERIVE or CKM_HKDF_DATA.
    pub output: NativeHkdfOutput,
}

/// Explicit MQV descriptor layout; the extended form carries the caller's
/// ephemeral public-key handle. No layout is inferred from a module identity.
pub enum NativeMqvLayout<'a> {
    /// CK_ECDH2_DERIVE_PARAMS or CK_X9_42_DH2_DERIVE_PARAMS.
    TwoPair,
    /// CK_ECMQV_DERIVE_PARAMS or CK_X9_42_MQV_DERIVE_PARAMS.
    WithPublicKey(&'a NativeObjectRef),
}
/// Inputs shared by the published two-pair agreement parameter structures.
pub struct NativeTwoPairAgreement<'a> {
    /// Exact CKD_* identifier.
    pub kdf: u64,
    /// First peer public value, with no implicit format conversion.
    pub peer_public: &'a [u8],
    /// Second peer public value.
    pub peer_public_second: &'a [u8],
    /// Local second private key, retained without exporting its value.
    pub private_second: &'a NativeObjectRef,
    /// Exact ulPrivateDataLen in bytes; supplied by the caller.
    pub private_second_bytes: u64,
    /// SharedData for EC, OtherInfo for X9.42; None differs from present empty.
    pub context: Option<&'a [u8]>,
}
/// Exact native encrypt-data derivation selection. The output template controls
/// the derived object's attributes; no ciphertext is exported by this route.
pub enum NativeEncryptData<'a> {
    /// CKM_DES_ECB_ENCRYPT_DATA.
    DesEcb(&'a [u8]),
    /// CKM_DES3_ECB_ENCRYPT_DATA.
    Des3Ecb(&'a [u8]),
    /// CKM_AES_ECB_ENCRYPT_DATA.
    AesEcb(&'a [u8]),
    /// CKM_CAMELLIA_ECB_ENCRYPT_DATA.
    CamelliaEcb(&'a [u8]),
    /// CKM_ARIA_ECB_ENCRYPT_DATA.
    AriaEcb(&'a [u8]),
    /// CKM_SEED_ECB_ENCRYPT_DATA.
    SeedEcb(&'a [u8]),
    /// CKM_DES_CBC_ENCRYPT_DATA, exact eight-byte IV.
    DesCbc {
        /// Exact initialization-vector bytes, copied into the native parameter owner.
        iv: [u8; 8],
        /// Exact data to encrypt as part of derivation, not a precomputed ciphertext.
        data: &'a [u8],
    },
    /// CKM_DES3_CBC_ENCRYPT_DATA, exact eight-byte IV.
    Des3Cbc {
        /// Exact initialization-vector bytes, copied into the native parameter owner.
        iv: [u8; 8],
        /// Exact data to encrypt as part of derivation, not a precomputed ciphertext.
        data: &'a [u8],
    },
    /// CKM_AES_CBC_ENCRYPT_DATA, exact sixteen-byte IV.
    AesCbc {
        /// Exact initialization-vector bytes, copied into the native parameter owner.
        iv: [u8; 16],
        /// Exact data to encrypt as part of derivation, not a precomputed ciphertext.
        data: &'a [u8],
    },
    /// CKM_CAMELLIA_CBC_ENCRYPT_DATA.
    CamelliaCbc {
        /// Exact initialization-vector bytes, copied into the native parameter owner.
        iv: [u8; 16],
        /// Exact data to encrypt as part of derivation, not a precomputed ciphertext.
        data: &'a [u8],
    },
    /// CKM_ARIA_CBC_ENCRYPT_DATA.
    AriaCbc {
        /// Exact initialization-vector bytes, copied into the native parameter owner.
        iv: [u8; 16],
        /// Exact data to encrypt as part of derivation, not a precomputed ciphertext.
        data: &'a [u8],
    },
    /// CKM_SEED_CBC_ENCRYPT_DATA.
    SeedCbc {
        /// Exact initialization-vector bytes, copied into the native parameter owner.
        iv: [u8; 16],
        /// Exact data to encrypt as part of derivation, not a precomputed ciphertext.
        data: &'a [u8],
    },
}
impl NativeEncryptData<'_> {
    /// Exact CKM identifier; not a module support claim.
    pub fn mechanism_number(&self) -> u64 {
        (match self {
            Self::DesEcb(_) => CKM_DES_ECB_ENCRYPT_DATA,
            Self::Des3Ecb(_) => CKM_DES3_ECB_ENCRYPT_DATA,
            Self::AesEcb(_) => CKM_AES_ECB_ENCRYPT_DATA,
            Self::CamelliaEcb(_) => CKM_CAMELLIA_ECB_ENCRYPT_DATA,
            Self::AriaEcb(_) => CKM_ARIA_ECB_ENCRYPT_DATA,
            Self::SeedEcb(_) => CKM_SEED_ECB_ENCRYPT_DATA,
            Self::DesCbc { .. } => CKM_DES_CBC_ENCRYPT_DATA,
            Self::Des3Cbc { .. } => CKM_DES3_CBC_ENCRYPT_DATA,
            Self::AesCbc { .. } => CKM_AES_CBC_ENCRYPT_DATA,
            Self::CamelliaCbc { .. } => CKM_CAMELLIA_CBC_ENCRYPT_DATA,
            Self::AriaCbc { .. } => CKM_ARIA_CBC_ENCRYPT_DATA,
            Self::SeedCbc { .. } => CKM_SEED_CBC_ENCRYPT_DATA,
        }) as u64
    }
    pub(crate) fn data(&self) -> &[u8] {
        match self {
            Self::DesEcb(data)
            | Self::Des3Ecb(data)
            | Self::AesEcb(data)
            | Self::CamelliaEcb(data)
            | Self::AriaEcb(data)
            | Self::SeedEcb(data)
            | Self::DesCbc { data, .. }
            | Self::Des3Cbc { data, .. }
            | Self::AesCbc { data, .. }
            | Self::CamelliaCbc { data, .. }
            | Self::AriaCbc { data, .. }
            | Self::SeedCbc { data, .. } => data,
        }
    }
}

/// Exact IKE PRF derivation inputs. Optional key references encode the native
/// has-key/rekey flags; key material remains inside the module.
pub enum NativeIkeDerivation<'a> {
    /// CKM_IKE2_PRF_PLUS_DERIVE, with an optional seed key and exact seed bytes.
    PrfPlus {
        /// Native PRF mechanism identifier (CKM), without algorithm substitution.
        prf: u64,

        /// Optional native seed key; None clears the corresponding has-key flag.
        seed_key: Option<&'a NativeObjectRef>,

        /// Exact seed bytes, copied before native dispatch.
        seed: &'a [u8],
    },
    /// CKM_IKE_PRF_DERIVE. A new key selects bRekey; data_as_key is independent.
    Prf {
        /// Native PRF mechanism identifier (CKM), without algorithm substitution.
        prf: u64,

        /// Exact bDataAsKey flag controlling the native PRF input interpretation.
        data_as_key: bool,

        /// Optional rekeying input; presence sets the native rekey flag.
        new_key: Option<&'a NativeObjectRef>,

        /// Exact initiator nonce bytes in protocol order.
        initiator_nonce: &'a [u8],

        /// Exact responder nonce bytes in protocol order.
        responder_nonce: &'a [u8],
    },
    /// CKM_IKE1_PRF_DERIVE. key_number is the exact native byte value.
    Ike1 {
        /// Native PRF mechanism identifier (CKM), without algorithm substitution.
        prf: u64,

        /// Native shared-key reference; no local export of its material.
        shared_key: &'a NativeObjectRef,

        /// Optional native key from the preceding IKE derivation step.
        previous_key: Option<&'a NativeObjectRef>,

        /// Exact initiator cookie bytes in protocol order.
        initiator_cookie: &'a [u8],

        /// Exact responder cookie bytes in protocol order.
        responder_cookie: &'a [u8],

        /// Exact native byte selecting the IKE key number.
        key_number: u8,
    },
    /// CKM_IKE1_EXTENDED_DERIVE, optional shared key and exact extra data.
    Ike1Extended {
        /// Native PRF mechanism identifier (CKM), without algorithm substitution.
        prf: u64,

        /// Optional native shared-key reference; None clears the native has-key flag.
        shared_key: Option<&'a NativeObjectRef>,

        /// Exact additional derivation bytes, without an implicit prefix or terminator.
        extra: &'a [u8],
    },
}
impl<'a> NativeIkeDerivation<'a> {
    /// Exact native mechanism identifier.
    pub fn mechanism_number(&self) -> u64 {
        (match self {
            Self::PrfPlus { .. } => CKM_IKE2_PRF_PLUS_DERIVE,
            Self::Prf { .. } => CKM_IKE_PRF_DERIVE,
            Self::Ike1 { .. } => CKM_IKE1_PRF_DERIVE,
            Self::Ike1Extended { .. } => CKM_IKE1_EXTENDED_DERIVE,
        }) as u64
    }
    pub(crate) fn keys(&self) -> [Option<&'a NativeObjectRef>; 2] {
        match self {
            Self::PrfPlus { seed_key, .. } => [*seed_key, None],
            Self::Prf { new_key, .. } => [*new_key, None],
            Self::Ike1 {
                shared_key,
                previous_key,
                ..
            } => [Some(*shared_key), *previous_key],
            Self::Ike1Extended { shared_key, .. } => [*shared_key, None],
        }
    }
}

/// Borrowed native derivation parameters, copied into owned erased storage
/// before dispatch. Public values are never decoded/re-encoded as an implicit
/// curve, mathematical group or key-strength policy. The module receives the
/// exact selected KDF number and public-data representation.
pub enum NativeKeyDerivation<'a> {
    /// CKM_GOSTR3410_DERIVE with exact CK_GOSTR3410_DERIVE_PARAMS.
    GostR3410 {
        /// Native CK_EC_KDF_TYPE; the module decides algorithm support.
        kdf: u64,
        /// Peer public value, copied without point re-encoding.
        peer_public: &'a [u8],
        /// User keying material; absent and present-empty remain distinct.
        ukm: Option<&'a [u8]>,
    },
    /// Exact caller-asserted C_DeriveKey ABI, creating one object. Declared
    /// auxiliary parameter outputs are allowed; hidden object handles are not.
    /// Native multi-object contracts use their typed routes.
    Extension {
        /// Per-request unsafe ABI assertion, bound to the selected Module.
        request: crate::ExtensionRequest<'a>,
        /// Exact destination class expected by the caller's template.
        class: ManagedClass,
    },
    /// Typed X3DH or Double Ratchet initialization with asserted implicit lengths.
    Messaging(crate::MessagingKeyDerivation<'a>),
    /// TLS/WTLS master-secret derivation. Use derive_native_key_with_output to
    /// obtain the version observation required by the caller's protocol.
    TlsMaster(crate::TlsMasterDerivation<'a>),
    /// TLS/TLS12 exporter KDF with exact label/random/context parameters.
    TlsKdf(crate::TlsKdfParameters<'a>),
    /// Native CKM_NULL copies the base value. This provides no key separation
    /// or cryptographic transformation; result class/template are caller choices.
    Null {
        /// Object class of the NULL derivation result; does not imply private visibility.
        class: ManagedClass,
    },
    /// Exact native IKE mechanism, with owned inputs and retained source keys.
    Ike(NativeIkeDerivation<'a>),
    /// CKM_ECMQV_DERIVE, with an explicitly selected published layout.
    Ecmqv {
        /// Exact two-pair agreement inputs and referenced key objects.
        agreement: NativeTwoPairAgreement<'a>,

        /// Explicit native parameter layout; never selected by provider identity.
        layout: NativeMqvLayout<'a>,
    },
    /// CKM_X9_42_DH_HYBRID_DERIVE and CK_X9_42_DH2_DERIVE_PARAMS.
    X942Hybrid(NativeTwoPairAgreement<'a>),
    /// CKM_X9_42_MQV_DERIVE, with an explicitly selected published layout.
    X942Mqv {
        /// Exact two-pair agreement inputs and referenced key objects.
        agreement: NativeTwoPairAgreement<'a>,

        /// Explicit native parameter layout; never selected by provider identity.
        layout: NativeMqvLayout<'a>,
    },
    /// Derive by encrypting caller data under the base key, without exporting it.
    EncryptData(NativeEncryptData<'a>),
    /// Append a second native key's value; neither key value is exported.
    ConcatenateKey(&'a NativeObjectRef),
    /// HKDF with a present info buffer, including when it is empty. The module
    /// checks allowed combinations; HkdfParameters also permits an absent info.
    Hkdf {
        /// Execute the extract phase when true.
        extract: bool,
        /// Execute the expand phase when true.
        expand: bool,
        /// Exact base hash CKM_* identifier, not an HMAC mechanism substitution.
        hash: u64,
        /// Explicit native salt representation.
        salt: NativeHkdfSalt<'a>,
        /// Exact info bytes.
        info: &'a [u8],
        /// Select secret-key or data-object output.
        output: NativeHkdfOutput,
    },
    /// Complete HKDF fields, preserving absent versus present-empty info.
    HkdfParameters(NativeHkdfParameters<'a>),
    /// Digest the native base value; output attributes remain caller-selected.
    Hash(KeyDerivationHash),
    /// PKCS #3 DH: raw unsigned big-endian peer public value.
    DhPkcs {
        /// Peer public value as required by the selected module's PKCS#3 ABI.
        peer_public: &'a [u8],
    },
    /// CK_ECDH1_DERIVE_PARAMS, for ordinary or cofactor ECDH.
    Ecdh {
        /// CKD_* value, converted to CK_ULONG without algorithm substitution.
        kdf: u64,
        /// Select CKM_ECDH1_COFACTOR_DERIVE when true, CKM_ECDH1_DERIVE otherwise.
        cofactor: bool,
        /// Exact peer point bytes; no implicit SEC1/DER/Montgomery conversion.
        peer_public: &'a [u8],
        /// None encodes NULL; Some(empty) retains a non-NULL zero-length buffer.
        shared_data: Option<&'a [u8]>,
    },
    /// CK_X9_42_DH1_DERIVE_PARAMS; one peer key pair.
    X942Dh {
        /// CKD_* KDF value checked for ABI representation only.
        kdf: u64,
        /// Peer public value.
        peer_public: &'a [u8],
        /// None encodes NULL; Some(empty) retains a non-NULL zero-length buffer.
        other_info: Option<&'a [u8]>,
    },
    /// Concatenate caller data with the native base-key value.
    ConcatenateData {
        /// Exact data, copied into erased ownership before dispatch.
        data: &'a [u8],
        /// Order of base and data.
        placement: DerivationDataPlacement,
    },
    /// CKM_XOR_BASE_AND_DATA with CK_KEY_DERIVATION_STRING_DATA.
    XorData {
        /// Bytes to XOR according to the native mechanism.
        data: &'a [u8],
    },
    /// CKM_EXTRACT_KEY_FROM_KEY with an exact CK_EXTRACT_PARAMS bit offset.
    Extract {
        /// Starting bit; output length comes from the template.
        start_bit: u64,
    },
    /// CKM_PUB_KEY_FROM_PRIV_KEY; produces a public-key object.
    PublicFromPrivate,
}
impl<'a> NativeKeyDerivation<'a> {
    /// One borrowed selection feeds both public HKDF representations. No phase
    /// or salt choice changes while normalizing the present-info convenience.
    pub(crate) fn hkdf_parameters(&self) -> Option<NativeHkdfParameters<'a>> {
        match self {
            Self::Hkdf {
                extract,
                expand,
                hash,
                salt,
                info,
                output,
            } => Some(NativeHkdfParameters {
                extract: *extract,
                expand: *expand,
                hash: *hash,
                salt: *salt,
                info: Some(*info),
                output: *output,
            }),
            Self::HkdfParameters(parameters) => Some(*parameters),
            _ => None,
        }
    }
    /// Exact mechanism for this request; no discovery or fallback is performed.
    pub fn mechanism_number(&self) -> u64 {
        self.native() as u64
    }
    pub(crate) fn native(&self) -> CK_MECHANISM_TYPE {
        match self {
            Self::GostR3410 { .. } => CKM_GOSTR3410_DERIVE,
            Self::Extension { request, .. } => {
                request.contract.mechanism_number() as CK_MECHANISM_TYPE
            }
            Self::Messaging(parameters) => parameters.native(),
            Self::TlsMaster(parameters) => parameters.mechanism_number() as CK_MECHANISM_TYPE,
            Self::TlsKdf(parameters) => match parameters.mechanism {
                crate::TlsKdfMechanism::Tls => CKM_TLS_KDF,
                crate::TlsKdfMechanism::Tls12 => CKM_TLS12_KDF,
            },
            Self::Null { .. } => CKM_NULL,
            Self::Ike(parameters) => parameters.mechanism_number() as CK_MECHANISM_TYPE,
            Self::Ecmqv { .. } => CKM_ECMQV_DERIVE,
            Self::X942Hybrid(_) => CKM_X9_42_DH_HYBRID_DERIVE,
            Self::X942Mqv { .. } => CKM_X9_42_MQV_DERIVE,
            Self::EncryptData(parameters) => parameters.mechanism_number() as CK_MECHANISM_TYPE,
            Self::ConcatenateKey(_) => CKM_CONCATENATE_BASE_AND_KEY,
            Self::Hkdf {
                output: NativeHkdfOutput::Key,
                ..
            }
            | Self::HkdfParameters(NativeHkdfParameters {
                output: NativeHkdfOutput::Key,
                ..
            }) => CKM_HKDF_DERIVE,
            Self::Hkdf {
                output: NativeHkdfOutput::Data,
                ..
            }
            | Self::HkdfParameters(NativeHkdfParameters {
                output: NativeHkdfOutput::Data,
                ..
            }) => CKM_HKDF_DATA,
            Self::Hash(hash) => hash.0,
            Self::DhPkcs { .. } => CKM_DH_PKCS_DERIVE,
            Self::Ecdh {
                cofactor: false, ..
            } => CKM_ECDH1_DERIVE,
            Self::Ecdh { cofactor: true, .. } => CKM_ECDH1_COFACTOR_DERIVE,
            Self::X942Dh { .. } => CKM_X9_42_DH_DERIVE,
            Self::ConcatenateData {
                placement: DerivationDataPlacement::AfterBase,
                ..
            } => CKM_CONCATENATE_BASE_AND_DATA,
            Self::ConcatenateData {
                placement: DerivationDataPlacement::BeforeBase,
                ..
            } => CKM_CONCATENATE_DATA_AND_BASE,
            Self::XorData { .. } => CKM_XOR_BASE_AND_DATA,
            Self::Extract { .. } => CKM_EXTRACT_KEY_FROM_KEY,
            Self::PublicFromPrivate => CKM_PUB_KEY_FROM_PRIV_KEY,
        }
    }
    pub(crate) fn secondary_keys(&self) -> [Option<&'a NativeObjectRef>; 4] {
        match self {
            Self::Messaging(parameters) => parameters.keys(),
            Self::Ike(parameters) => {
                let [first, second] = parameters.keys();
                [first, second, None, None]
            }
            Self::Ecmqv { agreement, layout } | Self::X942Mqv { agreement, layout } => [
                Some(agreement.private_second),
                match layout {
                    NativeMqvLayout::TwoPair => None,
                    NativeMqvLayout::WithPublicKey(key) => Some(*key),
                },
                None,
                None,
            ],
            Self::X942Hybrid(agreement) => [Some(agreement.private_second), None, None, None],
            Self::ConcatenateKey(key)
            | Self::Hkdf {
                salt: NativeHkdfSalt::Key(key),
                ..
            }
            | Self::HkdfParameters(NativeHkdfParameters {
                salt: NativeHkdfSalt::Key(key),
                ..
            }) => [Some(*key), None, None, None],
            _ => [None, None, None, None],
        }
    }
    pub(crate) fn check_extension(
        &self,
        inner: &std::sync::Arc<crate::module::Inner>,
    ) -> crate::Result<()> {
        if let Self::Extension { request, .. } = self {
            request
                .contract
                .check(inner, crate::ExtensionOperation::DeriveKey)?;
        }
        Ok(())
    }
    pub(crate) fn mutates_base(&self) -> bool {
        matches!(self, Self::Extension { request, .. } if request.contract.mutates_key())
    }
    pub(crate) fn layout_provenance(&self) -> crate::MechanismLayoutProvenance {
        match self {
            Self::Extension { request, .. } => request.contract.provenance(),
            // Messaging constructors require the caller to assert the native
            // extents which these historical C structures do not encode.
            Self::Messaging(_) => crate::MechanismLayoutProvenance::CallerAssertedLayout,
            _ => crate::MechanismLayoutProvenance::StandardLayout,
        }
    }
    pub(crate) fn output_class(&self) -> ManagedClass {
        match self {
            Self::Extension { class, .. } | Self::Null { class } => *class,
            Self::PublicFromPrivate => ManagedClass::PublicKey,
            Self::Hkdf {
                output: NativeHkdfOutput::Data,
                ..
            }
            | Self::HkdfParameters(NativeHkdfParameters {
                output: NativeHkdfOutput::Data,
                ..
            }) => ManagedClass::Data,
            _ => ManagedClass::SecretKey,
        }
    }
}
