// SPDX-License-Identifier: Apache-2.0
//! Public unit variants have distinct identities and survive copying and cloning.
use fe11::*;
use std::fmt::Debug;

fn verify_values<T: Copy + Clone + Debug + Eq>(values: &[T]) {
    for (index, original) in values.iter().enumerate() {
        let copied = *original;
        let cloned = T::clone(original);
        assert_eq!(copied, cloned);
        assert_eq!(cloned, *original);
        assert!(!format!("{original:?}").is_empty());
        for (other_index, other) in values.iter().enumerate() {
            assert_eq!(copied == *other, index == other_index);
        }
    }
}

// Matching a typed constant exercises structural equality using stable Rust.
// Each family provides a second variant to distinguish a match from a wildcard.
macro_rules! verify_variants {
    ($name:ident, $kind:ident, $first:ident, $($other:ident),+ $(,)?) => {
        #[test]
        fn $name() {
            const FIRST: $kind = $kind::$first;
            let values = [$kind::$first, $($kind::$other),+];
            verify_values(&values);
            for (index, value) in values.into_iter().enumerate() {
                assert_eq!(matches!(value, FIRST), index == 0);
            }
        }
    };
}

verify_variants!(
    advanced_close_status, AdvancedCloseStatus,
    Complete, Pending,
);
verify_variants!(
    advanced_session_mode, AdvancedSessionMode,
    Asynchronous, Synchronous,
);
verify_variants!(
    agreement_curve, AgreementCurve,
    BrainpoolP256, BrainpoolP384, P256, P384,
);
verify_variants!(
    announced_session_limits, AnnouncedSessionLimits,
    Ignore, IntersectWithAnnounced,
);
verify_variants!(
    attribute, Attribute,
    AllowedMechanisms, AlwaysAuthenticate, AlwaysSensitive, Application,
    CertificateCategory, CertificateType, Class, Copyable, Decrypt, Derive, Destroyable,
    EcParams, EcPoint, Encrypt, EndDate, Extractable, Id, Issuer, KeyGenMechanism,
    KeyType, Label, Local, Modifiable, Modulus, NeverExtractable, ObjectType,
    ParameterSet, Private, PublicExponent, PublicKeyInfo, Sensitive, SerialNumber, Sign,
    SignRecover, StartDate, Subject, Token, Trusted, UniqueId, Unwrap, ValueLen, Verify,
    VerifyRecover, Wrap, WrapWithTrusted,
);
verify_variants!(
    attribute_admission_failure, AttributeAdmissionFailure,
    Cancelled, Deadline,
);
verify_variants!(
    attribute_clarification, AttributeClarification,
    BatchOnly, ClarifyIndeterminate,
);
verify_variants!(
    attribute_layout, AttributeLayout,
    Boolean, Bytes, Date, Template, Unsigned, UnsignedArray, Version,
);
verify_variants!(
    attribute_unavailable_cause, AttributeUnavailableCause,
    Sensitive, Unspecified, Unsupported,
);
verify_variants!(
    cha_cha_nonce_length_encoding, ChaChaNonceLengthEncoding,
    Bits, BytesCompatibility,
);
verify_variants!(
    cipher_output_plan, CipherOutputPlan,
    LengthOnly, MechanismBound,
);
verify_variants!(
    cipher_parameters, CipherParameters,
    AriaEcb, CamelliaEcb, Cast3Ecb, Cast5Ecb, CastEcb, CdmfEcb, Des3Ecb, DesEcb,
    Gost28147Ecb, IdeaEcb, Null, Rc4, SeedEcb,
);
verify_variants!(
    classical_key_algorithm, ClassicalKeyAlgorithm,
    Ed25519, Ed448,
);
verify_variants!(
    content_issue, ContentIssue,
    EmptyPublicMaterial, IntegerEncoding, NotPublicKey, ObjectChanged,
);
verify_variants!(
    content_status, ContentStatus,
    Available, NotRequested,
);
verify_variants!(
    derivation_data_placement, DerivationDataPlacement,
    AfterBase, BeforeBase,
);
verify_variants!(
    derivation_path, DerivationPath,
    HkdfExpand, HkdfExtract, HkdfExtractExpand,
);
verify_variants!(
    destination_source, DestinationSource,
    Exclude, Include,
);
verify_variants!(
    dsa_verification_hash, DsaVerificationHash,
    Sha1, Sha224, Sha256, Sha384, Sha512,
);
verify_variants!(
    ec_curve, EcCurve,
    BrainpoolP256, BrainpoolP384, BrainpoolP512, P256, P384, P521, Secp256k1,
);
verify_variants!(
    ecdh_kdf, EcdhKdf,
    ConcatSha256, Null, X963Sha256,
);
verify_variants!(
    ed_dsa_variant, EdDsaVariant,
    Ed25519, Ed25519Context, Ed25519Prehash, Ed448, Ed448Prehash,
);
verify_variants!(
    edwards_curve, EdwardsCurve,
    Ed25519, Ed448,
);
verify_variants!(
    edwards_key_size_units, EdwardsKeySizeUnits,
    EncodedPointBits, FieldBits,
);
verify_variants!(
    edwards_parameter_encoding, EdwardsParameterEncoding,
    CurveName, Oid,
);
verify_variants!(
    edwards_point_encoding, EdwardsPointEncoding,
    DerOctetString, Raw,
);
verify_variants!(
    extension_direction, ExtensionDirection,
    InOut, Input, Output,
);
verify_variants!(
    extension_operation, ExtensionOperation,
    DecapsulateKey, Decrypt, DecryptMultipart, DeriveKey, Digest, DigestMultipart,
    EncapsulateKey, Encrypt, EncryptMultipart, GenerateKey, GenerateKeyPair, Sign,
    SignMessage, SignMessageMultipart, SignMultipart, SignRecover, UnwrapKey, Verify,
    VerifyMessage, VerifyMessageMultipart, VerifyMultipart, VerifyRecover,
    VerifySignature, VerifySignatureMultipart, WrapKey,
);
verify_variants!(
    external_concurrency, ExternalConcurrency,
    Concurrent, Serialized,
);
verify_variants!(
    foreign_access, ForeignAccess,
    Session, Token,
);
verify_variants!(
    foreign_completion, ForeignCompletion,
    Continue, Detached, Pending, Returned, Uncertain,
);
verify_variants!(
    foreign_progress, ForeignProgress,
    Pending, Sequence,
);
verify_variants!(
    foreign_step, ForeignStep,
    Cancel, CloseSession, Complete, Continue, GetId, Join, Start,
);
verify_variants!(
    foreign_work_kind, ForeignWorkKind,
    Call, Operation, Session,
);
verify_variants!(
    function_presence, FunctionPresence,
    Null, OutsideSelectedInterface, Present,
);
verify_variants!(
    generation_observation, GenerationObservation,
    Unavailable, Unsupported,
);
verify_variants!(
    hash_algorithm, HashAlgorithm,
    Sha224, Sha256, Sha384, Sha3_224, Sha3_256, Sha3_384, Sha3_512, Sha512,
);
verify_variants!(
    hash_execution, HashExecution,
    Pkcs11Combined, Pkcs11DigestThenPrimitive, RustSoftware,
);
verify_variants!(
    historical_classification, HistoricalClassification,
    HistoricalOnly, NonApprovedMd5,
);
verify_variants!(
    historical_hash, HistoricalHash,
    Md5, Sha1,
);
verify_variants!(
    hkdf_key_type, HkdfKeyType,
    Dedicated, Generic,
);
verify_variants!(
    hmac_key_type, HmacKeyType,
    Dedicated, Generic,
);
verify_variants!(
    identity_attribute, IdentityAttribute,
    Application, Class, Id, KeyType, Label, ObjectId, UniqueId,
);
verify_variants!(
    interface_selection, InterfaceSelection,
    Legacy220, Legacy230Draft, Legacy240, ProviderDefault,
);
verify_variants!(
    introduction_origin, IntroductionOrigin,
    Generated, Imported, ObservedLocal, ObservedNonLocal, ObservedUnknown, Unwrapped,
);
verify_variants!(
    kea_mechanism, KeaMechanism,
    Derive, KeyDerive,
);
verify_variants!(
    key_transport_usage, KeyTransportUsage,
    Unwrap, Wrap, WrapAndUnwrap,
);
verify_variants!(
    key_wrap_profile, KeyWrapProfile,
    AesKw, AesKwp, AuthenticatedGcm, RsaOaep,
);
verify_variants!(
    login_role, LoginRole,
    SecurityOfficer, User,
);
verify_variants!(
    managed_class, ManagedClass,
    Certificate, Data, DomainParameters, HardwareFeature, Mechanism, OtpKey, PrivateKey,
    Profile, PublicKey, SecretKey, Trust, Validation,
);
verify_variants!(
    mechanism_layout_provenance, MechanismLayoutProvenance,
    CallerAssertedLayout, StandardLayout,
);
verify_variants!(
    message_aead_mechanism, MessageAeadMechanism,
    Ccm, ChaCha20Poly1305, Gcm, Salsa20Poly1305,
);
verify_variants!(
    message_init_field, MessageInitField,
    DataLength, IvFixedBits, IvGenerator, IvLength, MacLength, NonceFixedBits,
    NonceGenerator, NonceLength, TagBits,
);
verify_variants!(
    message_init_layout, MessageInitLayout,
    InitWithOwnedMessageParameters, InitWithoutParameters,
);
verify_variants!(
    message_route, MessageRoute,
    Multipart, Single,
);
verify_variants!(
    ml_dsa_parameter_set, MlDsaParameterSet,
    MlDsa44, MlDsa65, MlDsa87,
);
verify_variants!(
    ml_kem_parameter_set, MlKemParameterSet,
    MlKem1024, MlKem512, MlKem768,
);
verify_variants!(
    module_digest_mismatch, ModuleDigestMismatch,
    Refuse, Report,
);
verify_variants!(
    module_digest_observation, ModuleDigestObservation,
    Matched, Mismatched, NotRequested,
);
verify_variants!(
    montgomery_domain, MontgomeryDomain,
    Curve25519, Curve448, X25519, X448,
);
verify_variants!(
    native_concurrency, NativeConcurrency,
    ApplicationMutexes, Concurrent, Serialized,
);
verify_variants!(
    native_digest_algorithm, NativeDigestAlgorithm,
    Blake2b160, Blake2b256, Blake2b384, Blake2b512, FastHash, GostR3411, Md2, Md5,
    Ripemd128, Ripemd160, Sha1, Sha224, Sha256, Sha384, Sha3_224, Sha3_256, Sha3_384,
    Sha3_512, Sha512, Sha512_224, Sha512_256,
);
verify_variants!(
    native_hkdf_output, NativeHkdfOutput,
    Data, Key,
);
verify_variants!(
    native_otp_algorithm, NativeOtpAlgorithm,
    Acti, Hotp, SecurId,
);
verify_variants!(
    native_pqc_family, NativePqcFamily,
    MlDsa, SlhDsa,
);
verify_variants!(
    notify_decision, NotifyDecision,
    Cancel, Continue,
);
verify_variants!(
    object_boolean_attribute, ObjectBooleanAttribute,
    AlwaysAuthenticate, AlwaysSensitive, Copyable, Decapsulate, Decrypt, Derive,
    Destroyable, Encapsulate, Encrypt, Extractable, Local, Modifiable, NeverExtractable,
    Private, Sensitive, Sign, SignRecover, Token, Trusted, Unwrap, Verify, VerifyRecover,
    Wrap, WrapWithTrusted,
);
verify_variants!(
    object_class, ObjectClass,
    PrivateKey, PublicKey,
);
verify_variants!(
    object_creator_provenance, ObjectCreatorProvenance,
    KnownCreationSession, TokenObject, UnknownPersistence, UnknownSessionCreator,
);
verify_variants!(
    object_visibility, ObjectVisibility,
    Private, Public,
);
verify_variants!(
    observation_issue, ObservationIssue,
    BooleanEncoding, IntegerEncoding, MechanismListEncoding,
);
verify_variants!(
    operation_pacing, OperationPacing,
    Cooperative, Eager,
);
verify_variants!(
    password_key_generator, PasswordKeyGenerator,
    Md2Des, Md5Cast, Md5Cast128, Md5Cast3, Md5Des, Sha1Cast128, Sha1Des2, Sha1Des3,
    Sha1Hmac, Sha1Rc2_128, Sha1Rc2_40, Sha1Rc4_128, Sha1Rc4_40,
);
verify_variants!(
    pbkdf2_layout, Pbkdf2Layout,
    Current, Historical,
);
verify_variants!(
    pqc_hash, PqcHash,
    Sha224, Sha256, Sha384, Sha3_224, Sha3_256, Sha3_384, Sha3_512, Sha512, Sha512_224,
    Sha512_256, Shake128, Shake256,
);
verify_variants!(
    pqc_hedging, PqcHedging,
    DeterministicRequired, Preferred, Required,
);
verify_variants!(
    pqc_private_encoding, PqcPrivateEncoding,
    Seed, SeedAndValue, Value,
);
verify_variants!(
    recover_mechanism, RecoverMechanism,
    Rsa9796, RsaPkcs, RsaX509,
);
verify_variants!(
    rsa_exponent_class, RsaExponentClass,
    ModernBound, OutsideModernBound,
);
verify_variants!(
    session_drop_behavior, SessionDropBehavior,
    Close, KeepOpen,
);
verify_variants!(
    signature_hash_provenance, SignatureHashProvenance,
    CallerPrepared, NativeEdwardsPrehash, PureEdwards,
);
verify_variants!(
    signing_request, SigningRequest,
    Ed25519, Ed448,
);
verify_variants!(
    slh_dsa_parameter_set, SlhDsaParameterSet,
    Sha2_128f, Sha2_128s, Sha2_192f, Sha2_192s, Sha2_256f, Sha2_256s, Shake128f,
    Shake128s, Shake192f, Shake192s, Shake256f, Shake256s,
);
verify_variants!(
    slot_event_status, SlotEventStatus,
    BlockingCallIssued, Closing, CompletionUnproven, FinalizationUncertain, Finalized,
    FinalizedImageRetained, Idle, PollIssued,
);
verify_variants!(
    state_provenance, StateProvenance,
    CapturedInProcess, Imported,
);
verify_variants!(
    stream_aead_algorithm, StreamAeadAlgorithm,
    ChaCha20, Salsa20,
);
verify_variants!(
    stream_input_status, StreamInputStatus,
    Closed, Open,
);
verify_variants!(
    symmetric_algorithm, SymmetricAlgorithm,
    Aes128, Aes192, Aes256, ChaCha20,
);
verify_variants!(
    tls_kdf_mechanism, TlsKdfMechanism,
    Tls, Tls12,
);
verify_variants!(
    tls_key_material_mechanism, TlsKeyMaterialMechanism,
    Ssl3, Tls,
);
verify_variants!(
    tls_key_material_part, TlsKeyMaterialPart,
    ClientKey, ClientMac, ServerKey, ServerMac, WtlsKey, WtlsMac,
);
verify_variants!(
    token_iv_cipher, TokenIvCipher,
    BatonCbc128, BatonCounter, BatonEcb128, BatonEcb96, BatonShuffle, JuniperCbc128,
    JuniperCounter, JuniperEcb128, JuniperShuffle, SkipjackCbc64, SkipjackCfb16,
    SkipjackCfb32, SkipjackCfb64, SkipjackCfb8, SkipjackEcb64, SkipjackOfb64,
);
verify_variants!(
    validation_capture_mode, ValidationCaptureMode,
    Capture, Disabled,
);
verify_variants!(
    windows_loader_channel, WindowsLoaderChannel,
    ActivationContext, ApiSets, DevOverrideEffective, DevOverrideRegistry, DotLocal,
    GlobalSearchState, KnownDlls, LoadedModules, PackageDependencyGraph,
    PackagedDotLocal, SearchDirectories,
);
verify_variants!(
    windows_loader_path_kind, WindowsLoaderPathKind,
    Directory, File, Missing, Other,
);
verify_variants!(
    windows_loader_request, WindowsLoaderRequest,
    NotRequested, Report, RequireKnown,
);
verify_variants!(
    windows_loader_unavailable, WindowsLoaderUnavailable,
    Allocation, ChangedDuringObservation, InvalidOutput, NoDocumentedProbe,
    ProvenanceUnavailable, ResourceLimit,
);
verify_variants!(
    windows_reparse_handling, WindowsReparseHandling,
    Reject, ResolveAndPin,
);
