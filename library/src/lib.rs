// SPDX-License-Identifier: Apache-2.0
#![doc = include_str!("../docs/overview.md")]

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

// These are implementation targets, not a claim of completed qualification.
// Fe11-sys supplies only these platform profiles. A compatible module ABI must
// be established by the application; selecting a PKCS#11 version cannot prove it.
#[cfg(not(any(
    all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"),
    all(target_os = "windows", target_arch = "x86_64", target_env = "msvc")
)))]
compile_error!("Fe11 implementation targets are Linux x86_64 GNU and Windows x86_64 MSVC.");

mod allocation;
mod atomic_update;

mod attribute_values;
mod attributes;

pub use attribute_values::{
    AttributeBatchCall, AttributeBatchCalls, AttributeBytes, AttributeInput, AttributeInputValue,
    AttributeIntegers, AttributeLayout, AttributeReadCalls, AttributeTemplateLimits, AttributeType,
    ExtensionAttribute, FlatAttributeBatch, FlatAttributeIntoIter, FlatAttributeObservation,
    FlatAttributeReadPlan, FlatAttributeRequest, FlatAttributeValue, StandardAttribute,
    TemplateAttributeChildren, TemplateAttributeNode, TemplateAttributeReadPlan,
    TemplateAttributeSlot, TemplateAttributeTree, TemplateAttributeValue,
};
mod pin;
pub use pin::{PinChange, PinRequest};
mod notify;
pub use notify::{Notification, NotifyDecision, NotifyDiagnostics, NotifyHandler};
mod admission_wait;
pub use admission_wait::{
    with_resource_admission, AdmissionCancellation, ResourceAdmission, SessionAdmission,
};
mod controls;
pub use controls::{AttributeUnavailableCause, Observation, ObservationIssue};
mod mechanism_catalog;
pub use mechanism_catalog::{MechanismCatalog, MechanismDiscovery, MechanismObservation};
mod mechanism_controls;
pub use mechanism_controls::{MechanismObservationPlan, MechanismObservationReport};
mod mechanism_policy;
pub use mechanism_policy::{MechanismAttributes, MechanismRequest};
mod content_controls;
mod reference_controls;
pub use content_controls::{
    ContentIssue, ContentMutationPlan, ContentObservation, ContentReadPlan, ContentReport,
    ContentStatus, ProtectedContent,
};
pub use reference_controls::{
    IdentityAttribute, ObjectReferencePlan, ObjectReferenceReport, ReferenceSearchPlan,
    ReferenceTemplate,
};
mod destination_controls;
pub use destination_controls::{
    DestinationPlan, DestinationReport, DestinationSearchPlan, DestinationSource,
    DestinationUserObservation,
};
mod mutation_controls;
pub use mutation_controls::{MutationObservationPlan, ObjectMutationPlan, ObjectMutationReport};
mod key_requests;
mod object_controls;
pub use key_requests::KeyUsageRequest;
mod search_controls;
pub use object_controls::{
    ObjectAdmission, ObjectBooleanAttribute, ObjectObservationPlan, ObjectObservationReport,
};
pub use search_controls::{ObjectSearchReport, ObjectSearchSelection};
mod object_visibility;
pub use object_visibility::ObjectVisibility;
mod public_key_import;
pub use public_key_import::{PublicImportMetadata, PublicKeyImportOptions};
mod advanced;
mod bounds;

pub mod diagnostics;
mod error;
mod interfaces;
mod module;
mod native;
mod native_return;
mod verify_engine;
pub use advanced::CipherStreamChunk;
pub use advanced::OperationPacing;
pub use advanced::SignatureMessage;
pub use advanced::{
    AdvancedCloseStatus, AdvancedSession, AdvancedSessionMode, GeneratedObjects, MacMessage,
    MessageRoute, MessageSignatures, MessageVerificationDetails, OperationProgress,
    OperationTicket, SavedOperationState, SessionValidation, StateCaptureProgress,
    StateKeyEncoding, StateKeyReference, StateRestoreFailure, StateRestoreKey, StateRestoreKeys,
    StateRestoreProgress, StateRestoreTicket,
};
pub use advanced::{
    AesBufferRequest, AesOutputPlan, CipherBufferRequest, CipherKeyReference, CipherOutputPlan,
};
pub use advanced::{
    CallerAssertedAuthenticatedRecord, CcmRecoveryRecord, GcmRecoveryRecord, NativeStateRecord,
    ParsedRecord, RecordLimits, StateExportFailure, StateProvenance, StreamAeadRecoveryRecord,
};
pub use advanced::{CancellationFlags, CancellationProgress};
pub use advanced::{
    CcmCiphertexts, CcmDecryptMessage, CcmEncryptMessage, CcmMessageCiphertext, CcmPlaintexts,
    CcmRejection, DeclaredGcmMessage, DeclaredGcmMessages, GcmCiphertext, GcmCiphertexts,
    GcmDecryptMessage, GcmEncryptMessage, GcmMessageExtension, GcmPlaintexts, GcmRejection,
    MessageAeadInit, MessageAeadInput, MessageAeadMechanism, MessageAeadParameters,
    MessageAeadRejection, StreamAeadCiphertext, StreamAeadCiphertexts, StreamAeadDecryptMessage,
    StreamAeadEncryptMessage, StreamAeadPlaintexts, StreamAeadRejection,
};
pub use advanced::{DetachedExportFailure, DetachedOperationRecord, DualRecoveryRecord};
pub use advanced::{
    DetachedOperation, DetachmentProgress, RejoinFailure, RejoinKeys, RejoinProgress, RejoinTicket,
};
pub use advanced::{
    DigestPlaintext, DualAuthenticatedPlaintext, DualCipher, DualCiphertext, DualMac, DualResult,
    UnauthenticatedPlaintext,
};
pub use advanced::{NativeMessageRejection, NativeMessageResults};
pub use advanced::{RecoverMechanism, RecoverOutputPlan, RecoveryBufferRequest, RecoveryOutput};
pub use advanced::{SignatureBufferRequest, SignatureOutputPlan};
pub use advanced::{StreamInputStatus, StreamProgress};
pub use advanced::{ValidationCaptureMode, ValidationObservation, ValidationReport};

mod administration;
mod authentication;
mod crypto;
mod random;
pub use crypto::kem::{
    KemCiphertext, KemDecapsulationKey, KemEncapsulation, KemEncapsulationKey, KemKeyPair,
    KemKeySpec, KemPublicKey, KemSharedKey, KemSharedKeySpec, MlKemParameterSet,
};
pub use crypto::pqc::{
    MlDsaParameterSet, PqcAlgorithm, PqcHash, PqcHedging, PqcPublicKey, PqcSignature,
    PqcSignatureMode, PqcSignatureParameters, SlhDsaParameterSet,
};
pub use crypto::pqc::{PqcKeyPair, PqcKeySpec, PqcSigningKey, PqcVerificationKey};
pub use crypto::{
    PqcImportedPrivateKey, PqcPrivateEncoding, PqcPrivateExport, PqcPrivateImportSpec,
    PqcPrivateInput, PqcPrivateKeyAlgorithm,
};
mod sp800_108;
pub use sp800_108::{
    NativeDerivedKeys, Sp800CounterFormat, Sp800Data, Sp800LengthFormat, Sp800Mode, Sp800Request,
};
mod kea_derivation;
pub use kea_derivation::{KeaMechanism, KeaRandoms, KeaRequest, KeaResult};
mod tls_key_material;
pub use tls_key_material::{
    DerivedKeyObservation, NativeTlsKeyMaterial, TlsKeyMaterialMechanism,
    TlsKeyMaterialObservations, TlsKeyMaterialPart, TlsKeyMaterialRequest,
};
mod tls_derivation;
pub use tls_derivation::{
    NativeDerivationOutput, NativeDerivedObject, NativePrfOutput, TlsKdfMechanism,
    TlsKdfParameters, TlsMasterDerivation, TlsPrfMechanism, TlsPrfRequest, TlsRandoms,
};
mod generation_parameters;
mod messaging_derivation;
pub use messaging_derivation::{
    MessagingKeyDerivation, RatchetParameters, X3dhInitiator, X3dhResponder,
};
mod native_derivation;
mod native_digest;
pub use generation_parameters::{
    DsaDomainGeneration, NativeGeneratedObject, NativeGenerationBytes, NativeGenerationOutput,
    NativeKeyGeneration, PasswordKeyGenerator, Pbkdf2Layout,
};
mod native_generation;
pub use native_derivation::{
    DerivationDataPlacement, KeyDerivationHash, NativeEncryptData, NativeHkdfOutput,
    NativeHkdfParameters, NativeHkdfSalt, NativeIkeDerivation, NativeKeyDerivation,
    NativeMqvLayout, NativeTwoPairAgreement,
};
pub use native_generation::{
    CreationObservation, GenerationTemplate, KeyGenerator, KeyPairGenerator, NativeKeyPair,
};
mod symmetric;
pub use native_digest::{
    NativeDigest, NativeDigestAlgorithm, NativeDigestTruncation, NativeNullDigestCapacity,
};
mod transport;
pub use crypto::derivation::*;
pub use crypto::{
    ClassicalKeyAlgorithm, ClassicalKeyPair, ClassicalKeySpec, ClassicalSignature, EcCurve,
    RsaExponentClass, RsaPssParameters, RsaSignatureProfile, SignatureHashProvenance,
    SignatureProfile, SigningKey, SigningRequest,
};
pub use crypto::{
    CryptoLimits, CryptoOptions, EdDsaParameters, EdDsaVariant, EdwardsCurve,
    EdwardsEncodingReport, EdwardsKeySizeUnits, EdwardsOptions, EdwardsParameterEncoding,
    EdwardsPointEncoding, HashAlgorithm, HashExecution, InputLimits, PreparedDigest,
    VerificationKey, VerificationProfile,
};
pub use crypto::{
    DsaVerificationDigest, DsaVerificationHash, HashProvenance, HistoricalClassification,
    HistoricalDigest, HistoricalHash, HistoricalProfile, HistoricalPssParameters,
    HistoricalVerificationResult, VerificationResult,
};
pub use symmetric::{
    AeadCiphertext, AeadNonce, AeadParameters, AeadPlaintext, AesCipherParameters, AesCiphertext,
    CallerSelectedInitLayout, CcmCiphertext, CcmNonce, CcmParameters, ChaChaNonceLengthEncoding,
    CipherParameters, Ciphertext, ClassicAeadCiphertext, ClassicAeadParameters,
    GenerationInvocation, GenerationMechanismReport, HmacKeyType, MessageAuthenticationCode,
    MessageInitField, MessageInitLayout, RcCipherParameters, StreamAeadAlgorithm,
    StreamAeadEncrypted, StreamAeadNonce, StreamAeadParameters, StreamCipherParameters,
    SymmetricAlgorithm, SymmetricKey, SymmetricKeySpec, SymmetricLimits, SymmetricProtection,
    TokenIv, TokenIvCipher, UnauthenticatedAesPlaintext, UnauthenticatedCipherPlaintext,
};
pub use transport::{
    AesKeyEncryptionKey, AesKeyEncryptionSpec, KeyTransportUsage, KeyWrapProfile, UnwrapParameters,
    UnwrappingKey, WrapLimits, WrapParameters, WrappedKey, WrappingKey,
};
pub use transport::{
    IntroducedSymmetricKey, IntroductionOrigin, IntroductionReport, SymmetricIntroductionSpec,
};
mod managed;
mod registry;
pub use managed::{
    CertificateSpec, CopyTarget, CreatedObjectSet, CreatedObjects, CreationObservationFailure,
    CreationRemainder, DataSpec, NativeObjectView, SearchPlan,
};
mod oaep;
mod objects;
mod session;
mod session_budget;
pub use session_budget::{
    AnnouncedSessionLimits, ModuleResourceStatus, SessionLimit, SessionPolicy, SessionUsage,
    TokenResourceStatus, TokenSessionLimit,
};

mod state_lock;

pub use administration::TokenAdministrationTarget;
pub use attributes::{Attribute, AttributeClarification, AttributeReadPlan, AttributeValue};
pub use diagnostics::*;
pub use error::{AttributeAdmissionFailure, Error, NativeOutputSize, Result};
pub use interfaces::{
    FunctionCatalog, FunctionPresence, InterfaceDiscoveryLimits, InterfaceSelection,
    InterfaceDescriptor, InterfaceInventory, InterfaceInventoryLimits,
};
pub use managed::{
    AttributeMutationReport, ManagedClass, ManagedObjectRef, ManagedSelector, NativeObjectIterator,
    NativeObjectMatches, NativeObjectRef, NativeObjectSelection, ObjectCreatorProvenance,
    ObjectMetadata,
};
pub use module::{
    Capabilities, DiscoveryReport, DiscoverySelection, ExternalConcurrency, ExternalInitialization,
    ExternalModuleIdentity, ForeignAccess, ForeignCall, ForeignCallback, ForeignCallbackHandle,
    ForeignCompletion, ForeignEvent, ForeignParticipant, ForeignProgress, ForeignReceipt,
    ForeignScope, ForeignStatus, ForeignStep, ForeignWork, ForeignWorkId, ForeignWorkKind,
    InitializationMutexFunctions, InitializationMutexes, InitializationOptions,
    InitializationReserved, Limits, LoginRole, MechanismInfo, Module, ModuleBuilder, ModuleConfig,
    ModuleDigestMismatch, ModuleDigestObservation, ModuleDrain, ModuleFileObservation, ModuleInfo,
    ModuleIntegrity, ModuleIntegrityReport, ModuleOptions, ModuleProvenance, NativeConcurrency,
    NativeLibraryInfo, NativeSlotInfo, NativeTokenInfo, ObjectLimits, RuntimeOwner,
    SlotDiscoveryFailure, TokenContext, TokenDrain, TokenIdentity, WindowsDependencySearch,
    WindowsFilePinning, WindowsFilePinningReport, WindowsImageConsistency,
    WindowsImageConsistencyReport, WindowsReparseHandling,
};
pub use module::{
    WindowsActivationAssembly, WindowsActivationContext, WindowsActivationFile,
    WindowsLoaderChannel, WindowsLoaderObservation, WindowsLoaderObservationLimits,
    WindowsLoaderObservations, WindowsLoaderPath, WindowsLoaderPathKind,
    WindowsLoaderRegistryValue, WindowsLoaderReport, WindowsLoaderRequest, WindowsLoaderRequests,
    WindowsLoaderSearchDirectories, WindowsLoaderUnavailable,
};
pub use native::events::SlotEventStatus;
pub use oaep::{OaepParams, SecretPlaintext};
pub use objects::{
    KeyPair, KeySpec, OaepKeySpec, ObjectClass, ObjectRef, ObjectSelector, PublicKeyFingerprint,
};
pub use random::{SecretBytes, SlotEvent};
pub use session::{
    ContextAuthentication, Digest32, PssParams, Session, SessionDropBehavior, SessionInfo,
    Verification,
};
pub use verify_engine::{VerifyEngine, VerifyEngineBuilder, VerifyEngineInfo};

/// Owned activation bytes; debug formatting and implicit cloning are not exposed.
pub struct SecretPin(zeroize::Zeroizing<Vec<u8>>);
impl SecretPin {
    /// Takes ownership of PIN bytes; the caller must control any copies made earlier.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(zeroize::Zeroizing::new(bytes))
    }
    fn erase(&mut self) {
        use zeroize::Zeroize;
        self.0.as_mut_slice().zeroize();
    }
}
impl Drop for SecretPin {
    fn drop(&mut self) {
        self.erase();
    }
}

pub use transport::{
    RsaKeyEncryptionPair, RsaKeyEncryptionPrivate, RsaKeyEncryptionPublic, RsaKeyEncryptionSpec,
};

pub use transport::{HistoricalBoolean, TransportHistoricalAttributes, TransportProtection};

pub use crypto::{IntroducedSigningKey, SigningIntroductionSpec, TransportSigningKeyPair};

pub use crypto::PrivateEncodingReport;

mod mechanism_extension;
pub use mechanism_extension::message::{
    NativeMessageAction, NativeMessagePart, NativeMessageResult, NativeMessageRoute,
};
mod native_kem;
mod native_message;
pub use mechanism_extension::{
    ExtensionBlock, ExtensionDirection, ExtensionInput, ExtensionOperation, ExtensionOutputLength,
    ExtensionOutputRegion, ExtensionParameterOutputs, ExtensionParameters, ExtensionPointer,
    ExtensionPointerTarget, ExtensionRequest, ExtensionResult, MechanismExtension,
    MechanismLayoutProvenance, NativeUnwrappedObject,
};
pub use native_kem::{NativeKemParameters, NativeKemResult};
pub use native_message::NativeMessageParameters;

mod native_mac;
pub use native_mac::{NativeMac, NativeMacAlgorithm, NativeMacParameters, Sha512TMacGeneral};

mod native_protocol;
pub use native_protocol::{NativeCmsParameters, NativeKipParameters, NativeNestedMechanism};
mod native_otp;
pub use native_otp::{
    NativeOtpAlgorithm, NativeOtpLimits, NativeOtpParameter, NativeOtpResult, NativeOtpValue,
};
mod native_rsa_cipher;
mod native_verification;
pub use native_verification::NativeVerificationParameters;
mod native_transport;
pub use native_rsa_cipher::NativeRsaCipherParameters;
pub use native_transport::{
    NativeOaepParameters, NativeSkipjackPrivate, NativeSkipjackRelay, NativeTransportMechanism,
    NativeTransportParameters,
};
mod native_signature;
pub use native_signature::{
    NativeEdDsaParameters, NativePqcCombined, NativePqcContext, NativePqcFamily,
    NativePssAlgorithm, NativeRecoveredMessage, NativeSignature, NativeSignatureAlgorithm,
    NativeSignatureParameters,
};
