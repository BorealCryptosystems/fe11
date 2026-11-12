// SPDX-License-Identifier: Apache-2.0
//! Rejection reasons grouped by technical responsibility.

mod aead_messages;
pub use aead_messages::AeadMessagesRejection;
mod asynchronous_execution;
pub use asynchronous_execution::AsynchronousExecutionRejection;
mod attribute_preparation;
pub use attribute_preparation::AttributePreparationRejection;
mod attribute_values;
pub use attribute_values::AttributeValuesRejection;
mod authentication;
pub use authentication::AuthenticationRejection;
mod callbacks;
pub use callbacks::CallbacksRejection;
mod cancellation;
pub use cancellation::CancellationRejection;
mod checkpoint_capture;
pub use checkpoint_capture::CheckpointCaptureRejection;
mod checkpoint_format;
pub use checkpoint_format::CheckpointFormatRejection;
mod cipher_continuation;
pub use cipher_continuation::CipherContinuationRejection;
mod classical_signatures;
pub use classical_signatures::ClassicalSignaturesRejection;
mod combined_operations;
pub use combined_operations::CombinedOperationsRejection;
mod derived_object_creation;
pub use derived_object_creation::DerivedObjectCreationRejection;
mod detachment;
pub use detachment::DetachmentRejection;
mod diagnostics;
pub use diagnostics::DiagnosticsRejection;
mod digest_continuation;
pub use digest_continuation::DigestContinuationRejection;
mod external_execution;
pub use external_execution::ExternalExecutionRejection;
mod input_bounds;
pub use input_bounds::InputBoundsRejection;
mod key_admission;
pub use key_admission::KeyAdmissionRejection;
mod key_derivation;
pub use key_derivation::KeyDerivationRejection;
mod key_encapsulation;
pub use key_encapsulation::KeyEncapsulationRejection;
mod key_encoding;
pub use key_encoding::KeyEncodingRejection;
mod key_transport;
pub use key_transport::KeyTransportRejection;
mod local_admission;
pub use local_admission::LocalAdmissionRejection;
mod mechanism_extensions;
pub use mechanism_extensions::MechanismExtensionsRejection;
mod mechanisms;
pub use mechanisms::MechanismsRejection;
mod memory_accounting;
pub use memory_accounting::MemoryAccountingRejection;
mod memory_allocation;
pub use memory_allocation::MemoryAllocationRejection;
mod message_record;
pub use message_record::MessageRecordRejection;
mod module_configuration;
pub use module_configuration::ModuleConfigurationRejection;
mod module_lifecycle;
pub use module_lifecycle::ModuleLifecycleRejection;
mod native_derivation;
pub use native_derivation::NativeDerivationRejection;
mod native_digest;
pub use native_digest::NativeDigestRejection;
mod native_encapsulation;
pub use native_encapsulation::NativeEncapsulationRejection;
mod native_execution;
pub use native_execution::NativeExecutionRejection;
mod native_interfaces;
pub use native_interfaces::NativeInterfacesRejection;
mod native_loading;
pub use native_loading::NativeLoadingRejection;
mod native_mac;
pub use native_mac::NativeMacRejection;
mod native_messages;
pub use native_messages::NativeMessagesRejection;
mod native_otp;
pub use native_otp::NativeOtpRejection;
mod native_protocols;
pub use native_protocols::NativeProtocolsRejection;
mod native_signature;
pub use native_signature::NativeSignatureRejection;
mod native_transport;
pub use native_transport::NativeTransportRejection;
mod object_cleanup;
pub use object_cleanup::ObjectCleanupRejection;
mod object_content;
pub use object_content::ObjectContentRejection;
mod object_copy;
pub use object_copy::ObjectCopyRejection;
mod object_creation;
pub use object_creation::ObjectCreationRejection;
mod object_destination;
pub use object_destination::ObjectDestinationRejection;
mod object_mutation;
pub use object_mutation::ObjectMutationRejection;
mod object_observation;
pub use object_observation::ObjectObservationRejection;
mod object_publication;
pub use object_publication::ObjectPublicationRejection;
mod object_references;
pub use object_references::ObjectReferencesRejection;
mod object_search;
pub use object_search::ObjectSearchRejection;
mod operation_keys;
pub use operation_keys::OperationKeysRejection;
mod operation_ownership;
pub use operation_ownership::OperationOwnershipRejection;
mod operation_record;
pub use operation_record::OperationRecordRejection;
mod operation_recovery;
pub use operation_recovery::OperationRecoveryRejection;
mod operation_state;
pub use operation_state::OperationStateRejection;
mod persistence;
pub use persistence::PersistenceRejection;
mod post_quantum_keys;
pub use post_quantum_keys::PostQuantumKeysRejection;
mod public_verification;
pub use public_verification::PublicVerificationRejection;
mod random_generation;
pub use random_generation::RandomGenerationRejection;
mod recovery_record;
pub use recovery_record::RecoveryRecordRejection;
mod reference_registry;
pub use reference_registry::ReferenceRegistryRejection;
mod restoration;
pub use restoration::RestorationRejection;
mod session_accounting;
pub use session_accounting::SessionAccountingRejection;
mod session_lifecycle;
pub use session_lifecycle::SessionLifecycleRejection;
mod signature_continuation;
pub use signature_continuation::SignatureContinuationRejection;
mod signature_messages;
pub use signature_messages::SignatureMessagesRejection;
mod symmetric_parameters;
pub use symmetric_parameters::SymmetricParametersRejection;
mod token_administration;
pub use token_administration::TokenAdministrationRejection;
mod verification_engine;
pub use verification_engine::VerificationEngineRejection;

/// Typed rejection cause; its enclosing error retains effect information.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectionReason {
    /// Aead Messages diagnostic.
    AeadMessages(AeadMessagesRejection),
    /// Asynchronous Execution diagnostic.
    AsynchronousExecution(AsynchronousExecutionRejection),
    /// Attribute Preparation diagnostic.
    AttributePreparation(AttributePreparationRejection),
    /// Attribute Values diagnostic.
    AttributeValues(AttributeValuesRejection),
    /// Authentication diagnostic.
    Authentication(AuthenticationRejection),
    /// Callbacks diagnostic.
    Callbacks(CallbacksRejection),
    /// Cancellation diagnostic.
    Cancellation(CancellationRejection),
    /// Checkpoint Capture diagnostic.
    CheckpointCapture(CheckpointCaptureRejection),
    /// Checkpoint Format diagnostic.
    CheckpointFormat(CheckpointFormatRejection),
    /// Cipher Continuation diagnostic.
    CipherContinuation(CipherContinuationRejection),
    /// Classical Signatures diagnostic.
    ClassicalSignatures(ClassicalSignaturesRejection),
    /// Combined Operations diagnostic.
    CombinedOperations(CombinedOperationsRejection),
    /// Derived Object Creation diagnostic.
    DerivedObjectCreation(DerivedObjectCreationRejection),
    /// Detachment diagnostic.
    Detachment(DetachmentRejection),
    /// Diagnostics diagnostic.
    Diagnostics(DiagnosticsRejection),
    /// Digest Continuation diagnostic.
    DigestContinuation(DigestContinuationRejection),
    /// External Execution diagnostic.
    ExternalExecution(ExternalExecutionRejection),
    /// Input Bounds diagnostic.
    InputBounds(InputBoundsRejection),
    /// Key Admission diagnostic.
    KeyAdmission(KeyAdmissionRejection),
    /// Key Derivation diagnostic.
    KeyDerivation(KeyDerivationRejection),
    /// Key Encapsulation diagnostic.
    KeyEncapsulation(KeyEncapsulationRejection),
    /// Key Encoding diagnostic.
    KeyEncoding(KeyEncodingRejection),
    /// Key Transport diagnostic.
    KeyTransport(KeyTransportRejection),
    /// Local Admission diagnostic.
    LocalAdmission(LocalAdmissionRejection),
    /// Mechanism Extensions diagnostic.
    MechanismExtensions(MechanismExtensionsRejection),
    /// Mechanisms diagnostic.
    Mechanisms(MechanismsRejection),
    /// Memory Accounting diagnostic.
    MemoryAccounting(MemoryAccountingRejection),
    /// Memory Allocation diagnostic.
    MemoryAllocation(MemoryAllocationRejection),
    /// Message Record diagnostic.
    MessageRecord(MessageRecordRejection),
    /// Module Configuration diagnostic.
    ModuleConfiguration(ModuleConfigurationRejection),
    /// Module Lifecycle diagnostic.
    ModuleLifecycle(ModuleLifecycleRejection),
    /// Native Derivation diagnostic.
    NativeDerivation(NativeDerivationRejection),
    /// Native Digest diagnostic.
    NativeDigest(NativeDigestRejection),
    /// Native Encapsulation diagnostic.
    NativeEncapsulation(NativeEncapsulationRejection),
    /// Native Execution diagnostic.
    NativeExecution(NativeExecutionRejection),
    /// Native Interfaces diagnostic.
    NativeInterfaces(NativeInterfacesRejection),
    /// Native Loading diagnostic.
    NativeLoading(NativeLoadingRejection),
    /// Native Mac diagnostic.
    NativeMac(NativeMacRejection),
    /// Native Messages diagnostic.
    NativeMessages(NativeMessagesRejection),
    /// Native Otp diagnostic.
    NativeOtp(NativeOtpRejection),
    /// Native Protocols diagnostic.
    NativeProtocols(NativeProtocolsRejection),
    /// Native Signature diagnostic.
    NativeSignature(NativeSignatureRejection),
    /// Native Transport diagnostic.
    NativeTransport(NativeTransportRejection),
    /// Object Cleanup diagnostic.
    ObjectCleanup(ObjectCleanupRejection),
    /// Object Content diagnostic.
    ObjectContent(ObjectContentRejection),
    /// Object Copy diagnostic.
    ObjectCopy(ObjectCopyRejection),
    /// Object Creation diagnostic.
    ObjectCreation(ObjectCreationRejection),
    /// Object Destination diagnostic.
    ObjectDestination(ObjectDestinationRejection),
    /// Object Mutation diagnostic.
    ObjectMutation(ObjectMutationRejection),
    /// Object Observation diagnostic.
    ObjectObservation(ObjectObservationRejection),
    /// Object Publication diagnostic.
    ObjectPublication(ObjectPublicationRejection),
    /// Object References diagnostic.
    ObjectReferences(ObjectReferencesRejection),
    /// Object Search diagnostic.
    ObjectSearch(ObjectSearchRejection),
    /// Operation Keys diagnostic.
    OperationKeys(OperationKeysRejection),
    /// Operation Ownership diagnostic.
    OperationOwnership(OperationOwnershipRejection),
    /// Operation Record diagnostic.
    OperationRecord(OperationRecordRejection),
    /// Operation Recovery diagnostic.
    OperationRecovery(OperationRecoveryRejection),
    /// Operation State diagnostic.
    OperationState(OperationStateRejection),
    /// Persistence diagnostic.
    Persistence(PersistenceRejection),
    /// Post Quantum Keys diagnostic.
    PostQuantumKeys(PostQuantumKeysRejection),
    /// Public Verification diagnostic.
    PublicVerification(PublicVerificationRejection),
    /// Random Generation diagnostic.
    RandomGeneration(RandomGenerationRejection),
    /// Recovery Record diagnostic.
    RecoveryRecord(RecoveryRecordRejection),
    /// Reference Registry diagnostic.
    ReferenceRegistry(ReferenceRegistryRejection),
    /// Restoration diagnostic.
    Restoration(RestorationRejection),
    /// Session Accounting diagnostic.
    SessionAccounting(SessionAccountingRejection),
    /// Session Lifecycle diagnostic.
    SessionLifecycle(SessionLifecycleRejection),
    /// Signature Continuation diagnostic.
    SignatureContinuation(SignatureContinuationRejection),
    /// Signature Messages diagnostic.
    SignatureMessages(SignatureMessagesRejection),
    /// Symmetric Parameters diagnostic.
    SymmetricParameters(SymmetricParametersRejection),
    /// Token Administration diagnostic.
    TokenAdministration(TokenAdministrationRejection),
    /// Verification Engine diagnostic.
    VerificationEngine(VerificationEngineRejection),
}

impl std::fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AeadMessages(reason) => std::fmt::Display::fmt(reason, f),
            Self::AsynchronousExecution(reason) => std::fmt::Display::fmt(reason, f),
            Self::AttributePreparation(reason) => std::fmt::Display::fmt(reason, f),
            Self::AttributeValues(reason) => std::fmt::Display::fmt(reason, f),
            Self::Authentication(reason) => std::fmt::Display::fmt(reason, f),
            Self::Callbacks(reason) => std::fmt::Display::fmt(reason, f),
            Self::Cancellation(reason) => std::fmt::Display::fmt(reason, f),
            Self::CheckpointCapture(reason) => std::fmt::Display::fmt(reason, f),
            Self::CheckpointFormat(reason) => std::fmt::Display::fmt(reason, f),
            Self::CipherContinuation(reason) => std::fmt::Display::fmt(reason, f),
            Self::ClassicalSignatures(reason) => std::fmt::Display::fmt(reason, f),
            Self::CombinedOperations(reason) => std::fmt::Display::fmt(reason, f),
            Self::DerivedObjectCreation(reason) => std::fmt::Display::fmt(reason, f),
            Self::Detachment(reason) => std::fmt::Display::fmt(reason, f),
            Self::Diagnostics(reason) => std::fmt::Display::fmt(reason, f),
            Self::DigestContinuation(reason) => std::fmt::Display::fmt(reason, f),
            Self::ExternalExecution(reason) => std::fmt::Display::fmt(reason, f),
            Self::InputBounds(reason) => std::fmt::Display::fmt(reason, f),
            Self::KeyAdmission(reason) => std::fmt::Display::fmt(reason, f),
            Self::KeyDerivation(reason) => std::fmt::Display::fmt(reason, f),
            Self::KeyEncapsulation(reason) => std::fmt::Display::fmt(reason, f),
            Self::KeyEncoding(reason) => std::fmt::Display::fmt(reason, f),
            Self::KeyTransport(reason) => std::fmt::Display::fmt(reason, f),
            Self::LocalAdmission(reason) => std::fmt::Display::fmt(reason, f),
            Self::MechanismExtensions(reason) => std::fmt::Display::fmt(reason, f),
            Self::Mechanisms(reason) => std::fmt::Display::fmt(reason, f),
            Self::MemoryAccounting(reason) => std::fmt::Display::fmt(reason, f),
            Self::MemoryAllocation(reason) => std::fmt::Display::fmt(reason, f),
            Self::MessageRecord(reason) => std::fmt::Display::fmt(reason, f),
            Self::ModuleConfiguration(reason) => std::fmt::Display::fmt(reason, f),
            Self::ModuleLifecycle(reason) => std::fmt::Display::fmt(reason, f),
            Self::NativeDerivation(reason) => std::fmt::Display::fmt(reason, f),
            Self::NativeDigest(reason) => std::fmt::Display::fmt(reason, f),
            Self::NativeEncapsulation(reason) => std::fmt::Display::fmt(reason, f),
            Self::NativeExecution(reason) => std::fmt::Display::fmt(reason, f),
            Self::NativeInterfaces(reason) => std::fmt::Display::fmt(reason, f),
            Self::NativeLoading(reason) => std::fmt::Display::fmt(reason, f),
            Self::NativeMac(reason) => std::fmt::Display::fmt(reason, f),
            Self::NativeMessages(reason) => std::fmt::Display::fmt(reason, f),
            Self::NativeOtp(reason) => std::fmt::Display::fmt(reason, f),
            Self::NativeProtocols(reason) => std::fmt::Display::fmt(reason, f),
            Self::NativeSignature(reason) => std::fmt::Display::fmt(reason, f),
            Self::NativeTransport(reason) => std::fmt::Display::fmt(reason, f),
            Self::ObjectCleanup(reason) => std::fmt::Display::fmt(reason, f),
            Self::ObjectContent(reason) => std::fmt::Display::fmt(reason, f),
            Self::ObjectCopy(reason) => std::fmt::Display::fmt(reason, f),
            Self::ObjectCreation(reason) => std::fmt::Display::fmt(reason, f),
            Self::ObjectDestination(reason) => std::fmt::Display::fmt(reason, f),
            Self::ObjectMutation(reason) => std::fmt::Display::fmt(reason, f),
            Self::ObjectObservation(reason) => std::fmt::Display::fmt(reason, f),
            Self::ObjectPublication(reason) => std::fmt::Display::fmt(reason, f),
            Self::ObjectReferences(reason) => std::fmt::Display::fmt(reason, f),
            Self::ObjectSearch(reason) => std::fmt::Display::fmt(reason, f),
            Self::OperationKeys(reason) => std::fmt::Display::fmt(reason, f),
            Self::OperationOwnership(reason) => std::fmt::Display::fmt(reason, f),
            Self::OperationRecord(reason) => std::fmt::Display::fmt(reason, f),
            Self::OperationRecovery(reason) => std::fmt::Display::fmt(reason, f),
            Self::OperationState(reason) => std::fmt::Display::fmt(reason, f),
            Self::Persistence(reason) => std::fmt::Display::fmt(reason, f),
            Self::PostQuantumKeys(reason) => std::fmt::Display::fmt(reason, f),
            Self::PublicVerification(reason) => std::fmt::Display::fmt(reason, f),
            Self::RandomGeneration(reason) => std::fmt::Display::fmt(reason, f),
            Self::RecoveryRecord(reason) => std::fmt::Display::fmt(reason, f),
            Self::ReferenceRegistry(reason) => std::fmt::Display::fmt(reason, f),
            Self::Restoration(reason) => std::fmt::Display::fmt(reason, f),
            Self::SessionAccounting(reason) => std::fmt::Display::fmt(reason, f),
            Self::SessionLifecycle(reason) => std::fmt::Display::fmt(reason, f),
            Self::SignatureContinuation(reason) => std::fmt::Display::fmt(reason, f),
            Self::SignatureMessages(reason) => std::fmt::Display::fmt(reason, f),
            Self::SymmetricParameters(reason) => std::fmt::Display::fmt(reason, f),
            Self::TokenAdministration(reason) => std::fmt::Display::fmt(reason, f),
            Self::VerificationEngine(reason) => std::fmt::Display::fmt(reason, f),
        }
    }
}

impl From<AeadMessagesRejection> for RejectionReason {
    fn from(reason: AeadMessagesRejection) -> Self {
        Self::AeadMessages(reason)
    }
}

impl From<AsynchronousExecutionRejection> for RejectionReason {
    fn from(reason: AsynchronousExecutionRejection) -> Self {
        Self::AsynchronousExecution(reason)
    }
}

impl From<AttributePreparationRejection> for RejectionReason {
    fn from(reason: AttributePreparationRejection) -> Self {
        Self::AttributePreparation(reason)
    }
}

impl From<AttributeValuesRejection> for RejectionReason {
    fn from(reason: AttributeValuesRejection) -> Self {
        Self::AttributeValues(reason)
    }
}

impl From<AuthenticationRejection> for RejectionReason {
    fn from(reason: AuthenticationRejection) -> Self {
        Self::Authentication(reason)
    }
}

impl From<CallbacksRejection> for RejectionReason {
    fn from(reason: CallbacksRejection) -> Self {
        Self::Callbacks(reason)
    }
}

impl From<CancellationRejection> for RejectionReason {
    fn from(reason: CancellationRejection) -> Self {
        Self::Cancellation(reason)
    }
}

impl From<CheckpointCaptureRejection> for RejectionReason {
    fn from(reason: CheckpointCaptureRejection) -> Self {
        Self::CheckpointCapture(reason)
    }
}

impl From<CheckpointFormatRejection> for RejectionReason {
    fn from(reason: CheckpointFormatRejection) -> Self {
        Self::CheckpointFormat(reason)
    }
}

impl From<CipherContinuationRejection> for RejectionReason {
    fn from(reason: CipherContinuationRejection) -> Self {
        Self::CipherContinuation(reason)
    }
}

impl From<ClassicalSignaturesRejection> for RejectionReason {
    fn from(reason: ClassicalSignaturesRejection) -> Self {
        Self::ClassicalSignatures(reason)
    }
}

impl From<CombinedOperationsRejection> for RejectionReason {
    fn from(reason: CombinedOperationsRejection) -> Self {
        Self::CombinedOperations(reason)
    }
}

impl From<DerivedObjectCreationRejection> for RejectionReason {
    fn from(reason: DerivedObjectCreationRejection) -> Self {
        Self::DerivedObjectCreation(reason)
    }
}

impl From<DetachmentRejection> for RejectionReason {
    fn from(reason: DetachmentRejection) -> Self {
        Self::Detachment(reason)
    }
}

impl From<DiagnosticsRejection> for RejectionReason {
    fn from(reason: DiagnosticsRejection) -> Self {
        Self::Diagnostics(reason)
    }
}

impl From<DigestContinuationRejection> for RejectionReason {
    fn from(reason: DigestContinuationRejection) -> Self {
        Self::DigestContinuation(reason)
    }
}

impl From<ExternalExecutionRejection> for RejectionReason {
    fn from(reason: ExternalExecutionRejection) -> Self {
        Self::ExternalExecution(reason)
    }
}

impl From<InputBoundsRejection> for RejectionReason {
    fn from(reason: InputBoundsRejection) -> Self {
        Self::InputBounds(reason)
    }
}

impl From<KeyAdmissionRejection> for RejectionReason {
    fn from(reason: KeyAdmissionRejection) -> Self {
        Self::KeyAdmission(reason)
    }
}

impl From<KeyDerivationRejection> for RejectionReason {
    fn from(reason: KeyDerivationRejection) -> Self {
        Self::KeyDerivation(reason)
    }
}

impl From<KeyEncapsulationRejection> for RejectionReason {
    fn from(reason: KeyEncapsulationRejection) -> Self {
        Self::KeyEncapsulation(reason)
    }
}

impl From<KeyEncodingRejection> for RejectionReason {
    fn from(reason: KeyEncodingRejection) -> Self {
        Self::KeyEncoding(reason)
    }
}

impl From<KeyTransportRejection> for RejectionReason {
    fn from(reason: KeyTransportRejection) -> Self {
        Self::KeyTransport(reason)
    }
}

impl From<LocalAdmissionRejection> for RejectionReason {
    fn from(reason: LocalAdmissionRejection) -> Self {
        Self::LocalAdmission(reason)
    }
}

impl From<MechanismExtensionsRejection> for RejectionReason {
    fn from(reason: MechanismExtensionsRejection) -> Self {
        Self::MechanismExtensions(reason)
    }
}

impl From<MechanismsRejection> for RejectionReason {
    fn from(reason: MechanismsRejection) -> Self {
        Self::Mechanisms(reason)
    }
}

impl From<MemoryAccountingRejection> for RejectionReason {
    fn from(reason: MemoryAccountingRejection) -> Self {
        Self::MemoryAccounting(reason)
    }
}

impl From<MemoryAllocationRejection> for RejectionReason {
    fn from(reason: MemoryAllocationRejection) -> Self {
        Self::MemoryAllocation(reason)
    }
}

impl From<MessageRecordRejection> for RejectionReason {
    fn from(reason: MessageRecordRejection) -> Self {
        Self::MessageRecord(reason)
    }
}

impl From<ModuleConfigurationRejection> for RejectionReason {
    fn from(reason: ModuleConfigurationRejection) -> Self {
        Self::ModuleConfiguration(reason)
    }
}

impl From<ModuleLifecycleRejection> for RejectionReason {
    fn from(reason: ModuleLifecycleRejection) -> Self {
        Self::ModuleLifecycle(reason)
    }
}

impl From<NativeDerivationRejection> for RejectionReason {
    fn from(reason: NativeDerivationRejection) -> Self {
        Self::NativeDerivation(reason)
    }
}

impl From<NativeDigestRejection> for RejectionReason {
    fn from(reason: NativeDigestRejection) -> Self {
        Self::NativeDigest(reason)
    }
}

impl From<NativeEncapsulationRejection> for RejectionReason {
    fn from(reason: NativeEncapsulationRejection) -> Self {
        Self::NativeEncapsulation(reason)
    }
}

impl From<NativeExecutionRejection> for RejectionReason {
    fn from(reason: NativeExecutionRejection) -> Self {
        Self::NativeExecution(reason)
    }
}

impl From<NativeInterfacesRejection> for RejectionReason {
    fn from(reason: NativeInterfacesRejection) -> Self {
        Self::NativeInterfaces(reason)
    }
}

impl From<NativeLoadingRejection> for RejectionReason {
    fn from(reason: NativeLoadingRejection) -> Self {
        Self::NativeLoading(reason)
    }
}

impl From<NativeMacRejection> for RejectionReason {
    fn from(reason: NativeMacRejection) -> Self {
        Self::NativeMac(reason)
    }
}

impl From<NativeMessagesRejection> for RejectionReason {
    fn from(reason: NativeMessagesRejection) -> Self {
        Self::NativeMessages(reason)
    }
}

impl From<NativeOtpRejection> for RejectionReason {
    fn from(reason: NativeOtpRejection) -> Self {
        Self::NativeOtp(reason)
    }
}

impl From<NativeProtocolsRejection> for RejectionReason {
    fn from(reason: NativeProtocolsRejection) -> Self {
        Self::NativeProtocols(reason)
    }
}

impl From<NativeSignatureRejection> for RejectionReason {
    fn from(reason: NativeSignatureRejection) -> Self {
        Self::NativeSignature(reason)
    }
}

impl From<NativeTransportRejection> for RejectionReason {
    fn from(reason: NativeTransportRejection) -> Self {
        Self::NativeTransport(reason)
    }
}

impl From<ObjectCleanupRejection> for RejectionReason {
    fn from(reason: ObjectCleanupRejection) -> Self {
        Self::ObjectCleanup(reason)
    }
}

impl From<ObjectContentRejection> for RejectionReason {
    fn from(reason: ObjectContentRejection) -> Self {
        Self::ObjectContent(reason)
    }
}

impl From<ObjectCopyRejection> for RejectionReason {
    fn from(reason: ObjectCopyRejection) -> Self {
        Self::ObjectCopy(reason)
    }
}

impl From<ObjectCreationRejection> for RejectionReason {
    fn from(reason: ObjectCreationRejection) -> Self {
        Self::ObjectCreation(reason)
    }
}

impl From<ObjectDestinationRejection> for RejectionReason {
    fn from(reason: ObjectDestinationRejection) -> Self {
        Self::ObjectDestination(reason)
    }
}

impl From<ObjectMutationRejection> for RejectionReason {
    fn from(reason: ObjectMutationRejection) -> Self {
        Self::ObjectMutation(reason)
    }
}

impl From<ObjectObservationRejection> for RejectionReason {
    fn from(reason: ObjectObservationRejection) -> Self {
        Self::ObjectObservation(reason)
    }
}

impl From<ObjectPublicationRejection> for RejectionReason {
    fn from(reason: ObjectPublicationRejection) -> Self {
        Self::ObjectPublication(reason)
    }
}

impl From<ObjectReferencesRejection> for RejectionReason {
    fn from(reason: ObjectReferencesRejection) -> Self {
        Self::ObjectReferences(reason)
    }
}

impl From<ObjectSearchRejection> for RejectionReason {
    fn from(reason: ObjectSearchRejection) -> Self {
        Self::ObjectSearch(reason)
    }
}

impl From<OperationKeysRejection> for RejectionReason {
    fn from(reason: OperationKeysRejection) -> Self {
        Self::OperationKeys(reason)
    }
}

impl From<OperationOwnershipRejection> for RejectionReason {
    fn from(reason: OperationOwnershipRejection) -> Self {
        Self::OperationOwnership(reason)
    }
}

impl From<OperationRecordRejection> for RejectionReason {
    fn from(reason: OperationRecordRejection) -> Self {
        Self::OperationRecord(reason)
    }
}

impl From<OperationRecoveryRejection> for RejectionReason {
    fn from(reason: OperationRecoveryRejection) -> Self {
        Self::OperationRecovery(reason)
    }
}

impl From<OperationStateRejection> for RejectionReason {
    fn from(reason: OperationStateRejection) -> Self {
        Self::OperationState(reason)
    }
}

impl From<PersistenceRejection> for RejectionReason {
    fn from(reason: PersistenceRejection) -> Self {
        Self::Persistence(reason)
    }
}

impl From<PostQuantumKeysRejection> for RejectionReason {
    fn from(reason: PostQuantumKeysRejection) -> Self {
        Self::PostQuantumKeys(reason)
    }
}

impl From<PublicVerificationRejection> for RejectionReason {
    fn from(reason: PublicVerificationRejection) -> Self {
        Self::PublicVerification(reason)
    }
}

impl From<RandomGenerationRejection> for RejectionReason {
    fn from(reason: RandomGenerationRejection) -> Self {
        Self::RandomGeneration(reason)
    }
}

impl From<RecoveryRecordRejection> for RejectionReason {
    fn from(reason: RecoveryRecordRejection) -> Self {
        Self::RecoveryRecord(reason)
    }
}

impl From<ReferenceRegistryRejection> for RejectionReason {
    fn from(reason: ReferenceRegistryRejection) -> Self {
        Self::ReferenceRegistry(reason)
    }
}

impl From<RestorationRejection> for RejectionReason {
    fn from(reason: RestorationRejection) -> Self {
        Self::Restoration(reason)
    }
}

impl From<SessionAccountingRejection> for RejectionReason {
    fn from(reason: SessionAccountingRejection) -> Self {
        Self::SessionAccounting(reason)
    }
}

impl From<SessionLifecycleRejection> for RejectionReason {
    fn from(reason: SessionLifecycleRejection) -> Self {
        Self::SessionLifecycle(reason)
    }
}

impl From<SignatureContinuationRejection> for RejectionReason {
    fn from(reason: SignatureContinuationRejection) -> Self {
        Self::SignatureContinuation(reason)
    }
}

impl From<SignatureMessagesRejection> for RejectionReason {
    fn from(reason: SignatureMessagesRejection) -> Self {
        Self::SignatureMessages(reason)
    }
}

impl From<SymmetricParametersRejection> for RejectionReason {
    fn from(reason: SymmetricParametersRejection) -> Self {
        Self::SymmetricParameters(reason)
    }
}

impl From<TokenAdministrationRejection> for RejectionReason {
    fn from(reason: TokenAdministrationRejection) -> Self {
        Self::TokenAdministration(reason)
    }
}

impl From<VerificationEngineRejection> for RejectionReason {
    fn from(reason: VerificationEngineRejection) -> Self {
        Self::VerificationEngine(reason)
    }
}
