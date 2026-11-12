// SPDX-License-Identifier: Apache-2.0
//! Busy reasons grouped by technical responsibility.

mod aead_messages;
pub use aead_messages::AeadMessagesBusy;
mod asynchronous_execution;
pub use asynchronous_execution::AsynchronousExecutionBusy;
mod authentication;
pub use authentication::AuthenticationBusy;
mod callbacks;
pub use callbacks::CallbacksBusy;
mod cancellation;
pub use cancellation::CancellationBusy;
mod checkpoint_capture;
pub use checkpoint_capture::CheckpointCaptureBusy;
mod cipher_continuation;
pub use cipher_continuation::CipherContinuationBusy;
mod combined_operations;
pub use combined_operations::CombinedOperationsBusy;
mod derived_object_creation;
pub use derived_object_creation::DerivedObjectCreationBusy;
mod detachment;
pub use detachment::DetachmentBusy;
mod digest_continuation;
pub use digest_continuation::DigestContinuationBusy;
mod external_execution;
pub use external_execution::ExternalExecutionBusy;
mod key_admission;
pub use key_admission::KeyAdmissionBusy;
mod local_admission;
pub use local_admission::LocalAdmissionBusy;
mod memory_accounting;
pub use memory_accounting::MemoryAccountingBusy;
mod module_lifecycle;
pub use module_lifecycle::ModuleLifecycleBusy;
mod native_execution;
pub use native_execution::NativeExecutionBusy;
mod native_loading;
pub use native_loading::NativeLoadingBusy;
mod native_messages;
pub use native_messages::NativeMessagesBusy;
mod object_cleanup;
pub use object_cleanup::ObjectCleanupBusy;
mod object_copy;
pub use object_copy::ObjectCopyBusy;
mod object_creation;
pub use object_creation::ObjectCreationBusy;
mod object_mutation;
pub use object_mutation::ObjectMutationBusy;
mod object_observation;
pub use object_observation::ObjectObservationBusy;
mod object_publication;
pub use object_publication::ObjectPublicationBusy;
mod operation_ownership;
pub use operation_ownership::OperationOwnershipBusy;
mod operation_recovery;
pub use operation_recovery::OperationRecoveryBusy;
mod operation_state;
pub use operation_state::OperationStateBusy;
mod reference_registry;
pub use reference_registry::ReferenceRegistryBusy;
mod restoration;
pub use restoration::RestorationBusy;
mod session_accounting;
pub use session_accounting::SessionAccountingBusy;
mod session_lifecycle;
pub use session_lifecycle::SessionLifecycleBusy;
mod signature_continuation;
pub use signature_continuation::SignatureContinuationBusy;
mod signature_messages;
pub use signature_messages::SignatureMessagesBusy;
mod token_administration;
pub use token_administration::TokenAdministrationBusy;

/// Typed busy cause; its enclosing error retains effect information.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BusyReason {
    /// Aead Messages diagnostic.
    AeadMessages(AeadMessagesBusy),
    /// Asynchronous Execution diagnostic.
    AsynchronousExecution(AsynchronousExecutionBusy),
    /// Authentication diagnostic.
    Authentication(AuthenticationBusy),
    /// Callbacks diagnostic.
    Callbacks(CallbacksBusy),
    /// Cancellation diagnostic.
    Cancellation(CancellationBusy),
    /// Checkpoint Capture diagnostic.
    CheckpointCapture(CheckpointCaptureBusy),
    /// Cipher Continuation diagnostic.
    CipherContinuation(CipherContinuationBusy),
    /// Combined Operations diagnostic.
    CombinedOperations(CombinedOperationsBusy),
    /// Derived Object Creation diagnostic.
    DerivedObjectCreation(DerivedObjectCreationBusy),
    /// Detachment diagnostic.
    Detachment(DetachmentBusy),
    /// Digest Continuation diagnostic.
    DigestContinuation(DigestContinuationBusy),
    /// External Execution diagnostic.
    ExternalExecution(ExternalExecutionBusy),
    /// Key Admission diagnostic.
    KeyAdmission(KeyAdmissionBusy),
    /// Local Admission diagnostic.
    LocalAdmission(LocalAdmissionBusy),
    /// Memory Accounting diagnostic.
    MemoryAccounting(MemoryAccountingBusy),
    /// Module Lifecycle diagnostic.
    ModuleLifecycle(ModuleLifecycleBusy),
    /// Native Execution diagnostic.
    NativeExecution(NativeExecutionBusy),
    /// Native Loading diagnostic.
    NativeLoading(NativeLoadingBusy),
    /// Native Messages diagnostic.
    NativeMessages(NativeMessagesBusy),
    /// Object Cleanup diagnostic.
    ObjectCleanup(ObjectCleanupBusy),
    /// Object Copy diagnostic.
    ObjectCopy(ObjectCopyBusy),
    /// Object Creation diagnostic.
    ObjectCreation(ObjectCreationBusy),
    /// Object Mutation diagnostic.
    ObjectMutation(ObjectMutationBusy),
    /// Object Observation diagnostic.
    ObjectObservation(ObjectObservationBusy),
    /// Object Publication diagnostic.
    ObjectPublication(ObjectPublicationBusy),
    /// Operation Ownership diagnostic.
    OperationOwnership(OperationOwnershipBusy),
    /// Operation Recovery diagnostic.
    OperationRecovery(OperationRecoveryBusy),
    /// Operation State diagnostic.
    OperationState(OperationStateBusy),
    /// Reference Registry diagnostic.
    ReferenceRegistry(ReferenceRegistryBusy),
    /// Restoration diagnostic.
    Restoration(RestorationBusy),
    /// Session Accounting diagnostic.
    SessionAccounting(SessionAccountingBusy),
    /// Session Lifecycle diagnostic.
    SessionLifecycle(SessionLifecycleBusy),
    /// Signature Continuation diagnostic.
    SignatureContinuation(SignatureContinuationBusy),
    /// Signature Messages diagnostic.
    SignatureMessages(SignatureMessagesBusy),
    /// Token Administration diagnostic.
    TokenAdministration(TokenAdministrationBusy),
}

impl std::fmt::Display for BusyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AeadMessages(reason) => std::fmt::Display::fmt(reason, f),
            Self::AsynchronousExecution(reason) => std::fmt::Display::fmt(reason, f),
            Self::Authentication(reason) => std::fmt::Display::fmt(reason, f),
            Self::Callbacks(reason) => std::fmt::Display::fmt(reason, f),
            Self::Cancellation(reason) => std::fmt::Display::fmt(reason, f),
            Self::CheckpointCapture(reason) => std::fmt::Display::fmt(reason, f),
            Self::CipherContinuation(reason) => std::fmt::Display::fmt(reason, f),
            Self::CombinedOperations(reason) => std::fmt::Display::fmt(reason, f),
            Self::DerivedObjectCreation(reason) => std::fmt::Display::fmt(reason, f),
            Self::Detachment(reason) => std::fmt::Display::fmt(reason, f),
            Self::DigestContinuation(reason) => std::fmt::Display::fmt(reason, f),
            Self::ExternalExecution(reason) => std::fmt::Display::fmt(reason, f),
            Self::KeyAdmission(reason) => std::fmt::Display::fmt(reason, f),
            Self::LocalAdmission(reason) => std::fmt::Display::fmt(reason, f),
            Self::MemoryAccounting(reason) => std::fmt::Display::fmt(reason, f),
            Self::ModuleLifecycle(reason) => std::fmt::Display::fmt(reason, f),
            Self::NativeExecution(reason) => std::fmt::Display::fmt(reason, f),
            Self::NativeLoading(reason) => std::fmt::Display::fmt(reason, f),
            Self::NativeMessages(reason) => std::fmt::Display::fmt(reason, f),
            Self::ObjectCleanup(reason) => std::fmt::Display::fmt(reason, f),
            Self::ObjectCopy(reason) => std::fmt::Display::fmt(reason, f),
            Self::ObjectCreation(reason) => std::fmt::Display::fmt(reason, f),
            Self::ObjectMutation(reason) => std::fmt::Display::fmt(reason, f),
            Self::ObjectObservation(reason) => std::fmt::Display::fmt(reason, f),
            Self::ObjectPublication(reason) => std::fmt::Display::fmt(reason, f),
            Self::OperationOwnership(reason) => std::fmt::Display::fmt(reason, f),
            Self::OperationRecovery(reason) => std::fmt::Display::fmt(reason, f),
            Self::OperationState(reason) => std::fmt::Display::fmt(reason, f),
            Self::ReferenceRegistry(reason) => std::fmt::Display::fmt(reason, f),
            Self::Restoration(reason) => std::fmt::Display::fmt(reason, f),
            Self::SessionAccounting(reason) => std::fmt::Display::fmt(reason, f),
            Self::SessionLifecycle(reason) => std::fmt::Display::fmt(reason, f),
            Self::SignatureContinuation(reason) => std::fmt::Display::fmt(reason, f),
            Self::SignatureMessages(reason) => std::fmt::Display::fmt(reason, f),
            Self::TokenAdministration(reason) => std::fmt::Display::fmt(reason, f),
        }
    }
}

impl From<AeadMessagesBusy> for BusyReason {
    fn from(reason: AeadMessagesBusy) -> Self {
        Self::AeadMessages(reason)
    }
}

impl From<AsynchronousExecutionBusy> for BusyReason {
    fn from(reason: AsynchronousExecutionBusy) -> Self {
        Self::AsynchronousExecution(reason)
    }
}

impl From<AuthenticationBusy> for BusyReason {
    fn from(reason: AuthenticationBusy) -> Self {
        Self::Authentication(reason)
    }
}

impl From<CallbacksBusy> for BusyReason {
    fn from(reason: CallbacksBusy) -> Self {
        Self::Callbacks(reason)
    }
}

impl From<CancellationBusy> for BusyReason {
    fn from(reason: CancellationBusy) -> Self {
        Self::Cancellation(reason)
    }
}

impl From<CheckpointCaptureBusy> for BusyReason {
    fn from(reason: CheckpointCaptureBusy) -> Self {
        Self::CheckpointCapture(reason)
    }
}

impl From<CipherContinuationBusy> for BusyReason {
    fn from(reason: CipherContinuationBusy) -> Self {
        Self::CipherContinuation(reason)
    }
}

impl From<CombinedOperationsBusy> for BusyReason {
    fn from(reason: CombinedOperationsBusy) -> Self {
        Self::CombinedOperations(reason)
    }
}

impl From<DerivedObjectCreationBusy> for BusyReason {
    fn from(reason: DerivedObjectCreationBusy) -> Self {
        Self::DerivedObjectCreation(reason)
    }
}

impl From<DetachmentBusy> for BusyReason {
    fn from(reason: DetachmentBusy) -> Self {
        Self::Detachment(reason)
    }
}

impl From<DigestContinuationBusy> for BusyReason {
    fn from(reason: DigestContinuationBusy) -> Self {
        Self::DigestContinuation(reason)
    }
}

impl From<ExternalExecutionBusy> for BusyReason {
    fn from(reason: ExternalExecutionBusy) -> Self {
        Self::ExternalExecution(reason)
    }
}

impl From<KeyAdmissionBusy> for BusyReason {
    fn from(reason: KeyAdmissionBusy) -> Self {
        Self::KeyAdmission(reason)
    }
}

impl From<LocalAdmissionBusy> for BusyReason {
    fn from(reason: LocalAdmissionBusy) -> Self {
        Self::LocalAdmission(reason)
    }
}

impl From<MemoryAccountingBusy> for BusyReason {
    fn from(reason: MemoryAccountingBusy) -> Self {
        Self::MemoryAccounting(reason)
    }
}

impl From<ModuleLifecycleBusy> for BusyReason {
    fn from(reason: ModuleLifecycleBusy) -> Self {
        Self::ModuleLifecycle(reason)
    }
}

impl From<NativeExecutionBusy> for BusyReason {
    fn from(reason: NativeExecutionBusy) -> Self {
        Self::NativeExecution(reason)
    }
}

impl From<NativeLoadingBusy> for BusyReason {
    fn from(reason: NativeLoadingBusy) -> Self {
        Self::NativeLoading(reason)
    }
}

impl From<NativeMessagesBusy> for BusyReason {
    fn from(reason: NativeMessagesBusy) -> Self {
        Self::NativeMessages(reason)
    }
}

impl From<ObjectCleanupBusy> for BusyReason {
    fn from(reason: ObjectCleanupBusy) -> Self {
        Self::ObjectCleanup(reason)
    }
}

impl From<ObjectCopyBusy> for BusyReason {
    fn from(reason: ObjectCopyBusy) -> Self {
        Self::ObjectCopy(reason)
    }
}

impl From<ObjectCreationBusy> for BusyReason {
    fn from(reason: ObjectCreationBusy) -> Self {
        Self::ObjectCreation(reason)
    }
}

impl From<ObjectMutationBusy> for BusyReason {
    fn from(reason: ObjectMutationBusy) -> Self {
        Self::ObjectMutation(reason)
    }
}

impl From<ObjectObservationBusy> for BusyReason {
    fn from(reason: ObjectObservationBusy) -> Self {
        Self::ObjectObservation(reason)
    }
}

impl From<ObjectPublicationBusy> for BusyReason {
    fn from(reason: ObjectPublicationBusy) -> Self {
        Self::ObjectPublication(reason)
    }
}

impl From<OperationOwnershipBusy> for BusyReason {
    fn from(reason: OperationOwnershipBusy) -> Self {
        Self::OperationOwnership(reason)
    }
}

impl From<OperationRecoveryBusy> for BusyReason {
    fn from(reason: OperationRecoveryBusy) -> Self {
        Self::OperationRecovery(reason)
    }
}

impl From<OperationStateBusy> for BusyReason {
    fn from(reason: OperationStateBusy) -> Self {
        Self::OperationState(reason)
    }
}

impl From<ReferenceRegistryBusy> for BusyReason {
    fn from(reason: ReferenceRegistryBusy) -> Self {
        Self::ReferenceRegistry(reason)
    }
}

impl From<RestorationBusy> for BusyReason {
    fn from(reason: RestorationBusy) -> Self {
        Self::Restoration(reason)
    }
}

impl From<SessionAccountingBusy> for BusyReason {
    fn from(reason: SessionAccountingBusy) -> Self {
        Self::SessionAccounting(reason)
    }
}

impl From<SessionLifecycleBusy> for BusyReason {
    fn from(reason: SessionLifecycleBusy) -> Self {
        Self::SessionLifecycle(reason)
    }
}

impl From<SignatureContinuationBusy> for BusyReason {
    fn from(reason: SignatureContinuationBusy) -> Self {
        Self::SignatureContinuation(reason)
    }
}

impl From<SignatureMessagesBusy> for BusyReason {
    fn from(reason: SignatureMessagesBusy) -> Self {
        Self::SignatureMessages(reason)
    }
}

impl From<TokenAdministrationBusy> for BusyReason {
    fn from(reason: TokenAdministrationBusy) -> Self {
        Self::TokenAdministration(reason)
    }
}
