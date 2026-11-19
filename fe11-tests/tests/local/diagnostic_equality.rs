// SPDX-License-Identifier: Apache-2.0
//! Diagnostic equality is public through Clone, Eq and Rust constant patterns.
use fe11::*;

fn assert_clone_eq<T: Clone + Eq + std::fmt::Debug>(reason: &T) {
    let copy = T::clone(reason);
    assert_eq!(&copy, reason);
}

macro_rules! check_reason {
    ($reason:ident, $first:ident $(, $other:ident)?) => {{
        // Matching a constant exercises structural equality on stable Rust.
        const SAMPLE: $reason = $reason::$first;
        assert_clone_eq(&SAMPLE);
        assert!(matches!($reason::$first, SAMPLE));
        $(
            assert_ne!(SAMPLE, $reason::$other);
            assert!(!matches!($reason::$other, SAMPLE));
        )?
    }};
}

#[test]
fn busy_reasons_preserve_structural_equality() {
    check_reason!(AeadMessagesBusy, AeadControlChanged);
    check_reason!(AsynchronousExecutionBusy, OperationTransferActive, RejoinDestinationActive);
    check_reason!(AuthenticationBusy, OperationControlInProgress);
    check_reason!(CallbacksBusy, NotificationRegistryCapacity);
    check_reason!(CancellationBusy, CancellationPending, StateRestorationActive);
    check_reason!(CheckpointCaptureBusy, StateCaptureActive);
    check_reason!(CipherContinuationBusy, AeadPlaintextAwaitsSuccessfulFinal, CipherControlInProgress);
    check_reason!(CombinedOperationsBusy, RecoveryDestinationActive);
    check_reason!(DerivedObjectCreationBusy, KeaCreationPlanChanged, KeyTransportCreationPlanChanged);
    check_reason!(DetachmentBusy, RestorationRequiresItsTransferTicket);
    check_reason!(DigestContinuationBusy, DigestControlInProgress);
    check_reason!(ExternalExecutionBusy, ForeignJoinSourceClaimed, UnregisteredForeignNativeResourceRetained);
    check_reason!(KeyAdmissionBusy, InitialCreationPlanChanged);
    check_reason!(LocalAdmissionBusy, ModuleActivity, ModuleDraining);
    check_reason!(MemoryAccountingBusy, SymmetricByteBudget);
    check_reason!(ModuleLifecycleBusy, AdvancedTokenActivity, UsableSessionPreventsRecoveryFinalization);
    check_reason!(NativeExecutionBusy, NotificationCallback, SlotEventSourceInUse);
    check_reason!(NativeLoadingBusy, DifferentNativeGenerationOrInitializerActive, NativeInitializationAttemptActive);
    check_reason!(NativeMessagesBusy, GenericMessageControlChanged, MessageDestinationRevocationCapacityChanged);
    check_reason!(ObjectCleanupBusy, CreatorMutation, ObjectCatalogue);
    check_reason!(ObjectCopyBusy, CopyCreationPlanChanged);
    check_reason!(ObjectCreationBusy, GenerationCreationPlanChanged, UnknownCreatorSessionClosing);
    check_reason!(ObjectMutationBusy, ContentCreationPlanChanged, TokenMutation);
    check_reason!(ObjectObservationBusy, RsaObjectCreationPlanChanged);
    check_reason!(ObjectPublicationBusy, MutationCleanupAwaitsNativeCompletion);
    check_reason!(OperationOwnershipBusy, AdvancedFinalizationActivity, OperationStateControl);
    check_reason!(OperationRecoveryBusy, RecoveryControlInProgress);
    check_reason!(OperationStateBusy, StateCaptureTransfer);
    check_reason!(ReferenceRegistryBusy, ObjectMutation, ReferenceQuotaExceeded);
    check_reason!(RestorationBusy, DestinationOperationControlActive, RestorationTransferActive);
    check_reason!(SessionAccountingBusy, SessionCapacity, UnpublishedNativeSession);
    check_reason!(SessionLifecycleBusy, ObjectSearchActive, SessionTransition);
    check_reason!(SignatureContinuationBusy, SignatureInitDispatchCredit, SignatureRevocationCapacityChanged);
    check_reason!(SignatureMessagesBusy, MessageSignatureControlChanged);
    check_reason!(TokenAdministrationBusy, TokenRegistryChanged);
}

#[test]
fn rejection_reasons_preserve_structural_equality() {
    check_reason!(AeadMessagesRejection, AeadInitDescriptorMutation, ValidationReportLength);
    check_reason!(AsynchronousExecutionRejection, CAsyncGetIDUnavailable, StateControlNotPending);
    check_reason!(AttributePreparationRejection, AttributeAbsentFromAdmissionSnapshot, TemplateFieldAllocation);
    check_reason!(AttributeValuesRejection, CGetAttributeValueUnavailable, ValidatedTemplateResultCouldNotBeRepresented);
    check_reason!(AuthenticationRejection, PinFrameAccounting, MissingContextualAuthentication);
    check_reason!(CallbacksRejection, NotificationPreparationConsumed, NotificationSessionBinding);
    check_reason!(CancellationRejection, CSessionCancelUnavailable, CancellationReturnUnproven);
    check_reason!(CheckpointCaptureRejection, AeadStreamCaptureAccounting, SnapshotStorageAccounting);
    check_reason!(CheckpointFormatRejection, CallerFedAeadAsynchronousModeUnavailable, SignatureParametersOnAnotherFamily);
    check_reason!(CipherContinuationRejection, AeadParameterAccountingOverflow, UnexpectedCipherGraphPacket);
    check_reason!(ClassicalSignaturesRejection, CDigestUnavailable, VerificationSelectorPublicIdentity);
    check_reason!(CombinedOperationsRejection, DualAesKeyRequired, TerminalDualAuthenticationWidth);
    check_reason!(DerivedObjectCreationRejection, KeaDiagnosticAccounting, UnchangingKeaPreparationWasInvalidated);
    check_reason!(DetachmentRejection, AsynchronousDetachmentSessionMode, NonterminalValidationAdapterNotIntegrated);
    check_reason!(DiagnosticsRejection, CleanupCauseNotUsed, SequenceCauseNotUsed);
    check_reason!(DigestContinuationRejection, AdvancedInputAllocation, UncopiedDigestSnapshot);
    check_reason!(ExternalExecutionRejection, ForeignJoinOwnerMismatch, ForeignWorkStepNotAdmitted);
    check_reason!(InputBoundsRejection, LengthBound, LengthConversion);
    check_reason!(KeyAdmissionRejection, AesKekAdmissionResultOwnerMismatch, VerificationSelectionResultOwnerMismatch);
    check_reason!(KeyDerivationRejection, EcdhKdfIdentifierWidth, TransportAgreementGenerationResultOwnerMismatch);
    check_reason!(KeyEncapsulationRejection, CDecapsulateKeyUnavailable, ExistingMlKemPairHasNoGenerationRequest);
    check_reason!(KeyEncodingRejection, EcCurveEncoding, UnsignedIntegerBitLength);
    check_reason!(KeyTransportRejection, AesKekAlgorithm, WrappingStorageSize);
    check_reason!(LocalAdmissionRejection, AdmissionContextOwnerMismatch, AdmissionWaiterAllocation);
    check_reason!(MechanismExtensionsRejection, NullExtensionParameterCannotOwnUnreachableBlocks, WrapStorageAccounting);
    check_reason!(MechanismsRejection, ConflictingMechanismProperties, RetainedMechanismRequestSize);
    check_reason!(MemoryAccountingRejection, CreditTransferExceedsOwnership, SymmetricOutputLength);
    check_reason!(MemoryAllocationRejection, StableOwnerAllocation);
    check_reason!(MessageRecordRejection, AeadInitSeed, TerminalMessageStreamReportAbsent);
    check_reason!(ModuleConfigurationRejection, InitializationArgumentsDuringAttachment, ProcessImageFilenameUnavailable);
    check_reason!(ModuleLifecycleRejection, CCloseAllSessionsUnavailable, UnavailableDiscoveryCount);
    check_reason!(NativeDerivationRejection, CDeriveKeyUnavailable, TwoPairAgreementStorageAccounting);
    check_reason!(NativeDigestRejection, DigestBitCountAbiWidth, NativeDigestOutputLength);
    check_reason!(NativeEncapsulationRejection, KemKdfAbiWidth);
    check_reason!(NativeExecutionRejection, CGenerateKeyUnavailable, UnqualifiedInterfaceVersion);
    check_reason!(NativeInterfacesRejection, CounterExhausted, UnsupportedInterfaceSelection);
    check_reason!(NativeLoadingRejection, WindowsDependencySearchUnavailable, TableSelectionExportBelongsToAnotherImage);
    check_reason!(NativeMacRejection, MacOutputLengthRepresentation, SinglePartMacRequiresOneInput);
    check_reason!(NativeMessagesRejection, CapturedGenericMessageRequiresDestinationBinding, StaleGenericMessageTicket);
    check_reason!(NativeOtpRejection, OtpOutputIsNotABoundedContiguousNativeGraph, CallerOtpValueByteBound);
    check_reason!(NativeProtocolsRejection, CmsKeyFieldAccounting, SingleCmsCallRequiresOneInput);
    check_reason!(NativeSignatureRejection, SignatureParameterScalarAbiWidth, SinglePartVerificationRequiresOneInput);
    check_reason!(NativeTransportRejection, SkipjackSharedPGExtent, TransportScalarAbiWidth);
    check_reason!(ObjectCleanupRejection, AbandonedReaderSnapshotAllocation, UnknownCreatorCloseCount);
    check_reason!(ObjectContentRejection, ContentContinuationPhase, FingerprintStateAllocation);
    check_reason!(ObjectCopyRejection, CCopyObjectUnavailable, CopyTemplateRecipeKind);
    check_reason!(ObjectCreationRejection, KemCallAbsent, UnwrapDispatchPhase);
    check_reason!(ObjectDestinationRejection, DestinationCardinalityWidth, UnrequestedDestinationCount);
    check_reason!(ObjectMutationRejection, CSetAttributeValueUnavailable, UnselectedMutationContent);
    check_reason!(ObjectObservationRejection, CDestroyObjectUnavailable, PublicAttributeSelectionSizeOverflow);
    check_reason!(ObjectPublicationRejection, Sp800OutputSlot, UnobservedNativeIdentityAbsent);
    check_reason!(ObjectReferencesRejection, CGetObjectSizeUnavailable, UnselectedReferenceContent);
    check_reason!(ObjectSearchRejection, DiscoveryContentPublicationIncomplete, UnselectedManagedContent);
    check_reason!(OperationKeysRejection, PssRequiresAnRsaReference, UnsubmittedNativeWriterCannotBeDuplicated);
    check_reason!(OperationOwnershipRejection, AeadMessageTicketRequired, ValidationSnapshotShapeChanged);
    check_reason!(OperationRecordRejection, AesRequiresPhaseSpecificTerminalValidation, TruncatedRecord);
    check_reason!(OperationRecoveryRejection, CSignRecoverUnavailable, UnexpectedRecoveryCipherKey);
    check_reason!(OperationStateRejection, CGetOperationStateUnavailable, StateSizeDirection);
    check_reason!(PersistenceRejection, AsynchronousRejoinSessionMode, UnsupportedAuthenticatedRecordKind);
    check_reason!(PostQuantumKeysRejection, CVerifySignatureUnavailable, SinglePartPqcVerificationRequiresOneInput);
    check_reason!(PublicVerificationRejection, CCreateObjectUnavailable, VerificationPublicationSize);
    check_reason!(RandomGenerationRejection, CGenerateRandomUnavailable, SlotEventGenerationAllocation);
    check_reason!(RecoveryRecordRejection, DetachedCapacityWidth, TerminalValidityCode);
    check_reason!(ReferenceRegistryRejection, ActivityContextNotifierAbsent, WriterTransferState);
    check_reason!(RestorationRejection, CSetOperationStateUnavailable, TransferStorageAccounting);
    check_reason!(SessionAccountingRejection, AmbiguousSessionOwner, StaleRecoveryCompletion);
    check_reason!(SessionLifecycleRejection, CAsyncCompleteUnavailable, ValidationFlagsTypeConversion);
    check_reason!(SignatureContinuationRejection, SignatureNotActive, VerificationSignatureNotSupplied);
    check_reason!(SignatureMessagesRejection, MacTagSize, UnexpectedRestorationEncryptionKey);
    check_reason!(SymmetricParametersRejection, Value32BitStreamCounterLength, TraditionalCcmHasNoNonceGenerationFields);
    check_reason!(TokenAdministrationRejection, CGetTokenInfoUnavailable, TokenRegistryChangedAfterDiscovery);
    check_reason!(VerificationEngineRejection, AbsoluteVerificationEnginePathRequired, VerificationEngineVerificationUnavailable);
}

#[test]
fn unsupported_reasons_preserve_structural_equality() {
    check_reason!(AeadMessagesUnsupported, DeclaredGcmMessageStateCapture);
    check_reason!(CipherContinuationUnsupported, CcmParameterLayoutUnavailableInSelectedEdition);
    check_reason!(MechanismExtensionsUnsupported, ExtensionNativeFunctionTuple);
    check_reason!(MechanismsUnsupported, CGetMechanismInfoUnavailable, MechanismListNotObserved);
    check_reason!(ModuleConfigurationUnsupported, ProcessImageFileIdentityObservation);
    check_reason!(ModuleLifecycleUnsupported, AutonomousArchiveRequiresAnObservedModuleFile, FileLoadingOptionsForProcessSource);
    check_reason!(NativeInterfacesUnsupported, FunctionTableVersion);
    check_reason!(NativeLoadingUnsupported, CurrentProcessLoaderPlatform, NativeImageIdentityPlatform);
    check_reason!(NativeMacUnsupported, MacHasNoGeneralLengthVariant);
    check_reason!(NativeMessagesUnsupported, MessageInterface, MessageSignatureFunctionTuple);
    check_reason!(ObjectCreationUnsupported, CreationClassRequiresAnExtensionContract);
    check_reason!(PostQuantumKeysUnsupported, CCreateObjectUnavailable, VerifysignatureRequiresThePkcs1132Interface);
    check_reason!(SignatureContinuationUnsupported, SignatureFunctionTuple);
}
