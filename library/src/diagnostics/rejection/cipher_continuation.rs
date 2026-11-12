// SPDX-License-Identifier: Apache-2.0
//! CipherContinuation causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to cipher continuation.
#[doc = include_str!("../../../docs/diagnostics/rejection-cipher_continuation.md")]
pub enum CipherContinuationRejection {
    /// AEAD parameter accounting overflow. [Detection, owner and recovery](#cause-AeadParameterAccountingOverflow).
    AeadParameterAccountingOverflow,
    /// AEAD record AAD absent. [Detection, owner and recovery](#cause-AeadRecordAadAbsent).
    AeadRecordAadAbsent,
    /// AEAD record counter field. [Detection, owner and recovery](#cause-AeadRecordCounterField).
    AeadRecordCounterField,
    /// AEAD record parameter combination. [Detection, owner and recovery](#cause-AeadRecordParameterCombination).
    AeadRecordParameterCombination,
    /// AEAD requires a secret key. [Detection, owner and recovery](#cause-AeadRequiresASecretKey).
    AeadRequiresASecretKey,
    /// AEAD restored nonce mismatch. [Detection, owner and recovery](#cause-AeadRestoredNonceMismatch).
    AeadRestoredNonceMismatch,
    /// AEAD retained nonce width. [Detection, owner and recovery](#cause-AeadRetainedNonceWidth).
    AeadRetainedNonceWidth,
    /// AEAD retained prefix length overflow. [Detection, owner and recovery](#cause-AeadRetainedPrefixLengthOverflow).
    AeadRetainedPrefixLengthOverflow,
    /// AEAD snapshot parameter shape changed. [Detection, owner and recovery](#cause-AeadSnapshotParameterShapeChanged).
    AeadSnapshotParameterShapeChanged,
    /// AES operation requires an AES key. [Detection, owner and recovery](#cause-AesOperationRequiresAnAesKey).
    AesOperationRequiresAnAesKey,
    /// CCM data length width. [Detection, owner and recovery](#cause-CcmDataLengthWidth).
    CcmDataLengthWidth,
    /// CCM stream framing requires its exact data length. [Detection, owner and recovery](#cause-CcmStreamFramingRequiresItsExactDataLength).
    CcmStreamFramingRequiresItsExactDataLength,
    /// CKM_NULL changed the current input. [Detection, owner and recovery](#cause-CkmNullChangedTheCurrentInput).
    CkmNullChangedTheCurrentInput,
    /// IETF nonce width. [Detection, owner and recovery](#cause-IetfNonceWidth).
    IetfNonceWidth,
    /// Archived cipher parameters cannot authorize Init. [Detection, owner and recovery](#cause-ArchivedCipherParametersCannotAuthorizeInit).
    ArchivedCipherParametersCannotAuthorizeInit,
    /// Cipher captured required capacity overflow. [Detection, owner and recovery](#cause-CipherCapturedRequiredCapacityOverflow).
    CipherCapturedRequiredCapacityOverflow,
    /// Cipher checkpoint key profile. [Detection, owner and recovery](#cause-CipherCheckpointKeyProfile).
    CipherCheckpointKeyProfile,
    /// Cipher checkpoint retains consumed input. [Detection, owner and recovery](#cause-CipherCheckpointRetainsConsumedInput).
    CipherCheckpointRetainsConsumedInput,
    /// Cipher complete-input counter width. [Detection, owner and recovery](#cause-CipherCompleteInputCounterWidth).
    CipherCompleteInputCounterWidth,
    /// Cipher complete-input size overflow. [Detection, owner and recovery](#cause-CipherCompleteInputSizeOverflow).
    CipherCompleteInputSizeOverflow,
    /// Cipher continuation unavailable. [Detection, owner and recovery](#cause-CipherContinuationUnavailable).
    CipherContinuationUnavailable,
    /// Cipher destination ABI declaration absent. [Detection, owner and recovery](#cause-CipherDestinationAbiDeclarationAbsent).
    CipherDestinationAbiDeclarationAbsent,
    /// Cipher destination ABI declaration mismatch. [Detection, owner and recovery](#cause-CipherDestinationAbiDeclarationMismatch).
    CipherDestinationAbiDeclarationMismatch,
    /// Cipher destination declaration mismatch. [Detection, owner and recovery](#cause-CipherDestinationDeclarationMismatch).
    CipherDestinationDeclarationMismatch,
    /// Cipher destination key presence/profile. [Detection, owner and recovery](#cause-CipherDestinationKeyPresenceProfile).
    CipherDestinationKeyPresenceProfile,
    /// Cipher destination output capacity. [Detection, owner and recovery](#cause-CipherDestinationOutputCapacity).
    CipherDestinationOutputCapacity,
    /// Cipher extension destination absent. [Detection, owner and recovery](#cause-CipherExtensionDestinationAbsent).
    CipherExtensionDestinationAbsent,
    /// Cipher extension graph already published. [Detection, owner and recovery](#cause-CipherExtensionGraphAlreadyPublished).
    CipherExtensionGraphAlreadyPublished,
    /// Cipher extension mechanism width. [Detection, owner and recovery](#cause-CipherExtensionMechanismWidth).
    CipherExtensionMechanismWidth,
    /// Cipher extension parameter identity. [Detection, owner and recovery](#cause-CipherExtensionParameterIdentity).
    CipherExtensionParameterIdentity,
    /// Cipher extension preparation changed. [Detection, owner and recovery](#cause-CipherExtensionPreparationChanged).
    CipherExtensionPreparationChanged,
    /// Cipher facade observer changed. [Detection, owner and recovery](#cause-CipherFacadeObserverChanged).
    CipherFacadeObserverChanged,
    /// Cipher facade owner changed. [Detection, owner and recovery](#cause-CipherFacadeOwnerChanged).
    CipherFacadeOwnerChanged,
    /// Cipher frame accounting overflow. [Detection, owner and recovery](#cause-CipherFrameAccountingOverflow).
    CipherFrameAccountingOverflow,
    /// Cipher graph absent. [Detection, owner and recovery](#cause-CipherGraphAbsent).
    CipherGraphAbsent,
    /// Cipher graph already published. [Detection, owner and recovery](#cause-CipherGraphAlreadyPublished).
    CipherGraphAlreadyPublished,
    /// Cipher graph metadata accounting. [Detection, owner and recovery](#cause-CipherGraphMetadataAccounting).
    CipherGraphMetadataAccounting,
    /// Cipher graph packet absent. [Detection, owner and recovery](#cause-CipherGraphPacketAbsent).
    CipherGraphPacketAbsent,
    /// Cipher graph packet uninitialized. [Detection, owner and recovery](#cause-CipherGraphPacketUninitialized).
    CipherGraphPacketUninitialized,
    /// Cipher graph record family. [Detection, owner and recovery](#cause-CipherGraphRecordFamily).
    CipherGraphRecordFamily,
    /// Cipher graph record route. [Detection, owner and recovery](#cause-CipherGraphRecordRoute).
    CipherGraphRecordRoute,
    /// Cipher graph snapshot size. [Detection, owner and recovery](#cause-CipherGraphSnapshotSize).
    CipherGraphSnapshotSize,
    /// Cipher has no authentication key role. [Detection, owner and recovery](#cause-CipherHasNoAuthenticationKeyRole).
    CipherHasNoAuthenticationKeyRole,
    /// Cipher import requires a destination ABI declaration. [Detection, owner and recovery](#cause-CipherImportRequiresADestinationAbiDeclaration).
    CipherImportRequiresADestinationAbiDeclaration,
    /// Cipher input changed before dispatch. [Detection, owner and recovery](#cause-CipherInputChangedBeforeDispatch).
    CipherInputChangedBeforeDispatch,
    /// Cipher input layout allocation. [Detection, owner and recovery](#cause-CipherInputLayoutAllocation).
    CipherInputLayoutAllocation,
    /// Cipher input length overflow. [Detection, owner and recovery](#cause-CipherInputLengthOverflow).
    CipherInputLengthOverflow,
    /// Cipher input metadata accounting. [Detection, owner and recovery](#cause-CipherInputMetadataAccounting).
    CipherInputMetadataAccounting,
    /// Cipher input metadata allocation. [Detection, owner and recovery](#cause-CipherInputMetadataAllocation).
    CipherInputMetadataAllocation,
    /// Cipher input storage accounting. [Detection, owner and recovery](#cause-CipherInputStorageAccounting).
    CipherInputStorageAccounting,
    /// Cipher is not ready for another input. [Detection, owner and recovery](#cause-CipherIsNotReadyForAnotherInput).
    CipherIsNotReadyForAnotherInput,
    /// Cipher is not waiting for storage. [Detection, owner and recovery](#cause-CipherIsNotWaitingForStorage).
    CipherIsNotWaitingForStorage,
    /// Cipher mechanism width. [Detection, owner and recovery](#cause-CipherMechanismWidth).
    CipherMechanismWidth,
    /// Cipher native input identity. [Detection, owner and recovery](#cause-CipherNativeInputIdentity).
    CipherNativeInputIdentity,
    /// Cipher native output length. [Detection, owner and recovery](#cause-CipherNativeOutputLength).
    CipherNativeOutputLength,
    /// Cipher observation ownership changed. [Detection, owner and recovery](#cause-CipherObservationOwnershipChanged).
    CipherObservationOwnershipChanged,
    /// Cipher operation storage size. [Detection, owner and recovery](#cause-CipherOperationStorageSize).
    CipherOperationStorageSize,
    /// Cipher outcome uncertain. [Detection, owner and recovery](#cause-CipherOutcomeUncertain).
    CipherOutcomeUncertain,
    /// Cipher output absent. [Detection, owner and recovery](#cause-CipherOutputAbsent).
    CipherOutputAbsent,
    /// Cipher output already transferred. [Detection, owner and recovery](#cause-CipherOutputAlreadyTransferred).
    CipherOutputAlreadyTransferred,
    /// Cipher output capacity overflow. [Detection, owner and recovery](#cause-CipherOutputCapacityOverflow).
    CipherOutputCapacityOverflow,
    /// Cipher output offset. [Detection, owner and recovery](#cause-CipherOutputOffset).
    CipherOutputOffset,
    /// Cipher output step unavailable. [Detection, owner and recovery](#cause-CipherOutputStepUnavailable).
    CipherOutputStepUnavailable,
    /// Cipher output still referenced by pending call. [Detection, owner and recovery](#cause-CipherOutputStillReferencedByPendingCall).
    CipherOutputStillReferencedByPendingCall,
    /// Cipher parameter framing changed on restoration. [Detection, owner and recovery](#cause-CipherParameterFramingChangedOnRestoration).
    CipherParameterFramingChangedOnRestoration,
    /// Cipher queued input cursor. [Detection, owner and recovery](#cause-CipherQueuedInputCursor).
    CipherQueuedInputCursor,
    /// Cipher reconstructed declaration absent or unexpected. [Detection, owner and recovery](#cause-CipherReconstructedDeclarationAbsentOrUnexpected).
    CipherReconstructedDeclarationAbsentOrUnexpected,
    /// Cipher record IV absent. [Detection, owner and recovery](#cause-CipherRecordIvAbsent).
    CipherRecordIvAbsent,
    /// Cipher record descriptor. [Detection, owner and recovery](#cause-CipherRecordDescriptor).
    CipherRecordDescriptor,
    /// Cipher record family. [Detection, owner and recovery](#cause-CipherRecordFamily).
    CipherRecordFamily,
    /// Cipher record input overflow. [Detection, owner and recovery](#cause-CipherRecordInputOverflow).
    CipherRecordInputOverflow,
    /// Cipher record key profile. [Detection, owner and recovery](#cause-CipherRecordKeyProfile).
    CipherRecordKeyProfile,
    /// Cipher record message absent. [Detection, owner and recovery](#cause-CipherRecordMessageAbsent).
    CipherRecordMessageAbsent,
    /// Cipher record next function or fragment. [Detection, owner and recovery](#cause-CipherRecordNextFunctionOrFragment).
    CipherRecordNextFunctionOrFragment,
    /// Cipher record offset overflow. [Detection, owner and recovery](#cause-CipherRecordOffsetOverflow).
    CipherRecordOffsetOverflow,
    /// Cipher record output bounds. [Detection, owner and recovery](#cause-CipherRecordOutputBounds).
    CipherRecordOutputBounds,
    /// Cipher record output profile. [Detection, owner and recovery](#cause-CipherRecordOutputProfile).
    CipherRecordOutputProfile,
    /// Cipher record parameters. [Detection, owner and recovery](#cause-CipherRecordParameters).
    CipherRecordParameters,
    /// Cipher record progression. [Detection, owner and recovery](#cause-CipherRecordProgression).
    CipherRecordProgression,
    /// Cipher record validation correlation. [Detection, owner and recovery](#cause-CipherRecordValidationCorrelation).
    CipherRecordValidationCorrelation,
    /// Cipher required length width. [Detection, owner and recovery](#cause-CipherRequiredLengthWidth).
    CipherRequiredLengthWidth,
    /// Cipher restoration key presence mismatch. [Detection, owner and recovery](#cause-CipherRestorationKeyPresenceMismatch).
    CipherRestorationKeyPresenceMismatch,
    /// Cipher restored capacity offset. [Detection, owner and recovery](#cause-CipherRestoredCapacityOffset).
    CipherRestoredCapacityOffset,
    /// Cipher restored fragment. [Detection, owner and recovery](#cause-CipherRestoredFragment).
    CipherRestoredFragment,
    /// Cipher restored function. [Detection, owner and recovery](#cause-CipherRestoredFunction).
    CipherRestoredFunction,
    /// Cipher restored offset overflow. [Detection, owner and recovery](#cause-CipherRestoredOffsetOverflow).
    CipherRestoredOffsetOverflow,
    /// Cipher restored required capacity. [Detection, owner and recovery](#cause-CipherRestoredRequiredCapacity).
    CipherRestoredRequiredCapacity,
    /// Cipher result already published. [Detection, owner and recovery](#cause-CipherResultAlreadyPublished).
    CipherResultAlreadyPublished,
    /// Cipher result incomplete. [Detection, owner and recovery](#cause-CipherResultIncomplete).
    CipherResultIncomplete,
    /// Cipher result length outside mechanism contract. [Detection, owner and recovery](#cause-CipherResultLengthOutsideMechanismContract).
    CipherResultLengthOutsideMechanismContract,
    /// Cipher retained output counters. [Detection, owner and recovery](#cause-CipherRetainedOutputCounters).
    CipherRetainedOutputCounters,
    /// Cipher retained output range. [Detection, owner and recovery](#cause-CipherRetainedOutputRange).
    CipherRetainedOutputRange,
    /// Cipher returned operands awaiting release. [Detection, owner and recovery](#cause-CipherReturnedOperandsAwaitingRelease).
    CipherReturnedOperandsAwaitingRelease,
    /// Cipher revocation storage size. [Detection, owner and recovery](#cause-CipherRevocationStorageSize).
    CipherRevocationStorageSize,
    /// Cipher size result code. [Detection, owner and recovery](#cause-CipherSizeResultCode).
    CipherSizeResultCode,
    /// Cipher snapshot accounting. [Detection, owner and recovery](#cause-CipherSnapshotAccounting).
    CipherSnapshotAccounting,
    /// Cipher snapshot parameter family changed. [Detection, owner and recovery](#cause-CipherSnapshotParameterFamilyChanged).
    CipherSnapshotParameterFamilyChanged,
    /// Cipher stream checkpoint progression. [Detection, owner and recovery](#cause-CipherStreamCheckpointProgression).
    CipherStreamCheckpointProgression,
    /// Cipher terminal completion unproven. [Detection, owner and recovery](#cause-CipherTerminalCompletionUnproven).
    CipherTerminalCompletionUnproven,
    /// Cipher terminal observation absent. [Detection, owner and recovery](#cause-CipherTerminalObservationAbsent).
    CipherTerminalObservationAbsent,
    /// Cipher terminal owner requires terminal capture. [Detection, owner and recovery](#cause-CipherTerminalOwnerRequiresTerminalCapture).
    CipherTerminalOwnerRequiresTerminalCapture,
    /// Cipher terminal progression. [Detection, owner and recovery](#cause-CipherTerminalProgression).
    CipherTerminalProgression,
    /// Cipher ticket already held by caller. [Detection, owner and recovery](#cause-CipherTicketAlreadyHeldByCaller).
    CipherTicketAlreadyHeldByCaller,
    /// Cipher writer key absent. [Detection, owner and recovery](#cause-CipherWriterKeyAbsent).
    CipherWriterKeyAbsent,
    /// Cipher writer permission absent. [Detection, owner and recovery](#cause-CipherWriterPermissionAbsent).
    CipherWriterPermissionAbsent,
    /// Classic AEAD parameter mutation. [Detection, owner and recovery](#cause-ClassicAeadParameterMutation).
    ClassicAeadParameterMutation,
    /// Classic AEAD result direction mismatch. [Detection, owner and recovery](#cause-ClassicAeadResultDirectionMismatch).
    ClassicAeadResultDirectionMismatch,
    /// Consumed cipher ticket. [Detection, owner and recovery](#cause-ConsumedCipherTicket).
    ConsumedCipherTicket,
    /// Declaration without cipher extension. [Detection, owner and recovery](#cause-DeclarationWithoutCipherExtension).
    DeclarationWithoutCipherExtension,
    /// Digest OID on non-digest owner. [Detection, owner and recovery](#cause-DigestOidOnNonDigestOwner).
    DigestOidOnNonDigestOwner,
    /// Extension cipher facade incomplete. [Detection, owner and recovery](#cause-ExtensionCipherFacadeIncomplete).
    ExtensionCipherFacadeIncomplete,
    /// Extension cipher facade route. [Detection, owner and recovery](#cause-ExtensionCipherFacadeRoute).
    ExtensionCipherFacadeRoute,
    /// Extension cipher requires an explicit buffer or length query. [Detection, owner and recovery](#cause-ExtensionCipherRequiresAnExplicitBufferOrLengthQuery).
    ExtensionCipherRequiresAnExplicitBufferOrLengthQuery,
    /// Extension cipher requires graph snapshot preparation. [Detection, owner and recovery](#cause-ExtensionCipherRequiresGraphSnapshotPreparation).
    ExtensionCipherRequiresGraphSnapshotPreparation,
    /// Extension cipher route declaration. [Detection, owner and recovery](#cause-ExtensionCipherRouteDeclaration).
    ExtensionCipherRouteDeclaration,
    /// Extension graph has no separate nonce field. [Detection, owner and recovery](#cause-ExtensionGraphHasNoSeparateNonceField).
    ExtensionGraphHasNoSeparateNonceField,
    /// Incremental cipher starts without queued input. [Detection, owner and recovery](#cause-IncrementalCipherStartsWithoutQueuedInput).
    IncrementalCipherStartsWithoutQueuedInput,
    /// Input prefix range. [Detection, owner and recovery](#cause-InputPrefixRange).
    InputPrefixRange,
    /// Legacy AEAD nonce width. [Detection, owner and recovery](#cause-LegacyAeadNonceWidth).
    LegacyAeadNonceWidth,
    /// Multipart cipher declaration required. [Detection, owner and recovery](#cause-MultipartCipherDeclarationRequired).
    MultipartCipherDeclarationRequired,
    /// Native cipher native asynchronous mode is unsupported. [Detection, owner and recovery](#cause-NativeCipherAsynchronousModeUnavailable).
    NativeCipherAsynchronousModeUnavailable,
    /// Native writer key absent. [Detection, owner and recovery](#cause-NativeWriterKeyAbsent).
    NativeWriterKeyAbsent,
    /// Non-AEAD record authentication fields. [Detection, owner and recovery](#cause-NonAeadRecordAuthenticationFields).
    NonAeadRecordAuthenticationFields,
    /// Only CCM requires an explicit stream plaintext length. [Detection, owner and recovery](#cause-OnlyCcmRequiresAnExplicitStreamPlaintextLength).
    OnlyCcmRequiresAnExplicitStreamPlaintextLength,
    /// Record route requires archived cipher graph. [Detection, owner and recovery](#cause-RecordRouteRequiresArchivedCipherGraph).
    RecordRouteRequiresArchivedCipherGraph,
    /// Record tag width. [Detection, owner and recovery](#cause-RecordTagWidth).
    RecordTagWidth,
    /// Revocation without native writer. [Detection, owner and recovery](#cause-RevocationWithoutNativeWriter).
    RevocationWithoutNativeWriter,
    /// Selected block cipher function unavailable. [Detection, owner and recovery](#cause-SelectedBlockCipherFunctionUnavailable).
    SelectedBlockCipherFunctionUnavailable,
    /// Selected cipher functions unavailable. [Detection, owner and recovery](#cause-SelectedCipherFunctionsUnavailable).
    SelectedCipherFunctionsUnavailable,
    /// Single-part cipher declaration required. [Detection, owner and recovery](#cause-SinglePartCipherDeclarationRequired).
    SinglePartCipherDeclarationRequired,
    /// Stale cipher facade ticket. [Detection, owner and recovery](#cause-StaleCipherFacadeTicket).
    StaleCipherFacadeTicket,
    /// Standalone native cipher parameters required. [Detection, owner and recovery](#cause-StandaloneNativeCipherParametersRequired).
    StandaloneNativeCipherParametersRequired,
    /// Synchronous AES decryption did not complete. [Detection, owner and recovery](#cause-SynchronousAesDecryptionDidNotComplete).
    SynchronousAesDecryptionDidNotComplete,
    /// Synchronous AES encryption did not complete. [Detection, owner and recovery](#cause-SynchronousAesEncryptionDidNotComplete).
    SynchronousAesEncryptionDidNotComplete,
    /// Synchronous cipher did not complete. [Detection, owner and recovery](#cause-SynchronousCipherDidNotComplete).
    SynchronousCipherDidNotComplete,
    /// Synchronous classic AEAD did not complete. [Detection, owner and recovery](#cause-SynchronousClassicAeadDidNotComplete).
    SynchronousClassicAeadDidNotComplete,
    /// Unexpected cipher graph packet. [Detection, owner and recovery](#cause-UnexpectedCipherGraphPacket).
    UnexpectedCipherGraphPacket,


}

impl std::fmt::Display for CipherContinuationRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {


            Self::AeadParameterAccountingOverflow => {
                f.write_str("AEAD parameter accounting overflow")
            }
            Self::AeadRecordAadAbsent => f.write_str("AEAD record AAD absent"),
            Self::AeadRecordCounterField => f.write_str("AEAD record counter field"),
            Self::AeadRecordParameterCombination => {
                f.write_str("AEAD record parameter combination")
            }
            Self::AeadRequiresASecretKey => f.write_str("AEAD requires a secret key"),
            Self::AeadRestoredNonceMismatch => f.write_str("AEAD restored nonce mismatch"),
            Self::AeadRetainedNonceWidth => f.write_str("AEAD retained nonce width"),
            Self::AeadRetainedPrefixLengthOverflow => {
                f.write_str("AEAD retained prefix length overflow")
            }
            Self::AeadSnapshotParameterShapeChanged => {
                f.write_str("AEAD snapshot parameter shape changed")
            }
            Self::AesOperationRequiresAnAesKey => f.write_str("AES operation requires an AES key"),
            Self::CcmDataLengthWidth => f.write_str("CCM data length width"),
            Self::CcmStreamFramingRequiresItsExactDataLength => {
                f.write_str("CCM stream framing requires its exact data length")
            }
            Self::CkmNullChangedTheCurrentInput => {
                f.write_str("CKM_NULL changed the current input")
            }
            Self::IetfNonceWidth => f.write_str("IETF nonce width"),
            Self::ArchivedCipherParametersCannotAuthorizeInit => {
                f.write_str("archived cipher parameters cannot authorize Init")
            }
            Self::CipherCapturedRequiredCapacityOverflow => {
                f.write_str("cipher captured required capacity overflow")
            }
            Self::CipherCheckpointKeyProfile => f.write_str("cipher checkpoint key profile"),
            Self::CipherCheckpointRetainsConsumedInput => {
                f.write_str("cipher checkpoint retains consumed input")
            }
            Self::CipherCompleteInputCounterWidth => {
                f.write_str("cipher complete-input counter width")
            }
            Self::CipherCompleteInputSizeOverflow => {
                f.write_str("cipher complete-input size overflow")
            }
            Self::CipherContinuationUnavailable => f.write_str("cipher continuation unavailable"),
            Self::CipherDestinationAbiDeclarationAbsent => {
                f.write_str("cipher destination ABI declaration absent")
            }
            Self::CipherDestinationAbiDeclarationMismatch => {
                f.write_str("cipher destination ABI declaration mismatch")
            }
            Self::CipherDestinationDeclarationMismatch => {
                f.write_str("cipher destination declaration mismatch")
            }
            Self::CipherDestinationKeyPresenceProfile => {
                f.write_str("cipher destination key presence/profile")
            }
            Self::CipherDestinationOutputCapacity => {
                f.write_str("cipher destination output capacity")
            }
            Self::CipherExtensionDestinationAbsent => {
                f.write_str("cipher extension destination absent")
            }
            Self::CipherExtensionGraphAlreadyPublished => {
                f.write_str("cipher extension graph already published")
            }
            Self::CipherExtensionMechanismWidth => f.write_str("cipher extension mechanism width"),
            Self::CipherExtensionParameterIdentity => {
                f.write_str("cipher extension parameter identity")
            }
            Self::CipherExtensionPreparationChanged => {
                f.write_str("cipher extension preparation changed")
            }
            Self::CipherFacadeObserverChanged => f.write_str("cipher facade observer changed"),
            Self::CipherFacadeOwnerChanged => f.write_str("cipher facade owner changed"),
            Self::CipherFrameAccountingOverflow => f.write_str("cipher frame accounting overflow"),
            Self::CipherGraphAbsent => f.write_str("cipher graph absent"),
            Self::CipherGraphAlreadyPublished => f.write_str("cipher graph already published"),
            Self::CipherGraphMetadataAccounting => f.write_str("cipher graph metadata accounting"),
            Self::CipherGraphPacketAbsent => f.write_str("cipher graph packet absent"),
            Self::CipherGraphPacketUninitialized => {
                f.write_str("cipher graph packet uninitialized")
            }
            Self::CipherGraphRecordFamily => f.write_str("cipher graph record family"),
            Self::CipherGraphRecordRoute => f.write_str("cipher graph record route"),
            Self::CipherGraphSnapshotSize => f.write_str("cipher graph snapshot size"),
            Self::CipherHasNoAuthenticationKeyRole => {
                f.write_str("cipher has no authentication key role")
            }
            Self::CipherImportRequiresADestinationAbiDeclaration => {
                f.write_str("cipher import requires a destination ABI declaration")
            }
            Self::CipherInputChangedBeforeDispatch => {
                f.write_str("cipher input changed before dispatch")
            }
            Self::CipherInputLayoutAllocation => f.write_str("cipher input layout allocation"),
            Self::CipherInputLengthOverflow => f.write_str("cipher input length overflow"),
            Self::CipherInputMetadataAccounting => f.write_str("cipher input metadata accounting"),
            Self::CipherInputMetadataAllocation => f.write_str("cipher input metadata allocation"),
            Self::CipherInputStorageAccounting => f.write_str("cipher input storage accounting"),
            Self::CipherIsNotReadyForAnotherInput => {
                f.write_str("cipher is not ready for another input")
            }
            Self::CipherIsNotWaitingForStorage => f.write_str("cipher is not waiting for storage"),
            Self::CipherMechanismWidth => f.write_str("cipher mechanism width"),
            Self::CipherNativeInputIdentity => f.write_str("cipher native input identity"),
            Self::CipherNativeOutputLength => f.write_str("cipher native output length"),
            Self::CipherObservationOwnershipChanged => {
                f.write_str("cipher observation ownership changed")
            }
            Self::CipherOperationStorageSize => f.write_str("cipher operation storage size"),
            Self::CipherOutcomeUncertain => f.write_str("cipher outcome uncertain"),
            Self::CipherOutputAbsent => f.write_str("cipher output absent"),
            Self::CipherOutputAlreadyTransferred => {
                f.write_str("cipher output already transferred")
            }
            Self::CipherOutputCapacityOverflow => f.write_str("cipher output capacity overflow"),
            Self::CipherOutputOffset => f.write_str("cipher output offset"),
            Self::CipherOutputStepUnavailable => f.write_str("cipher output step unavailable"),
            Self::CipherOutputStillReferencedByPendingCall => {
                f.write_str("cipher output still referenced by pending call")
            }
            Self::CipherParameterFramingChangedOnRestoration => {
                f.write_str("cipher parameter framing changed on restoration")
            }
            Self::CipherQueuedInputCursor => f.write_str("cipher queued input cursor"),
            Self::CipherReconstructedDeclarationAbsentOrUnexpected => {
                f.write_str("cipher reconstructed declaration absent or unexpected")
            }
            Self::CipherRecordIvAbsent => f.write_str("cipher record IV absent"),
            Self::CipherRecordDescriptor => f.write_str("cipher record descriptor"),
            Self::CipherRecordFamily => f.write_str("cipher record family"),
            Self::CipherRecordInputOverflow => f.write_str("cipher record input overflow"),
            Self::CipherRecordKeyProfile => f.write_str("cipher record key profile"),
            Self::CipherRecordMessageAbsent => f.write_str("cipher record message absent"),
            Self::CipherRecordNextFunctionOrFragment => {
                f.write_str("cipher record next function or fragment")
            }
            Self::CipherRecordOffsetOverflow => f.write_str("cipher record offset overflow"),
            Self::CipherRecordOutputBounds => f.write_str("cipher record output bounds"),
            Self::CipherRecordOutputProfile => f.write_str("cipher record output profile"),
            Self::CipherRecordParameters => f.write_str("cipher record parameters"),
            Self::CipherRecordProgression => f.write_str("cipher record progression"),
            Self::CipherRecordValidationCorrelation => {
                f.write_str("cipher record validation correlation")
            }
            Self::CipherRequiredLengthWidth => f.write_str("cipher required length width"),
            Self::CipherRestorationKeyPresenceMismatch => {
                f.write_str("cipher restoration key presence mismatch")
            }
            Self::CipherRestoredCapacityOffset => f.write_str("cipher restored capacity offset"),
            Self::CipherRestoredFragment => f.write_str("cipher restored fragment"),
            Self::CipherRestoredFunction => f.write_str("cipher restored function"),
            Self::CipherRestoredOffsetOverflow => f.write_str("cipher restored offset overflow"),
            Self::CipherRestoredRequiredCapacity => {
                f.write_str("cipher restored required capacity")
            }
            Self::CipherResultAlreadyPublished => f.write_str("cipher result already published"),
            Self::CipherResultIncomplete => f.write_str("cipher result incomplete"),
            Self::CipherResultLengthOutsideMechanismContract => {
                f.write_str("cipher result length outside mechanism contract")
            }
            Self::CipherRetainedOutputCounters => f.write_str("cipher retained output counters"),
            Self::CipherRetainedOutputRange => f.write_str("cipher retained output range"),
            Self::CipherReturnedOperandsAwaitingRelease => {
                f.write_str("cipher returned operands awaiting release")
            }
            Self::CipherRevocationStorageSize => f.write_str("cipher revocation storage size"),
            Self::CipherSizeResultCode => f.write_str("cipher size result code"),
            Self::CipherSnapshotAccounting => f.write_str("cipher snapshot accounting"),
            Self::CipherSnapshotParameterFamilyChanged => {
                f.write_str("cipher snapshot parameter family changed")
            }
            Self::CipherStreamCheckpointProgression => {
                f.write_str("cipher stream checkpoint progression")
            }
            Self::CipherTerminalCompletionUnproven => {
                f.write_str("cipher terminal completion unproven")
            }
            Self::CipherTerminalObservationAbsent => {
                f.write_str("cipher terminal observation absent")
            }
            Self::CipherTerminalOwnerRequiresTerminalCapture => {
                f.write_str("cipher terminal owner requires terminal capture")
            }
            Self::CipherTerminalProgression => f.write_str("cipher terminal progression"),
            Self::CipherTicketAlreadyHeldByCaller => {
                f.write_str("cipher ticket already held by caller")
            }
            Self::CipherWriterKeyAbsent => f.write_str("cipher writer key absent"),
            Self::CipherWriterPermissionAbsent => f.write_str("cipher writer permission absent"),
            Self::ClassicAeadParameterMutation => f.write_str("classic AEAD parameter mutation"),
            Self::ClassicAeadResultDirectionMismatch => {
                f.write_str("classic AEAD result direction mismatch")
            }
            Self::ConsumedCipherTicket => f.write_str("consumed cipher ticket"),
            Self::DeclarationWithoutCipherExtension => {
                f.write_str("declaration without cipher extension")
            }
            Self::DigestOidOnNonDigestOwner => f.write_str("digest OID on non-digest owner"),
            Self::ExtensionCipherFacadeIncomplete => {
                f.write_str("extension cipher facade incomplete")
            }
            Self::ExtensionCipherFacadeRoute => f.write_str("extension cipher facade route"),
            Self::ExtensionCipherRequiresAnExplicitBufferOrLengthQuery => {
                f.write_str("extension cipher requires an explicit buffer or length query")
            }
            Self::ExtensionCipherRequiresGraphSnapshotPreparation => {
                f.write_str("extension cipher requires graph snapshot preparation")
            }
            Self::ExtensionCipherRouteDeclaration => {
                f.write_str("extension cipher route declaration")
            }
            Self::ExtensionGraphHasNoSeparateNonceField => {
                f.write_str("extension graph has no separate nonce field")
            }
            Self::IncrementalCipherStartsWithoutQueuedInput => {
                f.write_str("incremental cipher starts without queued input")
            }
            Self::InputPrefixRange => f.write_str("input prefix range"),
            Self::LegacyAeadNonceWidth => f.write_str("legacy AEAD nonce width"),
            Self::MultipartCipherDeclarationRequired => {
                f.write_str("multipart cipher declaration required")
            }
            Self::NativeCipherAsynchronousModeUnavailable => {
                f.write_str("native cipher native asynchronous mode is unsupported")
            }
            Self::NativeWriterKeyAbsent => f.write_str("native writer key absent"),
            Self::NonAeadRecordAuthenticationFields => {
                f.write_str("non-AEAD record authentication fields")
            }
            Self::OnlyCcmRequiresAnExplicitStreamPlaintextLength => {
                f.write_str("only CCM requires an explicit stream plaintext length")
            }
            Self::RecordRouteRequiresArchivedCipherGraph => {
                f.write_str("record route requires archived cipher graph")
            }
            Self::RecordTagWidth => f.write_str("record tag width"),
            Self::RevocationWithoutNativeWriter => f.write_str("revocation without native writer"),
            Self::SelectedBlockCipherFunctionUnavailable => {
                f.write_str("selected block cipher function unavailable")
            }
            Self::SelectedCipherFunctionsUnavailable => {
                f.write_str("selected cipher functions unavailable")
            }
            Self::SinglePartCipherDeclarationRequired => {
                f.write_str("single-part cipher declaration required")
            }
            Self::StaleCipherFacadeTicket => f.write_str("stale cipher facade ticket"),
            Self::StandaloneNativeCipherParametersRequired => {
                f.write_str("standalone native cipher parameters required")
            }
            Self::SynchronousAesDecryptionDidNotComplete => {
                f.write_str("synchronous AES decryption did not complete")
            }
            Self::SynchronousAesEncryptionDidNotComplete => {
                f.write_str("synchronous AES encryption did not complete")
            }
            Self::SynchronousCipherDidNotComplete => {
                f.write_str("synchronous cipher did not complete")
            }
            Self::SynchronousClassicAeadDidNotComplete => {
                f.write_str("synchronous classic AEAD did not complete")
            }
            Self::UnexpectedCipherGraphPacket => f.write_str("unexpected cipher graph packet"),
        }
    }
}
