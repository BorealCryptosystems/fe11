// SPDX-License-Identifier: Apache-2.0
use crate::{BusyReason, RejectionReason, ResourceKind, UnsupportedReason};
use std::fmt;

mod completion;
pub(crate) mod encapsulation;
mod output_size;
pub(crate) use output_size::checked_native_size;
pub use output_size::NativeOutputSize;

/// Local admission failure following completed attribute observations. This
/// fixed-size diagnostic preserves resource dimensions without an allocation
/// or any attribute contents. It does not authorize replay of those calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeAdmissionFailure {
    /// An amount that can fit is temporarily unavailable.
    Busy(BusyReason),
    /// The requested amount itself exceeds the configured local ceiling.
    ResourceLimitExceeded {
        /// Static resource name, without input contents.
        resource: ResourceKind,
        /// Required amount in the resource's units.
        requested: usize,
        /// Caller-configured ceiling in the same units.
        limit: usize,
    },
    /// The caller cancelled local admission before its next dispatch.
    Cancelled,
    /// The caller's absolute local-admission deadline expired.
    Deadline,
}

/// Errors contain static categories and public PKCS#11 or OS status codes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc = include_str!("../docs/error-recovery.md")]
pub enum Error {
    /// The selected feature has no supported contract in this library profile.
    /// This local error is returned before dispatch; it is not a native CK_RV.
    Unsupported(UnsupportedReason),
    /// A fixed Init scalar changed in the explicitly selected owned-parameters
    /// representation. Refused before native dispatch, with no nonce consumed.
    /// This is a representation choice, not a PKCS#11 normative restriction.
    InitParameterChangeBeforeEffect {
        /// Changed scalar identifier only; no parameter value is disclosed.
        field: crate::MessageInitField,
    },
    /// A local invariant rejected admission or result publication.
    /// This category alone does not prove that no native effect occurred.
    Rejected(RejectionReason),
    /// A required loader observation was unavailable before loading any provider.
    LoaderObservationUnavailable {
        /// Named channel selected by the caller.
        channel: crate::WindowsLoaderChannel,
        /// Static cause or exact OS status, without paths or registry contents.
        cause: crate::WindowsLoaderUnavailable,
    },

    /// Explicit content observation did not yield available bytes.
    ContentUnavailable {
        /// Precise attribute or interpretation status, with no value.
        status: crate::ContentStatus,
    },

    /// The provider reported an error; an effect may already have occurred.
    Native {
        /// Static PKCS#11 function name.
        function: &'static str,
        /// Public provider return code.
        code: u64,
        /// True when the provider may already have changed native state.
        may_have_effect: bool,
    },
    /// A synchronous cipher call needs caller-selected output storage. The
    /// native operation and its buffers remain owned by this session; no output
    /// is published and no retry or cancellation occurs. Use the same session's
    /// take_cipher_ticket, resize_cipher_output and poll_cipher to continue, or
    /// explicitly close/cancel the operation. Cloning this error creates no ticket.
    CipherBufferRequired(crate::CipherBufferRequest),
    /// A synchronous signature call needs explicitly selected output storage.
    /// The exact native code, required bytes and previous capacity are preserved
    /// without publishing output or retrying. The session retains its operation;
    /// retrieve its signature or message ticket to continue or explicitly cancel.
    /// This diagnostic carries no continuation authority of its own.
    SignatureBufferRequired(crate::SignatureBufferRequest),
    /// The named native operation returned CKR_OK, but later bookkeeping or
    /// publication failed. Its native effect is completed; do not retry it.
    OperationCompleted {
        /// Exact successful native function, not an application policy name.
        function: &'static str,
        /// Original post-success failure, without the withheld report or values.
        cause: Box<Error>,
    },
    /// A native call returned a nonzero code and a local integrity or
    /// bookkeeping check also failed. Neither failure hides the other. Possible
    /// effects and revoked references must not be treated as an atomic rollback.
    NativeAndLocalFailure {
        /// Exact native function whose return preceded the local failure.
        function: &'static str,
        /// Exact nonzero native return code.
        code: u64,
        /// Local failure detected after that native return.
        cause: Box<Error>,
    },
    /// A returned output size and a local failure are both preserved. Neither
    /// authorizes output access, allocation, replay or a claim of non-creation.
    NativeOutputAndLocalFailure {
        /// Exact scalar observation and caller-selected bound.
        size: NativeOutputSize,
        /// Independent local failure in storage reserved before native dispatch.
        cause: Box<Error>,
    },
    /// A native size observation could not satisfy the caller's local bound.
    /// A successful size query is not a completed capture or cryptographic call.
    OutputSizeRejected {
        /// Exact observation and bound; no output bytes are disclosed.
        size: NativeOutputSize,
        /// Local conversion or bound failure, independent of the native code.
        reason: crate::InputBoundsRejection,
    },
    /// A native output call refused the supplied capacity. No partial output or
    /// automatic retry. This observation alone does not prove absence of effects;
    /// encapsulation retains the enclosing `ObjectsMayRemain` diagnostic.
    OutputBufferTooSmall {
        /// Exact native function that returned the refusal.
        function: &'static str,
        /// Original CKR_BUFFER_TOO_SMALL value.
        code: u64,
        /// Exact native required length, not an approved allocation size.
        /// Units are bytes, or descriptors for `C_GetInterfaceList`.
        required: usize,
        /// Capacity supplied by the caller, in the same native units.
        capacity: usize,
    },
    /// A native object mutation may have left objects whose ownership or cleanup
    /// could not be established. Reconciliation is required; no handles or private
    /// values are disclosed by this diagnostic.
    ObjectsMayRemain(Box<Error>),
    /// An operation and a cleanup stage both failed. A distinct later stage may
    /// preserve an earlier compound cause. The full chain retains the original
    /// native return and each secondary failure; it authorizes no cleanup replay.
    CleanupFailed {
        /// Original operation failure, with its native code/effect if applicable.
        operation: Box<Error>,
        /// Cleanup or local validation/bookkeeping failure; never a secret.
        cleanup: Box<Error>,
    },
    /// Invalid OAEP/AEAD ciphertext length or native cryptographic validity failure.
    /// Provider operational failures remain Native errors; no plaintext is returned.
    InvalidCiphertext,
    /// A lifecycle resource is occupied; this local acquisition made no native
    /// call. Earlier steps of the enclosing operation may already have effects.
    /// Releasing other owners can make admission possible. A request that exceeds
    /// the configured ceiling instead returns `ResourceLimitExceeded`.
    Busy(BusyReason),
    /// The request itself exceeds a caller-configured local resource ceiling.
    /// Waiting or releasing other owners cannot admit it. No native call is made
    /// by this acquisition; preceding steps may already have native effects.
    ResourceLimitExceeded {
        /// Static resource name; contains no key, attribute or input contents.
        resource: ResourceKind,
        /// Required amount, including this owner's existing credit on extension.
        requested: usize,
        /// Configured ceiling in the same units as `requested`.
        limit: usize,
    },
    /// Local admission stopped a grouped attribute read after native calls had
    /// completed. No values are published and no native call is retried.
    AttributeReadInterrupted {
        /// Exact completed call codes and descriptor counts.
        calls: crate::AttributeBatchCalls,
        /// Exact local admission cause, without any attribute contents.
        cause: AttributeAdmissionFailure,
    },
    /// A completed or uncertain attribute call could not yield a safe result.
    /// No attribute bytes are included; the native code is retained unchanged.
    AttributeReadInvalid {
        /// Native call provenance, including a partial-result return code.
        call: crate::AttributeBatchCall,
        /// Static integrity/completion reason, without attribute contents.
        reason: RejectionReason,
    },
    /// Local resource admission was cancelled before this request's next native dispatch.
    /// An operation already owned by an earlier request is not cancelled.
    AdmissionCancelled,
    /// The caller's local admission deadline expired before its next native dispatch.
    /// This does not describe or interrupt native execution time.
    AdmissionDeadline,
    /// A lock was poisoned; continuation is refused.
    Poisoned,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(reason) => write!(f, "unsupported: {reason}"),
            Self::InitParameterChangeBeforeEffect { field } => {
                write!(
                    f,
                    "initialization parameter changed before dispatch: {field:?}"
                )
            }
            Self::Rejected(reason) => write!(f, "rejected: {reason}"),
            Self::LoaderObservationUnavailable { channel, cause } => {
                write!(f, "loader observation {channel:?} unavailable: {cause:?}")
            }
            Self::ContentUnavailable { status } => write!(f, "content unavailable: {status:?}"),
            Self::Native {
                function,
                code,
                may_have_effect,
            } => {
                write!(
                    f,
                    "{function} returned 0x{code:08x}; effects possible: {may_have_effect}"
                )
            }
            Self::CipherBufferRequired(request) => {
                write!(f, "cipher output storage required: {request:?}")
            }
            Self::SignatureBufferRequired(request) => {
                write!(f, "signature output storage required: {request:?}")
            }
            Self::OperationCompleted { function, cause } => {
                write!(
                    f,
                    "{function} completed; result publication failed: {cause}"
                )
            }
            Self::NativeAndLocalFailure {
                function,
                code,
                cause,
            } => {
                write!(
                    f,
                    "{function} returned 0x{code:08x}; local failure: {cause}"
                )
            }
            Self::OutputBufferTooSmall {
                function,
                code,
                required,
                capacity,
            } => {
                write!(f, "{function} returned 0x{code:08x}; output requires {required}, capacity {capacity}")
            }
            Self::NativeOutputAndLocalFailure { size, cause } => {
                write!(f, "{size}; local failure: {cause}")
            }
            Self::OutputSizeRejected { size, reason } => {
                write!(f, "{size}; size rejected: {reason}")
            }
            Self::ObjectsMayRemain(cause) => write!(f, "native objects may remain: {cause}"),
            Self::CleanupFailed { operation, cleanup } => {
                write!(
                    f,
                    "operation failed: {operation}; cleanup failed: {cleanup}"
                )
            }
            Self::InvalidCiphertext => f.write_str("invalid ciphertext"),
            Self::Busy(reason) => write!(f, "busy: {reason}"),
            Self::ResourceLimitExceeded {
                resource,
                requested,
                limit,
            } => {
                write!(
                    f,
                    "{resource}: requested {requested}, configured limit {limit}"
                )
            }
            Self::AttributeReadInterrupted { calls, cause } => {
                write!(f, "attribute read interrupted after {calls:?}: {cause}")
            }
            Self::AttributeReadInvalid { call, reason } => {
                write!(f, "attribute result unusable after {call:?}: {reason}")
            }
            Self::AdmissionCancelled => f.write_str("local admission cancelled"),
            Self::AdmissionDeadline => f.write_str("local admission deadline expired"),
            Self::Poisoned => f.write_str("synchronization state poisoned"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OperationCompleted { cause, .. }
            | Self::NativeAndLocalFailure { cause, .. }
            | Self::NativeOutputAndLocalFailure { cause, .. }
            | Self::ObjectsMayRemain(cause) => Some(cause.as_ref()),
            // Both failures remain available in the public fields; the standard
            // single-source chain follows the original operation failure.
            Self::CleanupFailed { operation, .. } => Some(operation.as_ref()),
            _ => None,
        }
    }
}
impl fmt::Display for AttributeAdmissionFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy(reason) => write!(f, "busy: {reason}"),
            Self::ResourceLimitExceeded {
                resource,
                requested,
                limit,
            } => {
                write!(
                    f,
                    "{resource}: requested {requested}, configured limit {limit}"
                )
            }
            Self::Cancelled => f.write_str("local admission cancelled"),
            Self::Deadline => f.write_str("local admission deadline expired"),
        }
    }
}
/// Result type for library operations.
pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn check(
    rv: fe11_sys::CK_RV,
    function: &'static str,
    may_have_effect: bool,
) -> Result<()> {
    if rv == fe11_sys::CKR_OK as fe11_sys::CK_RV {
        Ok(())
    } else {
        Err(Error::Native {
            function,
            code: rv as u64,
            may_have_effect,
        })
    }
}

/// Unbound diagnostic leaf, allocated by an enclosing prepaid preparation.
/// Selecting the native function later transfers the same box without allocating.
/// Its enclosing owner must retain the leaf's credit through destruction or the
/// actual public error transfer; returning between internal helpers is not enough.
pub(crate) struct CompletionStorage {
    cause: Box<Error>,
}
impl CompletionStorage {
    pub(crate) const fn allocation_bytes() -> usize {
        std::mem::size_of::<Error>()
    }

    pub(crate) fn allocate() -> Result<Self> {
        Ok(Self {
            cause: crate::allocation::boxed(Error::Rejected(crate::RejectionReason::Diagnostics(
                crate::DiagnosticsRejection::CompletionDiagnosticNotUsed,
            )))?,
        })
    }

    pub(crate) fn bind(self, function: &'static str) -> CompletionDiagnostic {
        CompletionDiagnostic {
            function,
            cause: self.cause,
        }
    }

    /// Reuse the admitted leaf for a creation whose effect is still uncertain.
    /// The enclosing root keeps its credit after the marker leaves this helper.
    pub(crate) fn mark_remaining(mut self, cause: Error) -> Error {
        *self.cause = cause;
        Error::ObjectsMayRemain(self.cause)
    }
}

/// One prepaid leaf shared by mutually exclusive sequence/publication failures.
/// The cell is local to one synchronous invocation and never enters native code.
/// Its root keeps the credit even after a nested sequence transfers the error.
pub(crate) struct CompletionCell {
    storage: std::cell::RefCell<Option<CompletionStorage>>,
}
impl CompletionCell {
    /// The caller has already admitted this leaf and retains its credit.
    pub(crate) fn from_storage(storage: CompletionStorage) -> Self {
        Self {
            storage: std::cell::RefCell::new(Some(storage)),
        }
    }

    pub(crate) fn finish<T>(&self, function: &'static str, result: Result<T>) -> Result<T> {
        self.finish_native(function, fe11_sys::CKR_OK, result)
    }

    pub(crate) fn finish_native<T>(
        &self,
        function: &'static str,
        code: fe11_sys::CK_RV,
        result: Result<T>,
    ) -> Result<T> {
        result.map_err(|cause| self.error(function, code, cause))
    }

    pub(crate) fn completed_error(&self, function: &'static str, cause: Error) -> Error {
        self.error(function, fe11_sys::CKR_OK, cause)
    }

    /// A failed boundary inspection cannot establish successful completion.
    /// The reserved leaf is needed only when a native refusal must be retained
    /// alongside the local cause; the enclosing invocation keeps its charge.
    pub(crate) fn boundary_failure(
        &self,
        function: &'static str,
        code: fe11_sys::CK_RV,
        cause: Error,
    ) -> Error {
        if code == fe11_sys::CKR_OK {
            cause
        } else {
            self.error(function, code, cause)
        }
    }

    pub(crate) fn output_failure(&self, size: NativeOutputSize, cause: Error) -> Error {
        self.storage
            .borrow_mut()
            .take()
            .expect("one output error on exclusive invocation branches")
            .bind(size.function)
            .output_failure(
                size.code as fe11_sys::CK_RV,
                size.reported,
                size.limit,
                cause,
            )
    }

    fn error(&self, function: &'static str, code: fe11_sys::CK_RV, cause: Error) -> Error {
        let mut storage = self
            .storage
            .borrow_mut()
            .take()
            .expect("one completion error on exclusive invocation branches");
        *storage.cause = cause;
        if code == fe11_sys::CKR_OK {
            Error::OperationCompleted {
                function,
                cause: storage.cause,
            }
        } else {
            Error::NativeAndLocalFailure {
                function,
                code: code as u64,
                cause: storage.cause,
            }
        }
    }
}

/// The leaf is destroyed before its credit; a consumed leaf stays charged until
/// the public result transfer rather than the return of an internal helper.
pub(crate) struct PreparedCompletionCell {
    storage: CompletionCell,
    _credit: crate::symmetric::memory::Credit,
}
impl PreparedCompletionCell {
    pub(crate) fn prepare(prepaid: &mut crate::symmetric::memory::Credit) -> Result<Self> {
        let credit = prepaid.split(CompletionStorage::allocation_bytes())?;
        Ok(Self {
            storage: CompletionCell::from_storage(CompletionStorage::allocate()?),
            _credit: credit,
        })
    }

    pub(crate) fn cell(&self) -> &CompletionCell {
        &self.storage
    }
}

/// A prepaid leaf whose native function is selected only at dispatch. The
/// synchronous publication root retains this owner after `take` transfers its
/// storage, so native retirement cannot release the charge of an internal error.
pub(crate) struct PreparedCompletionStorage {
    storage: Option<CompletionStorage>,
    _credit: crate::symmetric::memory::Credit,
}
impl PreparedCompletionStorage {
    pub(crate) fn allocation_bytes() -> usize {
        CompletionStorage::allocation_bytes()
    }

    pub(crate) fn prepare(prepaid: &mut crate::symmetric::memory::Credit) -> Result<Self> {
        let credit = prepaid.split(Self::allocation_bytes())?;
        Ok(Self {
            storage: Some(CompletionStorage::allocate()?),
            _credit: credit,
        })
    }

    /// Bind storage already allocated in the admitted candidate. This performs
    /// no allocation and is safe to use while attaching that candidate.
    pub(crate) fn from_storage(
        storage: CompletionStorage,
        prepaid: &mut crate::symmetric::memory::Credit,
    ) -> Result<Self> {
        let credit = prepaid.split(Self::allocation_bytes())?;
        Ok(Self {
            storage: Some(storage),
            _credit: credit,
        })
    }

    pub(crate) fn take(&mut self) -> Result<CompletionStorage> {
        self.storage
            .take()
            .ok_or(Error::Rejected(crate::RejectionReason::Diagnostics(
                crate::DiagnosticsRejection::CompletionStorageAlreadyConsumed,
            )))
    }
}

/// A single completion leaf whose charge stays at the operation root after
/// `take` moves the diagnostic into a native-call or publication helper.
/// This owner must outlive every internal use of the resulting Error.
pub(crate) struct PreparedCompletion {
    diagnostic: Option<CompletionDiagnostic>,
    _credit: crate::symmetric::memory::Credit,
}
impl PreparedCompletion {
    pub(crate) fn allocation_bytes() -> usize {
        CompletionStorage::allocation_bytes()
    }

    pub(crate) fn prepare(
        function: &'static str,
        prepaid: &mut crate::symmetric::memory::Credit,
    ) -> Result<Self> {
        let credit = prepaid.split(Self::allocation_bytes())?;
        Ok(Self {
            diagnostic: Some(CompletionStorage::allocate()?.bind(function)),
            _credit: credit,
        })
    }

    pub(crate) fn take(&mut self) -> Result<CompletionDiagnostic> {
        self.diagnostic
            .take()
            .ok_or(Error::Rejected(crate::RejectionReason::Diagnostics(
                crate::DiagnosticsRejection::CompletionDiagnosticAlreadyConsumed,
            )))
    }
}

// Storage is prepared before native dispatch. The destruction owner returns it
// only after CKR_OK; finishing a denied publication then needs no allocation.
pub(crate) struct CompletionDiagnostic {
    function: &'static str,
    cause: Box<Error>,
}

/// Two simultaneously reported causes, without an object-uncertainty marker.
/// The enclosing preparation owns their credit through final publication.
pub(crate) struct FailurePair {
    operation: Box<Error>,
    cleanup: Box<Error>,
}
impl FailurePair {
    pub(crate) const fn allocation_bytes() -> usize {
        2 * std::mem::size_of::<Error>()
    }

    pub(crate) fn allocate() -> Result<Self> {
        Ok(Self {
            operation: crate::allocation::boxed(Error::Rejected(
                crate::RejectionReason::Diagnostics(
                    crate::DiagnosticsRejection::PrimaryFailureNotUsed,
                ),
            ))?,
            cleanup: crate::allocation::boxed(Error::Rejected(
                crate::RejectionReason::Diagnostics(
                    crate::DiagnosticsRejection::SecondaryFailureNotUsed,
                ),
            ))?,
        })
    }

    pub(crate) fn finish(mut self, operation: Error, cleanup: Error) -> Error {
        *self.operation = operation;
        *self.cleanup = cleanup;
        Error::CleanupFailed {
            operation: self.operation,
            cleanup: self.cleanup,
        }
    }
}

/// Reusable failure leaves and one uncertainty marker per possible output.
/// Successful destruction keeps both failure leaves for the next object. Once
/// a compound failure is returned, existing cleanup rules prohibit another C
/// cleanup attempt. Plain uncertainty markers may accumulate independently.
pub(crate) struct CleanupStorage {
    operation: Option<Box<Error>>,
    cleanup: Option<Box<Error>>,
    markers: Vec<Box<Error>>,
}
impl CleanupStorage {
    pub(crate) fn requested(marker_count: usize) -> Result<usize> {
        Self::bytes(marker_count, marker_count)
    }

    fn bytes(marker_count: usize, marker_capacity: usize) -> Result<usize> {
        marker_count
            .checked_add(2)
            .and_then(|count| count.checked_mul(std::mem::size_of::<Error>()))
            .and_then(|bytes| {
                marker_capacity
                    .checked_mul(std::mem::size_of::<Box<Error>>())
                    .and_then(|table| bytes.checked_add(table))
            })
            .ok_or(Error::Rejected(crate::RejectionReason::Diagnostics(
                crate::DiagnosticsRejection::CleanupStorageAccounting,
            )))
    }

    pub(crate) fn allocate(marker_count: usize) -> Result<Self> {
        let mut markers = Vec::new();
        markers.try_reserve_exact(marker_count).map_err(|_| {
            Error::Rejected(crate::RejectionReason::Diagnostics(
                crate::DiagnosticsRejection::CleanupMarkerAllocation,
            ))
        })?;
        for _ in 0..marker_count {
            markers.push(crate::allocation::boxed(Error::Rejected(
                crate::RejectionReason::Diagnostics(
                    crate::DiagnosticsRejection::CleanupMarkerNotUsed,
                ),
            ))?);
        }
        Ok(Self {
            operation: Some(crate::allocation::boxed(Error::Rejected(
                crate::RejectionReason::Diagnostics(
                    crate::DiagnosticsRejection::CleanupCauseNotUsed,
                ),
            ))?),
            cleanup: Some(crate::allocation::boxed(Error::Rejected(
                crate::RejectionReason::Diagnostics(
                    crate::DiagnosticsRejection::CleanupFailureNotUsed,
                ),
            ))?),
            markers,
        })
    }

    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        Self::bytes(self.markers.len(), self.markers.capacity())
    }

    pub(crate) fn mark_remaining(&mut self, cause: Error) -> Error {
        let mut marker = self.markers.pop().expect("one cleanup marker per output");
        *marker = cause;
        Error::ObjectsMayRemain(marker)
    }

    pub(crate) fn sequence_failure(&mut self, cause: Error, failure: Error) -> Error {
        let mut operation = self
            .operation
            .take()
            .expect("single compound cleanup failure");
        let mut cleanup = self
            .cleanup
            .take()
            .expect("single compound cleanup failure");
        *operation = cause;
        *cleanup = failure;
        Error::CleanupFailed { operation, cleanup }
    }

    pub(crate) fn object_failure(&mut self, mut cause: Error, failure: Error) -> Error {
        // Match CleanupDiagnostic::finish: normalize only outer object markers,
        // retaining every nested native/local failure of the primary cause.
        while let Error::ObjectsMayRemain(inner) = cause {
            cause = *inner;
        }
        let compound = self.sequence_failure(cause, failure);
        self.mark_remaining(compound)
    }
}

/// A synchronous root retains the credit of two causes after composition.
/// Parking a ticket can fail after the operation itself; neither failure may
/// replace the other, and this stage must not allocate while holding a guard.
pub(crate) struct PreparedFailurePair {
    pair: Option<FailurePair>,
    credit: crate::symmetric::memory::Credit,
}
impl PreparedFailurePair {
    pub(crate) const fn allocation_bytes() -> usize {
        FailurePair::allocation_bytes()
    }

    pub(crate) fn preparation_bytes() -> usize {
        Self::allocation_bytes() + crate::symmetric::memory::Budget::observation_bytes()
    }

    pub(crate) fn prepare(prepaid: &mut crate::symmetric::memory::Credit) -> Result<Self> {
        let credit = prepaid.split(Self::allocation_bytes())?;
        Ok(Self {
            pair: Some(FailurePair::allocate()?),
            credit,
        })
    }

    pub(crate) fn budget(&self) -> &std::sync::Arc<crate::symmetric::memory::Budget> {
        self.credit.budget()
    }

    pub(crate) fn finish(&mut self, operation: Error, cleanup: Error) -> Error {
        self.pair
            .take()
            .expect("one paired failure per root")
            .finish(operation, cleanup)
    }
}

impl crate::symmetric::memory::RetainedStorage for PreparedFailurePair {
    fn retain_credits(&self, retained: &mut crate::symmetric::memory::RetainedBytes) -> Result<()> {
        retained.add_credit(&self.credit)
    }
}

/// Root-owned credit survives errors moved from cleanup helpers to publication.
/// The public creation entry holds both independent diagnostics across private
/// runners and final result projection. Installing them transfers existing
/// credits only; it does not allocate or reserve more storage.
#[derive(Default)]
pub(crate) enum PreparedCreationDiagnostics {
    #[default]
    Empty,
    Creation {
        completion: PreparedCompletionStorage,
        cleanup: PreparedCleanupStorage,
    },
    Randoms {
        completion: PreparedCompletionStorage,
    },
}

impl PreparedCreationDiagnostics {
    pub(crate) fn retain_randoms(
        &mut self,
        completion: PreparedCompletionStorage,
    ) -> &mut PreparedCompletionStorage {
        *self = Self::Randoms { completion };
        let Self::Randoms { completion } = self else {
            unreachable!()
        };
        completion
    }

    pub(crate) fn install(
        &mut self,
        completion: PreparedCompletionStorage,
        cleanup: PreparedCleanupStorage,
    ) -> (&mut PreparedCompletionStorage, &mut PreparedCleanupStorage) {
        *self = Self::Creation {
            completion,
            cleanup,
        };
        let Self::Creation {
            completion,
            cleanup,
        } = self
        else {
            unreachable!()
        };
        (completion, cleanup)
    }
}

/// Root-owned credit survives errors moved from cleanup helpers to publication.
pub(crate) struct PreparedCleanupStorage {
    storage: CleanupStorage,
    _credit: crate::symmetric::memory::Credit,
}

/// Native creation and cleanup diagnostics remain charged through the public
/// result, including imports, KEM, unwrap and derivation observation helpers.
pub(crate) type ObjectCreationDiagnostics = Option<(PreparedCompletion, PreparedCleanupStorage)>;
impl PreparedCleanupStorage {
    pub(crate) fn bind(
        storage: CleanupStorage,
        prepaid: &mut crate::symmetric::memory::Credit,
    ) -> Result<Self> {
        let credit = prepaid.split(storage.allocated_bytes()?)?;
        Ok(Self {
            storage,
            _credit: credit,
        })
    }

    pub(crate) fn storage(&mut self) -> &mut CleanupStorage {
        &mut self.storage
    }
}

/// A complete cleanup error shape charged at the synchronous operation root.
/// Taking its leaves does not release their credit: the root must remain alive
/// through cleanup and the public transfer of any resulting error chain.
pub(crate) struct PreparedCleanupDiagnostic {
    diagnostic: Option<CleanupDiagnostic>,
    _credit: crate::symmetric::memory::Credit,
}
impl PreparedCleanupDiagnostic {
    pub(crate) const fn allocation_bytes() -> usize {
        CleanupDiagnostic::allocation_bytes()
    }

    pub(crate) fn prepare(prepaid: &mut crate::symmetric::memory::Credit) -> Result<Self> {
        let credit = prepaid.split(Self::allocation_bytes())?;
        Ok(Self {
            diagnostic: Some(CleanupDiagnostic::prepare_sequence()?),
            _credit: credit,
        })
    }

    /// Refill an already credited slot after its previous error was transferred
    /// to the caller. Only a new public invocation may reuse a consumed slot;
    /// an internal helper return does not establish that transfer.
    pub(crate) fn replenish(&mut self) -> Result<()> {
        if self.diagnostic.is_none() {
            self.diagnostic = Some(CleanupDiagnostic::prepare_sequence()?);
        }
        Ok(())
    }

    pub(crate) fn take(&mut self, cause: Error) -> CleanupDiagnostic {
        let mut diagnostic = self.diagnostic.take().expect("one cleanup stage per root");
        diagnostic.replace_operation(cause);
        diagnostic
    }
}

impl crate::symmetric::memory::RetainedStorage for PreparedCleanupDiagnostic {
    fn retain_credits(&self, retained: &mut crate::symmetric::memory::RetainedBytes) -> Result<()> {
        retained.add_credit(&self._credit)
    }
}

// Reserve the complete error shape before cleanup dispatch. A successful cleanup
// returns the original error unchanged, including any pre-existing effect marker.
pub(crate) struct CleanupDiagnostic {
    prepared: Error,
}
impl Error {
    pub(crate) fn without_object_marker(&self) -> &Error {
        let mut error = self;
        while let Error::ObjectsMayRemain(inner) = error {
            error = inner;
        }
        error
    }

    pub(crate) fn authentication_lost(&self) -> bool {
        // Preserve the function-specific logout evidence through the internal
        // cleanup/publication chain. A key-specific authentication refusal still
        // does not establish token-wide logout.
        match self.without_object_marker() {
            Error::Native {
                function: "C_Logout",
                code,
                ..
            }
            | Error::NativeAndLocalFailure {
                function: "C_Logout",
                code,
                ..
            } if *code == fe11_sys::CKR_USER_NOT_LOGGED_IN as u64 => true,
            Error::CleanupFailed { operation, cleanup } => {
                operation.authentication_lost() || cleanup.authentication_lost()
            }
            Error::OperationCompleted { cause, .. }
            | Error::NativeAndLocalFailure { cause, .. }
            | Error::NativeOutputAndLocalFailure { cause, .. } => cause.authentication_lost(),
            _ => false,
        }
    }
}
impl CleanupDiagnostic {
    /// Heap leaves owned by a preallocated sequence-cleanup diagnostic.
    pub(crate) const fn allocation_bytes() -> usize {
        3 * std::mem::size_of::<Error>()
    }

    /// Allocate before session possession and before any native effects. The
    /// primary cause is filled later without allocation; the enclosing owner
    /// charges these leaves together with its complete preparation graph.
    pub(crate) fn prepare_sequence() -> Result<Self> {
        let operation = crate::allocation::boxed(Error::Rejected(
            crate::RejectionReason::Diagnostics(crate::DiagnosticsRejection::SequenceCauseNotUsed),
        ))?;
        let cleanup = crate::allocation::boxed(Error::Rejected(
            crate::RejectionReason::Diagnostics(crate::DiagnosticsRejection::CleanupNotDispatched),
        ))?;
        let compound = crate::allocation::boxed(Error::CleanupFailed { operation, cleanup })?;
        Ok(Self {
            prepared: Error::ObjectsMayRemain(compound),
        })
    }

    /// Install the primary cause into storage reserved before native effects.
    /// This performs no allocation and does not normalize an earlier failure.
    pub(crate) fn replace_operation(&mut self, cause: Error) {
        let Error::ObjectsMayRemain(compound) = &mut self.prepared else {
            unreachable!()
        };
        let Error::CleanupFailed { operation, .. } = compound.as_mut() else {
            unreachable!()
        };
        **operation = cause;
    }

    // Sequence cleanup introduces no object-mutation marker of its own. Unpack
    // only this stage's prepared shell: an older ObjectsMayRemain marker belongs
    // to the original cause and survives both successful and failed cleanup.
    pub(crate) fn finish_sequence(self, failure: Option<Error>) -> Error {
        let Error::ObjectsMayRemain(compound) = self.prepared else {
            unreachable!()
        };
        let Error::CleanupFailed {
            operation,
            mut cleanup,
        } = *compound
        else {
            unreachable!()
        };
        match failure {
            Some(failure) => {
                *cleanup = failure;
                Error::CleanupFailed { operation, cleanup }
            }
            None => *operation,
        }
    }
    // All callers supply a leaf from local recording, the native return, or
    // registry bookkeeping. No callback or externally constructed error enters.
    pub(crate) fn finish(self, failure: Option<Error>) -> Error {
        let Error::ObjectsMayRemain(mut compound) = self.prepared else {
            unreachable!()
        };
        if let Some(failure) = failure {
            let Error::CleanupFailed { operation, cleanup } = compound.as_mut() else {
                unreachable!()
            };
            let mut primary = std::mem::replace(operation.as_mut(), Error::Poisoned);
            while let Error::ObjectsMayRemain(inner) = primary {
                primary = *inner;
            }
            **operation = primary;
            **cleanup = failure;
            Error::ObjectsMayRemain(compound)
        } else {
            let Error::CleanupFailed { operation, .. } = *compound else {
                unreachable!()
            };
            *operation
        }
    }
}
