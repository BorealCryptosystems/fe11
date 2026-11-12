// SPDX-License-Identifier: Apache-2.0
//! Correlated native observations, never a certification or authentication verdict.

use super::{
    asynchronous, record, spend, AdvancedSession, AdvancedSessionMode, OperationTicket,
    SessionValidation,
};
use crate::error::check;
use crate::module::{SessionEntry, State};

use crate::symmetric::memory::{Budget, Credit};
use crate::{Error, Result};

use fe11_sys::{CKR_OK, CKR_PENDING, CKS_LAST_VALIDATION_OK, CK_ASYNC_DATA, CK_FLAGS, CK_RV};
use std::sync::atomic::Ordering;
use std::sync::Arc;

mod report_storage;
pub(super) use report_storage::{PreparedReport, ReportStorage};

// A refused read cannot by itself invalidate a healthy cryptographic session.
// Keep the exact error; no absence or validation result is inferred from it.
fn read_failure_scope(rv: CK_RV) -> crate::native_return::FailureScope {
    crate::native_return::attribute_scope(rv)
}

pub(super) fn completed_read_refusal(error: &Error) -> bool {
    matches!(error, Error::Native {
        function: "C_GetSessionValidationFlags", code, ..
    } if crate::native_return::diagnostic_context_scope(*code) == crate::native_return::FailureScope::None
        && crate::native_return::diagnostic_memory_returned(*code))
}

/// Explicit capture policy for supported cryptographic ticket owners and the synchronous
/// helpers that expose a correlated report. This is not a session-wide native
/// setting. See [`AdvancedSession::set_validation_capture`] for its exact scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidationCaptureMode {
    /// No automatically added observation calls or report allocations.
    /// Explicit validation reads and digest_with_validation remain explicit requests.
    Disabled,
    /// Observe completed messages/finals in the selected advanced owner before
    /// its next native step. Plain synchronous Session facades are unaffected.
    Capture,
}
/// One native last-operation observation. Its meaning belongs to the module's
/// validation rules; a flag never upgrades a failed cryptographic result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidationObservation {
    /// Exact completed PKCS#11 function, not the query function.
    pub function: &'static str,
    /// Zero-based message in a batch, or None for a final/classic operation.
    pub message_index: Option<usize>,
    /// Exact flags or explicit absence of the selected function.
    pub validation: SessionValidation,
}
/// Ordered observations attached to the same consumed ticket as its result.
/// Neither the report nor its observation values assert FIPS certification.
pub struct ValidationReport {
    observations: Vec<ValidationObservation>,
    _credit: Credit,
}
impl ValidationReport {
    /// Read observations without releasing their bounded memory reservation.
    pub fn observations(&self) -> &[ValidationObservation] {
        &self.observations
    }
}
#[derive(Clone, Copy)]
pub(super) struct Point {
    pub function: &'static str,
    pub message_index: Option<usize>,
}
struct Frame {
    flags: CK_FLAGS,
    completion: CK_ASYNC_DATA,
    name: [u8; 32],
}
// SAFETY: frame is boxed before dispatch and only accessed through the owning
// operation/session guards. Pending storage is neither read nor relocated.
unsafe impl Send for Frame {}
// Failure and native retention are distinct: a malformed completion may fail
// locally while the module can still retain the original stable frame.
#[derive(Clone, Copy)]
enum NativeRetention {
    Released,
    ExecutionIncomplete,
    ReturnedUncertain,
}
#[derive(Clone, Copy)]
enum ObservationPhase {
    Idle,
    Queued(Point),
    Issued(Point),
    Pending(Point),
    Failed {
        point: Point,
        native: NativeRetention,
    },
}
struct Observation {
    // Every queued/pending point shares this preallocated stable frame. Moving
    // a phase never relocates the allocation referenced by the native module.
    frame: Box<Frame>,
    phase: ObservationPhase,
}
impl Observation {
    fn point(&self) -> Option<Point> {
        match self.phase {
            ObservationPhase::Idle => None,
            ObservationPhase::Queued(point)
            | ObservationPhase::Issued(point)
            | ObservationPhase::Pending(point)
            | ObservationPhase::Failed { point, .. } => Some(point),
        }
    }
    fn pending(&self) -> bool {
        matches!(
            self.phase,
            ObservationPhase::Issued(_)
                | ObservationPhase::Pending(_)
                | ObservationPhase::Failed {
                    native: NativeRetention::ExecutionIncomplete,
                    ..
                }
        )
    }
    fn retains_native_memory(&self) -> bool {
        self.pending()
            || matches!(
                self.phase,
                ObservationPhase::Failed {
                    native: NativeRetention::ReturnedUncertain,
                    ..
                }
            )
    }
    fn issued(&mut self) {
        let point = self.point().expect("queued validation before dispatch");
        self.phase = ObservationPhase::Issued(point);
    }
    // A returned anomaly retains its graph but does not authorize another
    // AsyncComplete. Explicit Close/Finalize can still recover this owner.
    fn quarantine_return(&mut self) {
        let point = self.point().expect("active validation before return");
        self.phase = ObservationPhase::Failed {
            point,
            native: NativeRetention::ReturnedUncertain,
        };
    }
    fn failed(&self) -> bool {
        matches!(self.phase, ObservationPhase::Failed { .. })
    }
    fn submitted(&mut self) {
        let point = self.point().expect("queued validation before dispatch");
        self.phase = ObservationPhase::Pending(point);
    }
    fn released(&mut self) {
        self.phase = match self.phase {
            ObservationPhase::Issued(point) | ObservationPhase::Pending(point) => {
                ObservationPhase::Queued(point)
            }
            ObservationPhase::Failed { point, .. } => ObservationPhase::Failed {
                point,
                native: NativeRetention::Released,
            },
            phase => phase,
        };
    }
    fn fail(&mut self) {
        let point = self.point().expect("active validation before failure");
        let native = match self.phase {
            ObservationPhase::Failed { native, .. } => native,
            ObservationPhase::Issued(_) | ObservationPhase::Pending(_) => {
                NativeRetention::ExecutionIncomplete
            }
            ObservationPhase::Idle | ObservationPhase::Queued(_) => NativeRetention::Released,
        };
        self.phase = ObservationPhase::Failed { point, native };
    }
}
enum ReportOwner {
    Available(ValidationReport),
    Consumed,
}
impl ReportOwner {
    fn as_ref(&self) -> Option<&ValidationReport> {
        match self {
            Self::Available(report) => Some(report),
            Self::Consumed => None,
        }
    }
    fn as_mut(&mut self) -> Option<&mut ValidationReport> {
        match self {
            Self::Available(report) => Some(report),
            Self::Consumed => None,
        }
    }
    fn take(&mut self) -> Option<ValidationReport> {
        match std::mem::replace(self, Self::Consumed) {
            Self::Available(report) => Some(report),
            Self::Consumed => None,
        }
    }
}
pub(super) struct Capture {
    report: ReportOwner,
    observation: Observation,
    maximum: usize,
    return_diagnostic: Option<crate::error::CompletionStorage>,
    _credit: Credit,
}
/// Unpublished report storage. No native pointer or observation is available
/// until the complete containing graph has admitted its actual capacity.
pub(super) struct CaptureStorage {
    report: ReportStorage,
}
impl CaptureStorage {
    pub(super) fn allocate(maximum: usize) -> Result<Self> {
        Capture::allocation_bytes(maximum)?;
        Ok(Self {
            report: ReportStorage::allocate(maximum)?,
        })
    }
    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        self.report
            .allocated_bytes()?
            .checked_add(Capture::control_bytes())
            .ok_or(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ValidationReportCapacityAccounting,
            )))
    }
    pub(super) fn bind(self, prepaid: &mut Credit) -> Result<Capture> {
        // The report's credit moves with its eventual result. The stable native
        // frame belongs to Capture and is independent of report vector growth.
        let prepared = self.report.bind(prepaid)?;
        let fixed = prepaid.split(Capture::control_bytes())?;
        let mut name = [0; 32];
        name[.."C_GetSessionValidationFlags".len()].copy_from_slice(b"C_GetSessionValidationFlags");
        Ok(Capture {
            report: ReportOwner::Available(prepared.report),
            observation: Observation {
                frame: Box::new(Frame {
                    flags: 0,
                    completion: crate::native::output::async_data(),
                    name,
                }),
                phase: ObservationPhase::Idle,
            },
            maximum: prepared.maximum,
            return_diagnostic: Some(crate::error::CompletionStorage::allocate()?),
            _credit: fixed,
        })
    }
}

impl Capture {
    pub(super) fn allocation_bytes(maximum: usize) -> Result<usize> {
        ReportStorage::allocation_bytes(maximum)?
            .checked_add(Self::control_bytes())
            .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::ValidationReportLength,
            )))
    }
    fn control_bytes() -> usize {
        std::mem::size_of::<Self>()
            + std::mem::size_of::<Frame>()
            + crate::error::CompletionStorage::allocation_bytes()
    }
    pub(super) fn new(budget: &Arc<Budget>, maximum: usize) -> Result<Self> {
        let mut required = Self::allocation_bytes(maximum)?;
        loop {
            let mut prepaid = budget.reserve(required)?;
            let storage = CaptureStorage::allocate(maximum)?;
            let actual = storage.allocated_bytes()?;
            if actual > required {
                drop(storage);
                drop(prepaid);
                required = actual;
                continue;
            }
            prepaid.release(required - actual);
            return storage.bind(&mut prepaid);
        }
    }

    pub(super) fn snapshot_capacity(&self) -> Result<usize> {
        if self.waiting() || self.observation.failed() {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ValidationIncomplete,
            )));
        }
        self.report
            .as_ref()
            .ok_or(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ValidationAlreadyPublished,
            )))?;
        Ok(self.maximum)
    }
    pub(super) fn copy_snapshot_from(&mut self, source: &Self) -> Result<()> {
        if self.maximum != source.snapshot_capacity()? || self.waiting() {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ValidationSnapshotShapeChanged,
            )));
        }
        let source = source.report.as_ref().expect("validated source report");
        let target = self.report.as_mut().ok_or(Error::Rejected(
            crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ValidationAlreadyPublished,
            ),
        ))?;
        if source.observations.len() > target.observations.capacity() {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ValidationSnapshotCapacityChanged,
            )));
        }
        target.observations.clear();
        target.observations.extend_from_slice(&source.observations);
        Ok(())
    }
    /// Encode only completed observations; never inspect a pending native frame.
    pub(super) fn write_checkpoint(
        value: Option<&Self>,
        writer: &mut record::Writer<'_>,
        limits: record::Limits,
    ) -> Result<()> {
        let value = value
            .map(|capture| {
                if capture.waiting()
                    || capture.observation.pending()
                    || capture.observation.failed()
                {
                    return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                        crate::OperationOwnershipRejection::ValidationIncomplete,
                    )));
                }
                let report = capture.report.as_ref().ok_or(Error::Rejected(
                    crate::RejectionReason::OperationOwnership(
                        crate::OperationOwnershipRejection::ValidationAlreadyPublished,
                    ),
                ))?;
                Ok((capture.maximum, report.observations.as_slice()))
            })
            .transpose()?;
        record::ValidationRecord::write(writer, value, limits)
    }
    /// Pure reconstruction after structural decoding, without measuring again.
    /// The enclosing record still has to validate operation/phase correlation.
    pub(super) fn from_checkpoint(
        budget: &Arc<Budget>,
        record: &record::ValidationRecord<'_>,
    ) -> Result<Self> {
        let mut capture = Self::new(budget, record.maximum())?;
        capture.restore_record(record)?;
        Ok(capture)
    }
    pub(super) fn restore_record(&mut self, record: &record::ValidationRecord<'_>) -> Result<()> {
        let report = self.report.as_mut().ok_or(Error::Rejected(
            crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ValidationAlreadyPublished,
            ),
        ))?;
        if self.maximum != record.maximum()
            || !report.observations.is_empty()
            || self.observation.point().is_some()
        {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ValidationReconstructionShape,
            )));
        }
        for observation in record.iter() {
            if report.observations.len() == self.maximum {
                return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::ValidationReportLength,
                )));
            }
            report.observations.push(observation?);
        }
        Ok(())
    }
    pub(super) fn queue(&mut self, point: Point) -> Result<()> {
        if self.observation.point().is_some()
            || self.observation.failed()
            || self
                .report
                .as_ref()
                .map_or(true, |r| r.observations.len() >= self.maximum)
        {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ValidationObservationSequence,
            )));
        }
        self.observation.phase = ObservationPhase::Queued(point);
        Ok(())
    }
    pub(super) fn terminal_prefix(
        &self,
        function: &str,
    ) -> Result<(usize, &[ValidationObservation])> {
        if self.observation.failed()
            || !self
                .observation
                .point()
                .is_some_and(|p| p.function == function && p.message_index.is_none())
        {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::TerminalValidationAssociation,
            )));
        }
        let report = self.report.as_ref().ok_or(Error::Rejected(
            crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ValidationAlreadyPublished,
            ),
        ))?;
        Ok((self.maximum, &report.observations))
    }
    pub(super) fn restore_terminal(&mut self, function: &'static str) -> Result<()> {
        self.queue(Point {
            function,
            message_index: None,
        })?;
        self.observation.submitted();
        Ok(())
    }
    pub(super) fn detached_release(&mut self) {
        self.observation.released();
    }
    pub(super) fn waiting(&self) -> bool {
        self.observation.point().is_some()
    }
    pub(super) fn pending(&self) -> bool {
        self.observation.pending()
    }
    pub(super) fn retains_native_memory(&self) -> bool {
        self.observation.retains_native_memory()
    }
    /// A message-indexed observation can detach only at the last message. Earlier
    /// indices are deferred. This checks metadata, not native output or transfer.
    pub(super) fn check_detachment(&self, message_count: usize) -> Result<()> {
        if let Some(index) = self
            .observation
            .point()
            .and_then(|point| point.message_index)
        {
            if index >= message_count {
                return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::ValidationMessageIndex,
                )));
            }
            if index < message_count - 1 {
                return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::IntermediateValidationDetachmentDeferred,
                )));
            }
        }
        Ok(()) // Other admission gates still apply, including terminal adapters.
    }
    pub(super) fn take(&mut self) -> Result<ValidationReport> {
        if self.waiting() || self.observation.failed() {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ValidationIncomplete,
            )));
        }
        self.report
            .take()
            .ok_or(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ValidationAlreadyPublished,
            )))
    }
    /// Local publication may reuse only a fully collected report. A returned
    /// anomaly or a pending observation is not a publication certificate.
    pub(super) fn publication_ready(&self) -> bool {
        !self.waiting() && !self.observation.failed() && self.report.as_ref().is_some()
    }
    pub(super) fn first(&self) -> Result<SessionValidation> {
        self.report
            .as_ref()
            .and_then(|r| r.observations.first())
            .map(|v| v.validation)
            .ok_or(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ValidationObservationAbsent,
            )))
    }
    fn complete(&mut self, value: SessionValidation) -> Result<()> {
        let point = self.observation.point().ok_or(Error::Rejected(
            crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ValidationPointAbsent,
            ),
        ))?;
        let report = self.report.as_mut().ok_or(Error::Rejected(
            crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ValidationAlreadyPublished,
            ),
        ))?;
        if report.observations.len() >= self.maximum {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ValidationReportLimit,
            )));
        }
        report.observations.push(ValidationObservation {
            function: point.function,
            message_index: point.message_index,
            validation: value,
        });
        self.observation.phase = ObservationPhase::Idle;
        Ok(())
    }
    pub(super) fn joined_capacity(&self) -> Result<Option<usize>> {
        if !self.observation.pending()
            || self.observation.failed()
            || self.observation.point().is_none()
        {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ValidationControlNotPending,
            )));
        }
        Ok(Some(std::mem::size_of::<CK_FLAGS>()))
    }
    pub(super) fn accept_joined(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        result: asynchronous::JoinedResult,
    ) -> Result<()> {
        crate::native_return::protocol::PendingInspection::forwarded(result.observed)
            .inspect(|| Ok(()))
            .resolve(|_, cause| cause)?;
        // JoinedCall already notified native context. Preserve this observer's
        // separate local poison flag without notifying the same context twice.
        if read_failure_scope(result.return_value) != crate::native_return::FailureScope::None {
            entry.poisoned.store(true, Ordering::Release);
        }
        self.joined_capacity()?;
        let (rv, flags) = match result.project_flags() {
            Ok(result) => result,
            Err(error) => {
                // A rejected joined projection cannot discharge the original
                // pending observation. Keep its execution proof outstanding.
                self.observation.fail();
                s.native.mark_uncertain();
                return Err(error);
            }
        };
        if !crate::native_return::async_memory_returned(rv as u64) {
            self.observation.fail();
            s.native.mark_uncertain();
            return self.finish_terminal(rv);
        }
        if let Some(flags) = flags {
            self.observation.frame.flags = flags;
        }
        self.observation.released();
        self.finish_terminal(rv)
    }
    pub(super) fn drive(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        observe: bool,
        remaining: &mut usize,
    ) -> Result<()> {
        if self.observation.failed() {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ValidationFailed,
            )));
        }
        if !self.waiting() {
            return Ok(());
        }
        let call = match s.native.asynchronous.and_then(|f| f.validation) {
            Some(call) => call,
            None => return self.complete(SessionValidation::Unavailable),
        };
        if self.observation.pending() && !observe || !spend(remaining) {
            return Ok(());
        }
        let completing = self.observation.pending();
        let rv = if completing {
            let complete =
                s.native
                    .asynchronous
                    .and_then(|f| f.complete)
                    .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                        crate::SessionLifecycleRejection::CAsyncCompleteUnavailable,
                    )))?;
            s.native.record("C_AsyncComplete")?;
            self.observation.issued();
            // SAFETY: fixed output and completion descriptor remain owned even
            // if a separate cancellation completed while this query was pending.
            unsafe {
                complete(
                    entry.handle,
                    self.observation.frame.name.as_mut_ptr(),
                    &mut self.observation.frame.completion,
                )
            }
        } else {
            s.native.record("C_GetSessionValidationFlags")?;
            self.observation.issued();
            // SAFETY: session remains reserved; this stable fixed output was
            // allocated before Init and no intervening operation can enter it.
            unsafe {
                call(
                    entry.handle,
                    CKS_LAST_VALIDATION_OK as _,
                    &mut self.observation.frame.flags,
                )
            }
        };
        use crate::native_return::protocol::PendingInspection;
        let observe_context = |_| Self::observe_context(s, entry, rv);
        let pending = if completing {
            s.native.observe_async_return(rv);
            PendingInspection::completed("C_GetSessionValidationFlags", rv, observe_context)
        } else {
            PendingInspection::returned("C_GetSessionValidationFlags", rv, observe_context)
        };
        let result = pending
            .inspect(|| {
                // Fixed flags stay at their original address. pValue is not used
                // to replace that allocation or interpreted as the flags scalar.
                if completing && self.observation.frame.completion.ulVersion != 0 {
                    return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                        crate::OperationOwnershipRejection::ValidationAsynchronousVersion,
                    )));
                }
                Ok(())
            })
            .resolve(|result, cause| {
                s.native.mark_uncertain();
                self.observation.fail();
                if result.code() == CKR_OK {
                    cause
                } else {
                    self.return_diagnostic
                        .take()
                        .expect("one terminal validation boundary failure")
                        .bind(result.function())
                        .boundary_failure(result.code(), cause)
                }
            })?;
        if rv == CKR_PENDING {
            self.observation.submitted();
            if entry.mode != AdvancedSessionMode::Asynchronous {
                s.native.mark_uncertain();
                return Err(Error::Native {
                    function: "C_GetSessionValidationFlags",
                    code: rv as u64,
                    may_have_effect: true,
                });
            }
            return Ok(());
        }
        if !result.memory_returned() {
            // Do not inspect flags or CK_ASYNC_DATA on GENERAL_ERROR. The
            // module may retain both the original output and completion frame.
            if completing {
                // The completion query returned, but did not establish that
                // the independently pending observation has stopped running.
                self.observation.fail();
            } else {
                self.observation.quarantine_return();
            }
            s.native.mark_uncertain();
            return self.finish_terminal(rv);
        }
        self.observation.released();
        self.finish_terminal(rv)
    }
    fn observe_context(s: &State, entry: &SessionEntry, rv: CK_RV) {
        if rv == CKR_PENDING {
            return;
        }
        let scope = read_failure_scope(rv);
        if scope != crate::native_return::FailureScope::None {
            entry.poisoned.store(true, Ordering::Release);
            s.apply_session_failure(entry, rv, scope);
        }
    }

    fn finish_terminal(&mut self, rv: CK_RV) -> Result<()> {
        if rv != CKR_OK {
            self.observation.fail();
            return check(
                rv,
                "C_GetSessionValidationFlags",
                crate::native_return::effect_uncertain(rv),
            );
        }
        self.complete(SessionValidation::Reported(
            self.observation.frame.flags as u64,
        ))
    }
}
impl OperationTicket {
    /// Available only when this ticket published its terminal result. Pending,
    /// rejected or cancelled operations never publish an attestation here.
    pub fn validation_report(&self) -> Option<&ValidationReport> {
        self.validation_report.as_ref()
    }
}
impl AdvancedSession {
    /// Select correlated observation for supported cryptographic ticket owners
    /// while idle: digest, signature/MAC, cipher, GCM, recover, dual and messages.
    /// This does not change native capabilities or interpret the returned flags.
    ///
    /// The report is obtained from OperationTicket::validation_report after its
    /// terminal result. The synchronous verify_signature_native and
    /// verify_signature_native_mac helpers also apply this mode and return their
    /// report explicitly. Their corresponding Session methods do not.
    ///
    /// Plain synchronous facades delegating to Session (including sign_native,
    /// verify_native, compute_native_mac, verify_native_mac, AES/RSA ciphers,
    /// Recover, OTP, CMS/KIP, execute_extension and execute_native_message)
    /// preserve their simple results and do not apply this capture mode. Use
    /// validation_flags for a separate native observation, or the corresponding
    /// advanced operation when an attached report is required. A separate read
    /// does not itself establish correlation with a preceding operation.
    /// Explicit validation reads and digest_with_validation are independent of
    /// this setting. No cryptographic result becomes a certification claim.
    pub fn set_validation_capture(&mut self, mode: ValidationCaptureMode) -> Result<()> {
        {
            let _access = self.session.advanced_access()?;
            if self
                .session
                .entry
                .advanced_operation
                .load(Ordering::Acquire)
                != 0
            {
                return Err(Error::Busy(crate::BusyReason::OperationOwnership(
                    crate::OperationOwnershipBusy::AdvancedOperation,
                )));
            }
        }
        self.validation_capture = mode;
        Ok(())
    }
    pub(super) fn validation_allocation_bytes(
        &self,
        maximum: usize,
        explicit: bool,
    ) -> Result<usize> {
        if explicit || self.validation_capture == ValidationCaptureMode::Capture {
            Capture::allocation_bytes(maximum)
        } else {
            Ok(0)
        }
    }
}

impl crate::symmetric::memory::RetainedStorage for Capture {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        // The stable scalar observation frame is paid by the capture credit.
        retained.add_credit(&self._credit)?;
        match &self.report {
            ReportOwner::Available(report) => retained.add_credit(&report._credit),
            ReportOwner::Consumed => Ok(()),
        }
    }
}
