// SPDX-License-Identifier: Apache-2.0
//! Explicit recovery capture and fresh decryption; no archive cryptography or fallback.
use super::aead_parameters::CipherKind;
use super::gcm::MessageKey;
use super::{
    preparation, reconstruction, record, validation, AdvancedSession,
    CallerAssertedAuthenticatedRecord, Operation, OperationBody, OperationTicket, RecordLimits,
    StateProvenance, ValidationCaptureMode, ValidationReport,
};
use crate::symmetric::memory::{Budget, Buffer, Credit};
use crate::{Error, Result};
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[doc = include_str!("../../docs/api/advanced/recovery/GcmRecoveryRecord.md")]
pub struct GcmRecoveryRecord {
    bytes: Buffer,
    limits: record::Limits,
    budget: Arc<Budget>,
    _credit: Credit,
}
impl GcmRecoveryRecord {
    /// Explicit sensitive export to the authorized persistence service only.
    /// Consumer copies are not erased by this library. Never publish these
    /// completed prefix results as a completed business batch.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
    /// Exact historical observations of the captured process, if requested.
    /// Earlier carried messages belong to prior records; no flags are invented.
    /// This allocation is bounded and makes no native validation query.
    pub fn historical_validation(&self) -> Result<Option<ValidationReport>> {
        let r = record::RecoveryManifest::read(self.as_bytes(), self.limits)?;
        r.validation
            .as_ref()
            .map(|v| validation::Capture::from_checkpoint(&self.budget, v)?.take())
            .transpose()
    }
}
/// Sensitive recovery CCM record; possession does not authenticate its persistence
/// envelope or authorize replay. Completed plaintext prefixes remain private.
pub struct CcmRecoveryRecord(GcmRecoveryRecord);
impl CcmRecoveryRecord {
    /// Sensitive export for the authorized persistence service; no replay authority.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
    /// Historical validation observations, with no fresh native query.
    pub fn historical_validation(&self) -> Result<Option<ValidationReport>> {
        self.0.historical_validation()
    }
}
/// Sensitive recovery record for ChaCha/Salsa-Poly1305 decryption.
/// Export does not authenticate persistence or authorize replay. Completed
/// plaintext prefixes must remain private to the authorized recovery service.
pub struct StreamAeadRecoveryRecord(GcmRecoveryRecord);
impl StreamAeadRecoveryRecord {
    /// Sensitive export; caller-made copies are not erased by this owner.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
    /// Historical observations only; no native validation query is made.
    pub fn historical_validation(&self) -> Result<Option<ValidationReport>> {
        self.0.historical_validation()
    }
}
impl AdvancedSession {
    /// Capture inputs and completed authenticated prefixes without exporting
    /// pending output or opaque native state. The family must match the ticket.
    pub fn capture_stream_aead_recovery(
        &self,
        ticket: &OperationTicket,
        limits: RecordLimits,
        algorithm: crate::StreamAeadAlgorithm,
    ) -> Result<StreamAeadRecoveryRecord> {
        self.capture_aead_recovery(ticket, limits, CipherKind::from_stream(algorithm))
            .map(StreamAeadRecoveryRecord)
    }
    /// Prepare fresh decryption from an explicitly authorized authenticated
    /// record. The caller establishes key continuity and old-worker exclusion;
    /// native identity checks alone cannot establish either guarantee.
    pub fn start_stream_aead_recovery(
        &self,
        record: CallerAssertedAuthenticatedRecord,
        key: &crate::ManagedObjectRef,
        algorithm: crate::StreamAeadAlgorithm,
    ) -> Result<OperationTicket> {
        self.start_aead_recovery(
            record,
            MessageKey::Native(key),
            CipherKind::from_stream(algorithm),
        )
    }
    /// Capture recovery inputs and authenticated prefix without pausing or cancelling
    /// native work. No pending output or opaque native state is exported.
    /// A pending validation/control must first reach a coherent boundary.
    pub fn capture_gcm_recovery(
        &self,
        ticket: &OperationTicket,
        limits: RecordLimits,
    ) -> Result<GcmRecoveryRecord> {
        self.capture_aead_recovery(ticket, limits, CipherKind::Gcm)
    }
    /// Capture CCM recovery inputs and the completed authenticated prefix under the
    /// same ownership and persistence contract as GCM, without native replay.
    pub fn capture_ccm_recovery(
        &self,
        ticket: &OperationTicket,
        limits: RecordLimits,
    ) -> Result<CcmRecoveryRecord> {
        self.capture_aead_recovery(ticket, limits, CipherKind::Ccm)
            .map(CcmRecoveryRecord)
    }
    fn capture_aead_recovery(
        &self,
        ticket: &OperationTicket,
        limits: RecordLimits,
        kind: CipherKind,
    ) -> Result<GcmRecoveryRecord> {
        if ticket.id == 0
            || ticket.uid != self.session.uid
            || !Arc::ptr_eq(&ticket.owner, &self.session.inner)
        {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ForeignOrConsumedRecoveryTicket,
            )));
        }
        let limits = limits.checked()?;
        let budget = &self.session.inner.symmetric_budget;
        let mut diagnostics = None;
        let (bytes, credit) = super::record_preparation::copy(
            &self.session,
            ticket,
            record::Kind::GcmRecoveryManifest,
            limits,
            std::mem::size_of::<GcmRecoveryRecord>(),
            &mut diagnostics,
            |op, w| {
                if op.cancellation.is_withdrawn()
                    || op.continuation_status.is_frozen()
                    || op.cancel.is_submitted()
                    || op.state_io().is_some()
                    || op.detachment().is_some()
                    || op.rejoin().is_some()
                    || op.joined.is_some()
                {
                    return Err(Error::Busy(crate::BusyReason::OperationRecovery(
                        crate::OperationRecoveryBusy::RecoveryControlInProgress,
                    )));
                }
                let OperationBody::AeadMessages(body) = &op.body else {
                    return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::RecoveryRequiresAeadMessageDecryption,
                    )));
                };
                if body.cipher_kind() != kind {
                    return Err(Error::Rejected(
                        crate::RejectionReason::OperationRecovery(crate::OperationRecoveryRejection::RecoveryMechanismDoesNotMatchRequestedApi),
                    ));
                }
                body.check_rejoin_key(&self.session.entry)?;
                let origin =
                    record::RecoveryOrigin::new(&self.session.inner, &self.session.snapshot);
                origin.write(w)?;
                w.u32(u32::try_from(body.carried_messages()).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::OperationRecovery(
                        crate::OperationRecoveryRejection::RecoveryPrefixWidth,
                    ))
                })?)?;
                w.record_bytes(record::Kind::GcmRecovery, limits, |w| {
                    body.write_recovery_section(budget, w, limits)
                })?;
                validation::Capture::write_checkpoint(op.validation.as_ref(), w, limits)
            },
        )?;
        record::RecoveryManifest::read(bytes.as_slice(), limits)?;
        Ok(GcmRecoveryRecord {
            bytes,
            limits,
            budget: budget.clone(),
            _credit: credit,
        })
    }
    /// Consume an explicitly authorized imported recovery record and prepare a fresh
    /// decryption in an idle destination. No native call occurs until poll.
    /// The record is consumed on refusal as well; no retry or fallback occurs.
    ///
    /// A native identity match is only a consistency check. The service assertion
    /// above must establish actual key continuity and old-worker exclusion.
    /// Newly requested validation reports cover only this fresh execution;
    /// historical observations remain in the protected source record.
    pub fn start_gcm_recovery(
        &self,
        record: CallerAssertedAuthenticatedRecord,
        key: &crate::SymmetricKey,
    ) -> Result<OperationTicket> {
        self.start_aead_recovery(record, MessageKey::Aes(key), CipherKind::Gcm)
    }
    /// Start an explicitly authorized fresh CCM decryption from a caller-asserted
    /// authenticated recovery record; the caller retains old-worker exclusion duties.
    pub fn start_ccm_recovery(
        &self,
        record: CallerAssertedAuthenticatedRecord,
        key: &crate::SymmetricKey,
    ) -> Result<OperationTicket> {
        self.start_aead_recovery(record, MessageKey::Aes(key), CipherKind::Ccm)
    }
    fn start_aead_recovery(
        &self,
        record: CallerAssertedAuthenticatedRecord,
        key: MessageKey<'_>,
        kind: CipherKind,
    ) -> Result<OperationTicket> {
        let r = record::RecoveryManifest::read(record.bytes.as_slice(), record.limits)?;
        if r.section.mechanism != kind.mechanism() as u64 {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecovery(
                crate::OperationRecoveryRejection::RecoveryMechanismDoesNotMatchRequestedApi,
            )));
        }
        r.origin.check_token(&self.session.snapshot)?;
        let route = r
            .section
            .messages
            .iter()
            .next()
            .ok_or(Error::Rejected(crate::RejectionReason::OperationRecovery(
                crate::OperationRecoveryRejection::RecoveryEmptyBatch,
            )))??
            .route;
        let expected_key = r.section.keys.cipher.ok_or(Error::Rejected(
            crate::RejectionReason::OperationRecovery(
                crate::OperationRecoveryRejection::RecoveryCipherKeyAbsent,
            ),
        ))?;
        let progress = self
            .session
            .recovery_preflight(|state| {
                super::gcm::check_message_key(state, key, kind, true, route)
            })?
            .retaining(record.retained_bytes(&self.session.inner.symmetric_budget)?)?;
        let readers = super::keys::KeyReaders::prepare_retaining_at_epoch(
            &self.session,
            [Some(match key {
                MessageKey::Aes(key) => &key.managed,
                MessageKey::Native(key) => key,
            })],
            self.session.snapshot.authentication_stamp(),
            &progress,
        )?;
        let ((prepared, cancel, validation), s, mut prepared_readers) =
            readers.prepare_with(&self.session, &progress, || {
                let recipe = reconstruction::Recipe::aead_recovery(
                    &r.section,
                    self.session.inner.crypto_options.limits,
                    self.validation_capture == ValidationCaptureMode::Capture,
                )?;
                let resources = reconstruction::resources::Resources::prepare(
                    &self.session,
                    &progress,
                    recipe,
                    None,
                    None,
                    preparation::Shell::allocation_bytes(),
                )?;
                let mut metadata = resources.metadata;
                let cancel = preparation::Shell::from_prepaid(&mut metadata)?;
                let (prepared, validation) = resources.continuation.into_aead_recovery()?;
                Ok((prepared, cancel, validation))
            })?;
        if self
            .session
            .entry
            .advanced_operation
            .load(Ordering::Acquire)
            != 0
        {
            return Err(Error::Busy(crate::BusyReason::CombinedOperations(
                crate::CombinedOperationsBusy::RecoveryDestinationActive,
            )));
        }
        r.origin.check_token(&self.session.snapshot)?;
        let lease = self.aead_message_key(&s, key, kind, true, route, &mut prepared_readers)?;
        lease.check_checkpoint(expected_key, r.section.profile, 0)?;
        let body = prepared.bind(lease);
        let (token, cancel) = cancel.bind(&s.lease_admission()?)?;
        let mut operation = Operation::new(OperationBody::AeadMessages(body), token, cancel)
            .with_validation(validation);
        operation.provenance = Some(StateProvenance::Imported);
        let (id, _) = s.operations.install(&self.session.entry, operation)?;
        Ok(OperationTicket {
            owner: self.session.inner.clone(),
            uid: self.session.uid,
            id,
            validation_report: None,
            state_provenance: Some(StateProvenance::Imported),
        })
    }
}
