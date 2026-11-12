// SPDX-License-Identifier: Apache-2.0
//! Explicit recovery restart of one unfinished dual GCM message.
use super::{
    authentication, check_dual_functions, output_bounds, preparation, reconstruction, record,
    validation, AdvancedSession, Authentication, CallerAssertedAuthenticatedRecord, DualOperation,
    DualStep, MessageRoute, Mode, OperationBody, OperationTicket, RecordLimits, SymmetricAlgorithm,
    SymmetricKey, ValidationCaptureMode, ValidationReport,
};
use crate::advanced::record::Family;
use crate::symmetric::memory::{Budget, Buffer, Credit};
use crate::{Error, Result};
use fe11_sys::CKM_AES_GCM;
use std::sync::Arc;
#[doc = include_str!("../../../docs/api/advanced/dual/recovery/DualRecoveryRecord.md")]
pub struct DualRecoveryRecord {
    bytes: Buffer,
    limits: record::Limits,
    budget: Arc<Budget>,
    _credit: Credit,
}
impl DualRecoveryRecord {
    /// Explicit export to the authorized persistence service. No authorization,
    /// encryption, erasure of consumer copies or source cancellation is implied.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
    /// Completed observations of the old execution; never newly measured flags.
    pub fn historical_validation(&self) -> Result<Option<ValidationReport>> {
        let r = record::DualRecovery::read(self.as_bytes(), self.limits)?;
        r.validation
            .as_ref()
            .map(|v| validation::Capture::from_checkpoint(&self.budget, v)?.take())
            .transpose()
    }
}
impl DualOperation {
    fn write_recovery(
        &self,
        _budget: &Arc<Budget>,
        w: &mut record::Writer<'_>,
        limits: record::Limits,
    ) -> Result<()> {
        use record::{Message, MessageState, Messages, NonceOrigin, Parameters};
        if !self.mode.decrypt()
            || !self.cipher.gcm()
            || !self.valid
            || matches!(self.step, DualStep::Done | DualStep::Failed)
            || self.output.is_none()
        {
            return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualRecoveryRequiresUnfinishedGcmDecryption,
            )));
        }
        let parts = self
            .layout
            .fragments(&self.inputs, MessageRoute::Multipart)?;
        let d = record::Descriptor {
            input: crate::advanced::input::InputState::closed(),
            family: if self.mode.mac() {
                Family::DecryptVerify
            } else {
                Family::DecryptDigest
            },
            profile: self
                .authentication
                .selection()
                .profile(self.cipher_key.checkpoint_profile()?)?,
            phase: record::Function::from_name(if self.mode.mac() {
                "C_VerifyInit"
            } else {
                "C_DigestInit"
            })?,
            mechanism: CKM_AES_GCM as u64,
            size: 0,
            active_flags: 0,
            validation_requested: false,
            digest_bits: None,
            cipher_options: None,
            carried_messages: 0,
        };
        d.write(w)?;
        record::KeyBindings {
            cipher: Some(self.cipher_key.checkpoint_key(record::KeyRole::Cipher)?),
            authentication: self
                .authentication
                .key()
                .map(|k| k.checkpoint_key(record::KeyRole::Authentication))
                .transpose()?,
        }
        .write(w)?;
        let (_, expected) = output_bounds(
            self.input_length,
            true,
            CKM_AES_GCM as u64,
            self.cipher.tag_bytes(),
        )?;
        let m = Message {
            route: MessageRoute::Multipart,
            params: Parameters {
                digest_output: None,
                cipher_extension: None,
                digest_extension: None,
                signature: None,
                digest_oid: None,
                message_init: None,
                counter_bits: None,
                iv_generator: Some(0),
                iv_fixed_bits: Some(0),
                iv_initial: Some(self.cipher.expected_iv.as_slice()),
                nonce: Some(self.cipher.expected_iv.as_slice()),
                aad: Some(self.cipher.aad.as_slice()),
                tag_bits: self
                    .cipher
                    .selection()
                    .expect("GCM recovery selection")
                    .tag_bits() as u32,
                hash: Some(self.authentication.selection().hash().mechanism_number()),
                mgf: None,
                salt: None,
            },
            origin: NonceOrigin::Provided,
            state: MessageState::Planned,
            fragments: parts,
            next_fragment: 0,
            produced: 0,
            expected,
            result: &[],
            tag_or_signature: if self.mode.mac() {
                Some(self.auth.as_slice())
            } else {
                None
            },
            residual_start: 0,
            residual_length: 0,
        };
        Messages::write(w, &[m], limits)
    }
}
impl AdvancedSession {
    /// Capture immutable inputs of an unfinished dual GCM decryption. Neither
    /// pending output nor opaque native state is read or exported. Capture does
    /// not stop the old executor or authorize another operation.
    pub fn capture_dual_gcm_recovery(
        &self,
        ticket: &OperationTicket,
        limits: RecordLimits,
    ) -> Result<DualRecoveryRecord> {
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
        let (bytes, credit) = super::super::record_preparation::copy(
            &self.session,
            ticket,
            record::Kind::DualRecovery,
            limits,
            std::mem::size_of::<DualRecoveryRecord>(),
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
                let OperationBody::Dual(body) = &op.body else {
                    return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                        crate::CombinedOperationsRejection::RecoveryRequiresDualGcmDecryption,
                    )));
                };
                body.check_keys(&self.session.entry)?;
                let origin =
                    record::RecoveryOrigin::new(&self.session.inner, &self.session.snapshot);
                origin.write(w)?;
                body.write_recovery(budget, w, limits)?;
                validation::Capture::write_checkpoint(op.validation.as_ref(), w, limits)
            },
        )?;
        record::DualRecovery::read(bytes.as_slice(), limits)?;
        Ok(DualRecoveryRecord {
            bytes,
            limits,
            budget: budget.clone(),
            _credit: credit,
        })
    }
    /// Consume a service-authorized record and prepare a new dual decryption in
    /// an idle destination. It repeats the unfinished message from identical
    /// inputs, not C_SetOperationState. No native dispatch occurs until poll.
    /// The assertion must cover manifest freshness, key generations and proven
    /// exclusion of the old executor. A timeout or lost connection is not proof.
    /// Refusal consumes the record without retry, fallback or business replay.
    pub fn start_dual_gcm_recovery(
        &self,
        record: CallerAssertedAuthenticatedRecord,
        key: &SymmetricKey,
        mac: Option<&SymmetricKey>,
    ) -> Result<OperationTicket> {
        let mut retired_owner = None;
        let r = record::DualRecovery::read(record.bytes.as_slice(), record.limits)?;
        r.origin.check_token(&self.session.snapshot)?;
        let message = r.messages.iter().next().ok_or(Error::Rejected(
            crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualRecoveryEmptyMessage,
            ),
        ))??;
        let mode = if r.descriptor.family == Family::DecryptVerify {
            Mode::DecryptVerify
        } else {
            Mode::DecryptDigest
        };
        if mode.mac() != mac.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualRecoveryKeyRoles,
            )));
        }
        let authentication = Authentication::from_record(r.descriptor, &message)?;
        if !matches!(
            key.algorithm,
            SymmetricAlgorithm::Aes128 | SymmetricAlgorithm::Aes192 | SymmetricAlgorithm::Aes256
        ) {
            return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualAesKeyRequired,
            )));
        }
        if let Some(mac) = mac {
            if Some(authentication::HmacAlgorithm::from_key(mac.algorithm)?) != authentication.mac()
            {
                return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::DualMacKeyAlgorithm,
                )));
            }
        }
        let progress = self
            .session
            .recovery_preflight(|state| check_dual_functions(state, mode))?
            .retaining(record.retained_bytes(&self.session.inner.symmetric_budget)?)?;
        let key_readers = super::super::keys::KeyReaders::prepare_retaining_at_epoch(
            &self.session,
            [Some(&key.managed), mac.map(|key| &*key.managed)],
            self.session.snapshot.authentication_stamp(),
            &progress,
        )?;
        let ((prepared, cancel, validation), access, mut prepared_readers) = key_readers
            .prepare_with(&self.session, &progress, || {
                let recipe = reconstruction::Recipe::dual_recovery(
                    r.descriptor,
                    &r.messages,
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
                let (prepared, validation) = resources.continuation.into_dual_recovery()?;
                Ok((prepared, cancel, validation))
            })?;
        self.install_prepared_dual(
            key,
            mac,
            prepared,
            cancel,
            validation,
            access,
            Some((authentication::cipher_profile(r.descriptor)?, r.keys)),
            &mut prepared_readers,
            &mut retired_owner,
        )
    }
}
