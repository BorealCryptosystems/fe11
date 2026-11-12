// SPDX-License-Identifier: Apache-2.0
//! Start signature and verification message sequences with PSS or MAC parameters.
//! The public facade transfers the chosen message route to its operation owner.

use super::*;

impl AdvancedSession {
    /// Sign original messages with native combined RSA-PSS SHA256,
    /// MGF1-SHA256 and salt32. No software hashing or classical-sign fallback.
    pub fn sign_pss_sha256_messages(
        &self,
        key: &crate::SigningKey,
        messages: &[SignatureMessage<'_>],
        route: MessageRoute,
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        let bits = key.message_pss_bits(pss_profile())?;
        self.start_pss_messages(
            key.management_reference(),
            bits,
            pss_profile(),
            messages,
            None,
            route,
            limits,
        )
    }

    /// Verify every message with the same fixed PSS profile and native hash.
    /// Invalid rejects the complete batch; no successful prefix is published.
    pub fn verify_pss_sha256_messages(
        &self,
        key: &crate::VerificationKey,
        messages: &[SignatureMessage<'_>],
        expected: &[&[u8]],
        route: MessageRoute,
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        let bits = key.message_pss_bits(pss_profile())?;
        self.start_pss_messages(
            key.management_reference(),
            bits,
            pss_profile(),
            messages,
            Some(expected),
            route,
            limits,
        )
    }

    /// Sign original messages with the selected combined RSA-PSS mechanism.
    /// Message hash, MGF1 hash and salt length are independent; native refusal
    /// never selects another profile, hash route or message route.
    pub fn sign_pss_messages(
        &self,
        key: &crate::SigningKey,
        parameters: crate::RsaPssParameters,
        messages: &[SignatureMessage<'_>],
        route: MessageRoute,
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        let bits = key.message_pss_bits(parameters)?;
        self.start_pss_messages(
            key.management_reference(),
            bits,
            parameters,
            messages,
            None,
            route,
            limits,
        )
    }

    /// Verify a complete batch under the exact caller-selected PSS parameters.
    /// An invalid message prevents publication of a successful batch prefix.
    pub fn verify_pss_messages(
        &self,
        key: &crate::VerificationKey,
        parameters: crate::RsaPssParameters,
        messages: &[SignatureMessage<'_>],
        expected: &[&[u8]],
        route: MessageRoute,
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        let bits = key.message_pss_bits(parameters)?;
        self.start_pss_messages(
            key.management_reference(),
            bits,
            parameters,
            messages,
            Some(expected),
            route,
            limits,
        )
    }

    pub(super) fn start_pss_messages(
        &self,
        key: &crate::ManagedObjectRef,
        bits: usize,
        parameters: crate::RsaPssParameters,
        messages: &[SignatureMessage<'_>],
        expected: Option<&[&[u8]]>,
        route: MessageRoute,
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        // Declared before preparation/session guards so returned native buffers
        // are erased and their budget credit released only after possession.
        let mut retired_owner = None;
        let mut released = ReleasedInputs::default();
        validate_messages(
            messages,
            expected,
            limits,
            self.session.inner.crypto_options.limits,
        )?;
        let (prepared, cancel, validation, s, mut prepared_readers) = self.prepare_signatures(
            key,
            parameters.mechanism(crate::HashExecution::Pkcs11Combined)?,
            bits / 8 + usize::from(bits % 8 != 0),
            messages,
            expected,
            route,
            Some(parameters.checked()?),
        )?;
        let key = KeyLease::for_rsa_messages(
            &self.session,
            key,
            bits,
            expected.is_none(),
            &mut prepared_readers,
        )?;
        let result = self.install_signatures(
            &s.lease_admission()?,
            prepared.bind(key),
            cancel,
            validation,
            &mut released,
            &mut retired_owner,
        );
        drop(s);
        result
    }

    /// Sign a bounded batch using the selected native message route and a
    /// protected HMAC-SHA256/384/512 key admitted in this session.
    pub fn sign_mac_messages(
        &self,
        key: &SymmetricKey,
        messages: &[MacMessage<'_>],
        route: MessageRoute,
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        self.start_mac_messages(key, messages, None, route, limits)
    }

    /// Verify all messages. Invalid means at least one signature failed; no
    /// successful authentication is published for a partial batch. The native
    /// process is finalized after the first invalid signature, without retries.
    pub fn verify_mac_messages(
        &self,
        key: &SymmetricKey,
        messages: &[MacMessage<'_>],
        expected: &[&[u8]],
        route: MessageRoute,
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        self.start_mac_messages(key, messages, Some(expected), route, limits)
    }

    pub(super) fn start_mac_messages(
        &self,
        key: &SymmetricKey,
        messages: &[MacMessage<'_>],
        expected: Option<&[&[u8]]>,
        route: MessageRoute,
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        // Declared before preparation/session guards so returned native buffers
        // are erased and their budget credit released only after possession.
        let mut retired_owner = None;
        let mut released = ReleasedInputs::default();
        validate_messages(
            messages,
            expected,
            limits,
            self.session.inner.crypto_options.limits,
        )?;
        let output_length = key.algorithm.mac_length().ok_or(Error::Rejected(
            crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageHmacKeyRequired,
            ),
        ))?;
        let kind = key.algorithm.mechanism();
        let (prepared, cancel, validation, s, mut prepared_readers) = self.prepare_signatures(
            &key.managed,
            kind,
            output_length,
            messages,
            expected,
            route,
            None,
        )?;
        let key_lease = KeyLease::new(&self.session, key, &mut prepared_readers)?;
        let result = self.install_signatures(
            &s.lease_admission()?,
            prepared.bind(key_lease),
            cancel,
            validation,
            &mut released,
            &mut retired_owner,
        );
        drop(s);
        result
    }

    pub(super) fn check_signature_functions(
        state: &crate::module::State,
        verify: bool,
        route: MessageRoute,
    ) -> Result<()> {
        let f =
            state
                .native
                .messages
                .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::MessageInterfaceUnavailable,
                )))?;
        let available = if verify {
            f.verify_init.is_some()
                && f.verify_finish.is_some()
                && match route {
                    MessageRoute::Single => f.verify_message.is_some(),
                    MessageRoute::Multipart => f.verify_begin.is_some() && f.verify_next.is_some(),
                }
        } else {
            f.sign_init.is_some()
                && f.sign_finish.is_some()
                && match route {
                    MessageRoute::Single => f.sign_message.is_some(),
                    MessageRoute::Multipart => f.sign_begin.is_some() && f.sign_next.is_some(),
                }
        };
        if !available {
            return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageFunctionsUnavailable,
            )));
        }
        Ok(())
    }

    pub(super) fn prepare_signatures(
        &self,
        key: &crate::ManagedObjectRef,
        kind: CK_MECHANISM_TYPE,
        size: usize,
        messages: &[MacMessage<'_>],
        expected: Option<&[&[u8]]>,
        route: MessageRoute,
        pss: Option<CK_RSA_PKCS_PSS_PARAMS>,
    ) -> Result<(
        PreparedMac,
        preparation::Shell,
        Option<validation::Capture>,
        crate::session::SessionAccess<'_>,
        [Option<crate::registry::ReadPermit>; 1],
    )> {
        let maximum = messages.len().checked_add(1).ok_or(Error::Rejected(
            crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::ValidationReportLength,
            ),
        ))?;
        let progress = self.session.advanced_preflight(|state| {
            Self::check_signature_functions(state, expected.is_some(), route)
        })?;
        let validation_bytes = self.validation_allocation_bytes(maximum, false)?;
        let shape = snapshot::Shape::for_request(kind, size, messages, expected, route, pss)?;
        let key_readers = super::super::keys::KeyReaders::prepare(&self.session, [Some(key)])?;
        let mut total = shape
            .request_bytes()?
            .checked_add(preparation::Shell::allocation_bytes())
            .and_then(|n| n.checked_add(validation_bytes))
            .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::MessageOperationStorageSize,
            )))?;
        let ((body, cancel, validation), access, readers) =
            key_readers.prepare_with(&self.session, &progress, || loop {
                let mut prepaid =
                    preparation::reserve_new_with_progress(&self.session, total, &progress)?;
                let storage = shape.allocate_request(messages, expected)?;
                let validation = (validation_bytes != 0)
                    .then(|| validation::CaptureStorage::allocate(maximum))
                    .transpose()?;
                let validation_actual = validation
                    .as_ref()
                    .map(validation::CaptureStorage::allocated_bytes)
                    .transpose()?
                    .unwrap_or(0);
                let actual = storage
                    .allocated_bytes()?
                    .checked_add(validation_actual)
                    .and_then(|n| n.checked_add(preparation::Shell::allocation_bytes()))
                    .ok_or(Error::Rejected(crate::RejectionReason::SignatureMessages(
                        crate::SignatureMessagesRejection::MessageOperationStorageSize,
                    )))?;
                if actual > total {
                    drop(validation);
                    drop(storage);
                    drop(prepaid);
                    total = actual;
                    continue;
                }
                prepaid.release(total - actual);
                let body = storage
                    .bind(&mut prepaid)?
                    .fill_request(messages, expected)?;
                let validation = validation
                    .map(|storage| storage.bind(&mut prepaid))
                    .transpose()?;
                let cancel = preparation::Shell::from_prepaid(&mut prepaid)?;
                return Ok((body, cancel, validation));
            })?;
        Ok((body, cancel, validation, access, readers))
    }

    pub(super) fn install_signatures(
        &self,
        admission: &crate::session::LeaseAdmission<'_, '_>,
        body: MacOperation,
        cancel: preparation::Shell,
        validation: Option<validation::Capture>,
        released: &mut ReleasedInputs,
        retired_owner: &mut Option<std::sync::Arc<super::super::ledger::OperationCell>>,
    ) -> Result<OperationTicket> {
        let s = admission.access();
        if !s.owns_session(&self.session) {
            return Err(Error::Rejected(crate::RejectionReason::SignatureMessages(
                crate::SignatureMessagesRejection::ForeignOperationLeaseAdmission,
            )));
        }
        Self::check_signature_functions(s, body.verify, body.route)?;
        let (lease, cancel) = cancel.bind(admission)?;
        let (id, operation) = s.operations.install(
            &self.session.entry,
            Operation::new(OperationBody::Messages(body), lease, cancel)
                .with_validation(validation),
        )?;
        let ticket = OperationTicket {
            owner: self.session.inner.clone(),
            uid: self.session.uid,
            id,
            validation_report: None,
            state_provenance: None,
        };
        // The starter root is declared before access and survives projection
        // of any error that retires this operation during the initial drive.
        *retired_owner = Some(operation.clone());
        let mut operation = operation.lock().map_err(|_| Error::Poisoned)?;
        let driven = drive(
            s,
            &self.session.entry,
            &mut operation,
            false,
            &mut self.pacing.budget(),
        );
        // This entry point drives before the first poll. Drain established-
        // return buffers now, before error retirement and before exposing the
        // ticket to another capacity preparation or continuation.
        assert!(released.is_empty(), "startup retirement owner is fresh");
        if let OperationBody::Messages(body) = &mut operation.body {
            *released = body.take_released_inputs();
        }
        if let Err(error) = driven {
            let (error, _) = operation.retire_terminal_error(s, &self.session.entry, error);
            return Err(error);
        }
        Ok(ticket)
    }
}
