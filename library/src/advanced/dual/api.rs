// SPDX-License-Identifier: Apache-2.0
//! Start paired digest/cipher or signature/cipher operations.
//! Each facade carries the selected hash or MAC and both native operation roles.

use super::*;

impl AdvancedSession {
    /// Native SHA256 plus encryption; SHA256 is not an authentication tag.
    pub fn digest_encrypt(
        &self,
        key: &SymmetricKey,
        cipher: DualCipher<'_>,
        parts: &[&[u8]],
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        let mut retired_owner = None;
        self.start_dual(
            key,
            None,
            Mode::DigestEncrypt,
            cipher,
            parts,
            None,
            limits,
            &mut retired_owner,
        )
    }

    /// Decrypt and digest the complete plaintext, including native final residue.
    /// CBC output remains explicitly unauthenticated.
    pub fn decrypt_digest(
        &self,
        key: &SymmetricKey,
        cipher: DualCipher<'_>,
        parts: &[&[u8]],
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        let mut retired_owner = None;
        self.start_dual(
            key,
            None,
            Mode::DecryptDigest,
            cipher,
            parts,
            None,
            limits,
            &mut retired_owner,
        )
    }

    /// Native encryption plus HMAC-SHA256 of plaintext, using a distinct admitted key.
    /// The module decides support for the explicitly selected cipher/MAC pair.
    pub fn sign_encrypt(
        &self,
        key: &SymmetricKey,
        mac: &SymmetricKey,
        cipher: DualCipher<'_>,
        parts: &[&[u8]],
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        let mut retired_owner = None;
        self.start_dual(
            key,
            Some(mac),
            Mode::SignEncrypt,
            cipher,
            parts,
            None,
            limits,
            &mut retired_owner,
        )
    }

    /// Publish plaintext only after cipher completion and full HMAC-SHA256 verification.
    pub fn decrypt_verify(
        &self,
        key: &SymmetricKey,
        mac: &SymmetricKey,
        cipher: DualCipher<'_>,
        parts: &[&[u8]],
        expected: &[u8; 32],
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        let mut retired_owner = None;
        self.start_dual(
            key,
            Some(mac),
            Mode::DecryptVerify,
            cipher,
            parts,
            Some(expected),
            limits,
            &mut retired_owner,
        )
    }

    /// Encrypt and hash all plaintext with the selected native hash.
    /// Poll publishes DigestEncryptedWithAlgorithm; a digest is not a MAC.
    pub fn digest_encrypt_with_hash(
        &self,
        key: &SymmetricKey,
        hash: crate::HashAlgorithm,
        cipher: DualCipher<'_>,
        parts: &[&[u8]],
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        let mut retired_owner = None;
        self.prepare_dual_selected(
            key,
            None,
            Mode::DigestEncrypt,
            Authentication::Digest(hash),
            cipher,
            parts,
            None,
            limits,
            None,
            &mut retired_owner,
        )
    }

    /// Decrypt and hash all plaintext, including bytes returned by DecryptFinal.
    /// Poll publishes DigestDecryptedWithAlgorithm; CBC output remains unauthenticated.
    pub fn decrypt_digest_with_hash(
        &self,
        key: &SymmetricKey,
        hash: crate::HashAlgorithm,
        cipher: DualCipher<'_>,
        parts: &[&[u8]],
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        let mut retired_owner = None;
        self.prepare_dual_selected(
            key,
            None,
            Mode::DecryptDigest,
            Authentication::Digest(hash),
            cipher,
            parts,
            None,
            limits,
            None,
            &mut retired_owner,
        )
    }

    /// Encrypt and compute a full native HMAC using the supplied MAC key's algorithm.
    /// Supports typed HMAC-SHA256/384/512 keys; no other primitive is substituted.
    /// Poll publishes MacEncryptedWithAlgorithm. This is not a transport protocol.
    pub fn sign_encrypt_with_mac(
        &self,
        key: &SymmetricKey,
        mac: &SymmetricKey,
        cipher: DualCipher<'_>,
        parts: &[&[u8]],
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        let mut retired_owner = None;
        let authentication = Authentication::Hmac(HmacAlgorithm::from_key(mac.algorithm)?);
        self.prepare_dual_selected(
            key,
            Some(mac),
            Mode::SignEncrypt,
            authentication,
            cipher,
            parts,
            None,
            limits,
            None,
            &mut retired_owner,
        )
    }

    /// Decrypt and verify the full HMAC selected by the supplied MAC key.
    /// The expected MAC must have that algorithm's full length. Plaintext is
    /// published only after verification; invalid verification carries no bytes.
    pub fn decrypt_verify_with_mac(
        &self,
        key: &SymmetricKey,
        mac: &SymmetricKey,
        cipher: DualCipher<'_>,
        parts: &[&[u8]],
        expected: &[u8],
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        let mut retired_owner = None;
        let authentication = Authentication::Hmac(HmacAlgorithm::from_key(mac.algorithm)?);
        self.prepare_dual_selected(
            key,
            Some(mac),
            Mode::DecryptVerify,
            authentication,
            cipher,
            parts,
            Some(expected),
            limits,
            None,
            &mut retired_owner,
        )
    }

    pub(super) fn start_dual(
        &self,
        key: &SymmetricKey,
        mac: Option<&SymmetricKey>,
        mode: Mode,
        cipher: DualCipher<'_>,
        parts: &[&[u8]],
        expected: Option<&[u8; 32]>,
        limits: crate::InputLimits,
        retired_owner: &mut Option<std::sync::Arc<super::super::ledger::OperationCell>>,
    ) -> Result<OperationTicket> {
        self.prepare_dual(
            key,
            mac,
            mode,
            cipher,
            parts,
            expected,
            limits,
            None,
            retired_owner,
        )
    }

    pub(super) fn prepare_dual(
        &self,
        key: &SymmetricKey,
        mac: Option<&SymmetricKey>,
        mode: Mode,
        cipher: DualCipher<'_>,
        parts: &[&[u8]],
        expected: Option<&[u8; 32]>,
        limits: crate::InputLimits,
        recovery: Option<(u8, record::KeyBindings<'_>)>,
        retired_owner: &mut Option<std::sync::Arc<super::super::ledger::OperationCell>>,
    ) -> Result<OperationTicket> {
        self.prepare_dual_selected(
            key,
            mac,
            mode,
            Authentication::legacy(mode),
            cipher,
            parts,
            expected.map(|v| v.as_slice()),
            limits,
            recovery,
            retired_owner,
        )
    }

    pub(super) fn prepare_dual_selected(
        &self,
        key: &SymmetricKey,
        mac: Option<&SymmetricKey>,
        mode: Mode,
        authentication: Authentication,
        cipher: DualCipher<'_>,
        parts: &[&[u8]],
        expected: Option<&[u8]>,
        limits: crate::InputLimits,
        recovery: Option<(u8, record::KeyBindings<'_>)>,
        retired_owner: &mut Option<std::sync::Arc<super::super::ledger::OperationCell>>,
    ) -> Result<OperationTicket> {
        if mode.mac() != authentication.mac().is_some()
            || mode.mac() != mac.is_some()
            || (mode == Mode::DecryptVerify) != expected.is_some()
        {
            return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualAuthenticationRoles,
            )));
        }
        if expected.is_some_and(|value| value.len() != authentication.length()) {
            return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualFullMacLength,
            )));
        }
        let cipher_kind = cipher::mechanism(&cipher);
        let (tag_bytes, iv_bytes) = match &cipher {
            DualCipher::Gcm { nonce, aad } => {
                nonce.validate_gcm(aad.len())?;
                (nonce.tag_bytes()?, nonce.iv().len())
            }
            DualCipher::Ctr { counter_bits, .. } => {
                cipher::counter_width(*counter_bits)?;
                (0, 16)
            }
            DualCipher::Ecb => (0, 0),
            DualCipher::Cbc { .. }
            | DualCipher::CbcPad { .. }
            | DualCipher::Ofb { .. }
            | DualCipher::Cfb8 { .. }
            | DualCipher::Cfb64 { .. }
            | DualCipher::Cfb128 { .. } => (0, 16),
        };
        if !matches!(
            key.algorithm,
            SymmetricAlgorithm::Aes128 | SymmetricAlgorithm::Aes192 | SymmetricAlgorithm::Aes256
        ) {
            return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualAesKeyRequired,
            )));
        }
        limits.validate(self.session.inner.crypto_options.limits, parts)?;
        let input = parts.iter().try_fold(0usize, |n, p| {
            n.checked_add(p.len()).ok_or(Error::Rejected(
                crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::DualInputOverflow,
                ),
            ))
        })?;
        let aad = match &cipher {
            DualCipher::Gcm { aad, .. } => aad.len(),
            _ => 0,
        };
        bounds::ck_length(aad)?;
        if input
            .checked_add(aad)
            .and_then(|n| {
                n.checked_add(iv_bytes).and_then(|n| {
                    n.checked_add(if mode.mac() {
                        authentication.length()
                    } else {
                        0
                    })
                })
            })
            .map_or(true, |n| n > limits.maximum_total_bytes)
        {
            return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualContextCeiling,
            )));
        }
        output_bounds(input, mode.decrypt(), cipher_kind as u64, tag_bytes)?;
        if let Some(mac) = mac {
            if Some(HmacAlgorithm::from_key(mac.algorithm)?) != authentication.mac() {
                return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::DualMacKeyAlgorithm,
                )));
            }
        }
        let check_functions = |state: &crate::module::State| check_dual_functions(state, mode);
        let progress = self.session.advanced_preflight(&check_functions)?;
        let validation_bytes = self.validation_allocation_bytes(2, false)?;
        let shape =
            snapshot::Shape::for_request(mode, authentication, &cipher, parts, input, expected)?;
        let mut total = shape
            .allocation_bytes()
            .checked_add(preparation::Shell::allocation_bytes())
            .and_then(|n| n.checked_add(validation_bytes))
            .ok_or(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualOperationStorageSize,
            )))?;
        let key_readers = super::super::keys::KeyReaders::prepare(
            &self.session,
            [Some(&key.managed), mac.map(|key| &*key.managed)],
        )?;
        let ((prepared, cancel, validation), access, mut prepared_readers) = key_readers
            .prepare_with(&self.session, &progress, || loop {
                let mut prepaid =
                    preparation::reserve_new_with_progress(&self.session, total, &progress)?;
                let storage = shape.allocate_request(&cipher, parts, &mut prepaid)?;
                let validation = (validation_bytes != 0)
                    .then(|| validation::CaptureStorage::allocate(2))
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
                    .ok_or(Error::Rejected(crate::RejectionReason::CombinedOperations(
                        crate::CombinedOperationsRejection::DualOperationStorageSize,
                    )))?;
                if actual > total {
                    drop(validation);
                    drop(storage);
                    drop(prepaid);
                    total = actual;
                    continue;
                }
                prepaid.release(total - actual);
                let prepared = storage
                    .bind(&mut prepaid)?
                    .fill_request(&cipher, parts, expected)?;
                let validation = validation
                    .map(|storage| storage.bind(&mut prepaid))
                    .transpose()?;
                let cancel = preparation::Shell::from_prepaid(&mut prepaid)?;
                return Ok((prepared, cancel, validation));
            })?;
        self.install_prepared_dual(
            key,
            mac,
            prepared,
            cancel,
            validation,
            access,
            recovery,
            &mut prepared_readers,
            retired_owner,
        )
    }

    pub(super) fn install_prepared_dual(
        &self,
        key: &SymmetricKey,
        mac: Option<&SymmetricKey>,
        prepared: PreparedDual,
        cancel: preparation::Shell,
        validation: Option<validation::Capture>,
        s: crate::session::SessionAccess<'_>,
        recovery: Option<(u8, record::KeyBindings<'_>)>,
        permits: &mut [Option<crate::registry::ReadPermit>],
        retired_owner: &mut Option<std::sync::Arc<super::super::ledger::OperationCell>>,
    ) -> Result<OperationTicket> {
        let mode = prepared.mode;
        let authentication = prepared.authentication;
        if recovery.is_some()
            && self
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

        check_dual_functions(&s, mode)?;
        // Transfer the prepared permissions in handle order within this module/token.
        // Application IDs do not establish aliasing or key distinctness.
        let (cipher_key, mac_key) = if let Some(mac) = mac {
            if mac.managed.handle < key.managed.handle {
                let m = KeyLease::new(&self.session, mac, permits)?;
                (KeyLease::new(&self.session, key, permits)?, Some(m))
            } else {
                let c = KeyLease::new(&self.session, key, permits)?;
                (c, Some(KeyLease::new(&self.session, mac, permits)?))
            }
        } else {
            (KeyLease::new(&self.session, key, permits)?, None)
        };
        if let Some((profile, bindings)) = &recovery {
            cipher_key.check_checkpoint(
                bindings.cipher.ok_or(Error::Rejected(
                    crate::RejectionReason::CombinedOperations(
                        crate::CombinedOperationsRejection::DualRecoveryCipherKey,
                    ),
                ))?,
                *profile,
                0,
            )?;
            match (&mac_key, bindings.authentication) {
                (Some(k), Some(b)) => k.check_checkpoint(
                    b,
                    authentication
                        .mac()
                        .ok_or(Error::Rejected(crate::RejectionReason::CombinedOperations(
                            crate::CombinedOperationsRejection::DualMacSelection,
                        )))?
                        .profile(),
                    0,
                )?,
                (None, None) => {}
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                        crate::CombinedOperationsRejection::DualRecoveryKeyRoles,
                    )))
                }
            }
        }
        let provenance = recovery.as_ref().map(|_| StateProvenance::Imported);
        let body = prepared.bind(cipher_key, mac_key)?;
        let (lease, cancel) = cancel.bind(&s.lease_admission()?)?;
        let mut owner =
            Operation::new(OperationBody::Dual(body), lease, cancel).with_validation(validation);
        owner.provenance = provenance;
        let (id, operation) = s.operations.install(&self.session.entry, owner)?;
        // Retain the common terminal diagnostic after a failed initial drive
        // removes this operation; the public entry owns this anchor.
        *retired_owner = Some(operation.clone());
        let ticket = OperationTicket {
            owner: self.session.inner.clone(),
            uid: self.session.uid,
            id,
            validation_report: None,
            state_provenance: provenance,
        };
        if recovery.is_none() {
            let mut operation = operation.lock().map_err(|_| Error::Poisoned)?;
            if let Err(error) = drive(
                &s,
                &self.session.entry,
                &mut operation,
                false,
                &mut self.pacing.budget(),
            ) {
                let (error, _) = operation.retire_terminal_error(&s, &self.session.entry, error);
                return Err(error);
            }
        }
        Ok(ticket)
    }
}
