// SPDX-License-Identifier: Apache-2.0
//! Start AEAD message sequences with explicit keys and initialization layout.
//! Encryption and decryption retain distinct nonce, tag and output obligations.

use super::*;

impl AdvancedSession {
    /// Encrypt messages with native AES-128/192/256-GCM and the chosen IV/tag. The route
    /// and nonce origin are explicit; refusal never selects another mechanism.
    pub fn encrypt_gcm_messages(
        &self,
        key: &SymmetricKey,
        messages: &[GcmEncryptMessage<'_>],
        route: MessageRoute,
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        self.start_aead_messages(
            MessageKey::Aes(key),
            Requests::Encrypt(messages),
            route,
            limits,
            MessageInitLayout::InitWithoutParameters,
        )
    }

    /// Decrypt a complete batch, retaining every plaintext until every message
    /// and the native process have completed successfully. One bad message
    /// rejects the batch and releases no plaintext from earlier messages.
    /// A native insufficient-buffer return retains the exact call and exposes
    /// CipherBufferRequired through polling; replacement and retry are explicit.
    pub fn decrypt_gcm_messages(
        &self,
        key: &SymmetricKey,
        messages: &[GcmDecryptMessage<'_>],
        route: MessageRoute,
        limits: crate::InputLimits,
    ) -> Result<OperationTicket> {
        self.start_aead_messages(
            MessageKey::Aes(key),
            Requests::Decrypt(messages),
            route,
            limits,
            MessageInitLayout::InitWithoutParameters,
        )
    }

    /// Encrypt a batch with an explicit Init layout. The owned-parameters
    /// variant shares stable IV/tag targets across every message and refuses
    /// changed fixed scalars before any native call for the batch.
    pub fn encrypt_gcm_messages_with_init(
        &self,
        key: &SymmetricKey,
        messages: &[GcmEncryptMessage<'_>],
        route: MessageRoute,
        limits: crate::InputLimits,
        init: MessageInitLayout,
    ) -> Result<OperationTicket> {
        self.start_aead_messages(
            MessageKey::Aes(key),
            Requests::Encrypt(messages),
            route,
            limits,
            init,
        )
    }

    /// Decrypt with the same explicit shared-target contract; all plaintexts
    /// remain private until every message and the native process succeed.
    pub fn decrypt_gcm_messages_with_init(
        &self,
        key: &SymmetricKey,
        messages: &[GcmDecryptMessage<'_>],
        route: MessageRoute,
        limits: crate::InputLimits,
        init: MessageInitLayout,
    ) -> Result<OperationTicket> {
        self.start_aead_messages(
            MessageKey::Aes(key),
            Requests::Decrypt(messages),
            route,
            limits,
            init,
        )
    }

    pub(in crate::advanced) fn aead_message_key(
        &self,
        s: &State,
        key: MessageKey<'_>,
        kind: CipherKind,
        decrypt: bool,
        route: MessageRoute,
        permits: &mut [Option<crate::registry::ReadPermit>],
    ) -> Result<KeyLease> {
        message_key(&self.session, s, key, kind, decrypt, route, permits)
    }

    pub(super) fn start_aead_messages(
        &self,
        key: MessageKey<'_>,
        requests: Requests<'_>,
        route: MessageRoute,
        limits: crate::InputLimits,
        init: MessageInitLayout,
    ) -> Result<OperationTicket> {
        let mut diagnostics = None;
        start_shared_messages(
            &self.session,
            key,
            requests,
            route,
            limits,
            init,
            self.pacing,
            self.validation_capture == ValidationCaptureMode::Capture,
            InputAccounting::Batch,
            None,
            &mut diagnostics,
        )
        .map(|(ticket, _, _)| ticket)
    }
}

impl Session {
    pub(crate) fn gcm_message_buffers(
        &self,
        key: &crate::ManagedObjectRef,
        nonce: AeadNonce,
        aad: &[u8],
        parts: &[&[u8]],
        limits: crate::InputLimits,
        init: MessageInitLayout,
        retained_metadata: usize,
        message_diagnostics: &mut Option<crate::advanced::AeadMessageDiagnostics>,
    ) -> Result<(Buffer, Buffer, Credit)> {
        complete_single_message(
            self,
            MessageKey::Native(key),
            Request {
                nonce: Selection::Gcm(nonce),
                aad,
                parts,
                tag: None,
            },
            CipherKind::Gcm,
            false,
            MessageRoute::Single,
            limits,
            init,
            retained_metadata,
            message_diagnostics,
        )
    }
}
