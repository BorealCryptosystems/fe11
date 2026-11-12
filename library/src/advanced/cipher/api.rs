// SPDX-License-Identifier: Apache-2.0
//! Both facades install and drive the same standalone cipher owner.
use super::{
    drive, poll, snapshot, validation, AdvancedSession, AdvancedSessionMode, CipherKeyReference,
    CipherOperation, CipherOutputPlan, Direction, MessageRoute, Operation, OperationBody,
    OperationPacing, OperationProgress, OperationTicket, Selection,
};
use crate::{AesCipherParameters, CipherParameters, InputLimits, SymmetricAlgorithm, SymmetricKey};
use crate::{Error, Result, Session};
use fe11_sys::{CKM_AES_CCM, CK_MECHANISM_TYPE};
use std::sync::Arc;

// The convenience AES profile and the generic native reference retain their
// distinct checkpoint bindings; both use the same operation and dispatch path.
#[derive(Clone, Copy)]
pub(super) enum CipherKey<'a> {
    Profiled(&'a SymmetricKey),
    Native(CipherKeyReference<'a>),
}

impl Session {
    /// Take a continuation retained after an error in a synchronous operation.
    /// A failed native operation may permit only explicit cleanup, not resumption.
    /// This is a local, single-use transfer for this session, not a native call.
    /// Select space with resize_cipher_output, then continue with poll_cipher.
    /// Calling twice fails; tickets already returned by begin_* cannot be taken.
    /// Dropping this ticket does not cancel work. Explicit session close remains
    /// available if continuation is unwanted or native cancellation is unavailable.
    pub fn take_cipher_ticket(&self) -> Result<OperationTicket> {
        let access = self.advanced_access()?;
        let held = access.operations.get(self.uid)?;
        let mut operation = held.lock().map_err(|_| Error::Poisoned)?;
        let OperationBody::Cipher(body) = &mut operation.body else {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::CipherTicketRequired,
            )));
        };
        // A revoked key must not prevent recovering the owner for cleanup.
        body.take_observer()?;
        Ok(OperationTicket {
            owner: self.inner.clone(),
            uid: self.uid,
            id: operation.id,
            validation_report: None,
            state_provenance: None,
        })
    }

    /// Select capacity for the pending output call, excluding prior output.
    /// This allocates and preserves the produced prefix without a native call.
    /// It is valid only after CipherBufferRequired; it does not publish plaintext.
    pub fn resize_aes_output(&self, ticket: &OperationTicket, capacity: usize) -> Result<()> {
        resize(self, ticket, capacity)
    }
    /// Initialize standalone AES encryption and stop after C_EncryptInit.
    /// Contextual authentication may be supplied before poll_aes consumes data.
    /// No digest/MAC or nonce generation is implicit; output remains owned.
    pub fn begin_encrypt_aes(
        &self,
        key: &SymmetricKey,
        parameters: AesCipherParameters,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<OperationTicket> {
        self.begin_encrypt_aes_with_output_plan(
            key,
            parameters,
            route,
            parts,
            limits,
            CipherOutputPlan::MechanismBound,
        )
    }
    /// Select the first AES output call's buffer strategy explicitly.
    /// CipherBufferRequired preserves the native operation and input step. Choose
    /// storage with resize_aes_output before polling again; no automatic retry.
    pub fn begin_encrypt_aes_with_output_plan(
        &self,
        key: &SymmetricKey,
        parameters: AesCipherParameters,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
        output: CipherOutputPlan,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        start(
            self,
            key,
            parameters,
            Direction::Encrypt,
            route,
            parts,
            limits,
            output,
            false,
            &mut 1,
            &mut retirement,
        )
    }
    /// Initialize standalone AES decryption without publishing intermediate bytes.
    /// The completed plaintext is explicitly unauthenticated.
    pub fn begin_decrypt_aes(
        &self,
        key: &SymmetricKey,
        parameters: AesCipherParameters,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<OperationTicket> {
        self.begin_decrypt_aes_with_output_plan(
            key,
            parameters,
            route,
            parts,
            limits,
            CipherOutputPlan::MechanismBound,
        )
    }
    /// Select the first AES output call's buffer strategy explicitly.
    /// CipherBufferRequired preserves the native operation and input step. Choose
    /// storage with resize_aes_output before polling again; no automatic retry.
    pub fn begin_decrypt_aes_with_output_plan(
        &self,
        key: &SymmetricKey,
        parameters: AesCipherParameters,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
        output: CipherOutputPlan,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        start(
            self,
            key,
            parameters,
            Direction::Decrypt,
            route,
            parts,
            limits,
            output,
            false,
            &mut 1,
            &mut retirement,
        )
    }
    /// Advance only this session's AES ticket to its next publication boundary.
    /// A foreign, stale or different-family ticket is rejected before dispatch.
    pub fn poll_aes(&self, ticket: &mut OperationTicket) -> Result<OperationProgress> {
        self.poll_cipher(ticket)
    }
    /// Advance this session's cipher ticket to the next output boundary.
    /// Preserves the native size report when explicit buffer selection is needed.
    pub fn poll_cipher(&self, ticket: &mut OperationTicket) -> Result<OperationProgress> {
        if !Arc::ptr_eq(&ticket.owner, &self.inner) || ticket.uid != self.uid || ticket.id == 0 {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ForeignOrConsumedCipherTicket,
            )));
        }
        let mut released = crate::advanced::poll::ReleasedInputs::default();
        let access = self.advanced_access()?;
        {
            let held = access.operations.get(self.uid)?;
            let operation = held.lock().map_err(|_| Error::Poisoned)?;
            if operation.id != ticket.id || !matches!(&operation.body, OperationBody::Cipher(_)) {
                return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::CipherTicketRequired,
                )));
            }
        }
        poll::poll_with_access(self, ticket, &access, OperationPacing::Eager, &mut released)
    }
}
impl AdvancedSession {
    /// Take the continuation left by this facade's synchronous cipher method.
    /// No native call occurs. Use resize_cipher_output and poll to continue;
    /// explicit cancel or close is also available without taking a ticket.
    pub fn take_cipher_ticket(&self) -> Result<OperationTicket> {
        self.session.take_cipher_ticket()
    }

    /// Select capacity for the pending output call, excluding prior output.
    /// This allocates and preserves the produced prefix without a native call.
    /// It is valid only after CipherBufferRequired; it does not publish plaintext.
    pub fn resize_aes_output(&self, ticket: &OperationTicket, capacity: usize) -> Result<()> {
        resize(&self.session, ticket, capacity)
    }
    /// Start standalone AES encryption with the selected pacing and validation.
    /// Cooperative pacing stops after Init; no auxiliary authentication operation.
    pub fn start_encrypt_aes(
        &self,
        key: &SymmetricKey,
        parameters: AesCipherParameters,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<OperationTicket> {
        self.start_encrypt_aes_with_output_plan(
            key,
            parameters,
            route,
            parts,
            limits,
            CipherOutputPlan::MechanismBound,
        )
    }
    /// Select the first AES output call's buffer strategy explicitly.
    /// CipherBufferRequired preserves the native operation and input step. Choose
    /// storage with resize_aes_output before polling again; no automatic retry.
    pub fn start_encrypt_aes_with_output_plan(
        &self,
        key: &SymmetricKey,
        parameters: AesCipherParameters,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
        output: CipherOutputPlan,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        start(
            &self.session,
            key,
            parameters,
            Direction::Encrypt,
            route,
            parts,
            limits,
            output,
            self.validation_capture == crate::advanced::ValidationCaptureMode::Capture,
            &mut self.pacing.budget(),
            &mut retirement,
        )
    }
    /// Start standalone AES decryption; poll publishes only complete plaintext.
    /// Captured validation flags do not turn an unauthenticated cipher into AEAD.
    pub fn start_decrypt_aes(
        &self,
        key: &SymmetricKey,
        parameters: AesCipherParameters,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<OperationTicket> {
        self.start_decrypt_aes_with_output_plan(
            key,
            parameters,
            route,
            parts,
            limits,
            CipherOutputPlan::MechanismBound,
        )
    }
    /// Select the first AES output call's buffer strategy explicitly.
    /// CipherBufferRequired preserves the native operation and input step. Choose
    /// storage with resize_aes_output before polling again; no automatic retry.
    pub fn start_decrypt_aes_with_output_plan(
        &self,
        key: &SymmetricKey,
        parameters: AesCipherParameters,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
        output: CipherOutputPlan,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        start(
            &self.session,
            key,
            parameters,
            Direction::Decrypt,
            route,
            parts,
            limits,
            output,
            self.validation_capture == crate::advanced::ValidationCaptureMode::Capture,
            &mut self.pacing.budget(),
            &mut retirement,
        )
    }
}

pub(crate) fn encrypt_synchronous(
    session: &Session,
    key: &SymmetricKey,
    parameters: AesCipherParameters,
    route: MessageRoute,
    parts: &[&[u8]],
    limits: InputLimits,
    retirement: &mut crate::advanced::PollDiagnostics,
) -> Result<crate::Ciphertext> {
    let mut facade = super::synchronous::Facade::start(
        session,
        CipherKey::Profiled(key),
        CipherParameters::from(parameters),
        Direction::Encrypt,
        route,
        parts,
        limits,
        retirement,
    )?;
    facade.poll(session, |progress| match progress {
        OperationProgress::CipherEncrypted(output) => Ok(output),
        _ => Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
            crate::CipherContinuationRejection::SynchronousAesEncryptionDidNotComplete,
        ))),
    })
}
pub(crate) fn decrypt_synchronous(
    session: &Session,
    key: &SymmetricKey,
    parameters: AesCipherParameters,
    route: MessageRoute,
    parts: &[&[u8]],
    limits: InputLimits,
    retirement: &mut crate::advanced::PollDiagnostics,
) -> Result<crate::UnauthenticatedCipherPlaintext> {
    let mut facade = super::synchronous::Facade::start(
        session,
        CipherKey::Profiled(key),
        CipherParameters::from(parameters),
        Direction::Decrypt,
        route,
        parts,
        limits,
        retirement,
    )?;
    facade.poll(session, |progress| match progress {
        OperationProgress::CipherDecrypted(output) => Ok(output),
        _ => Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
            crate::CipherContinuationRejection::SynchronousAesDecryptionDidNotComplete,
        ))),
    })
}

impl Session {
    /// Select the next output buffer after CipherBufferRequired, without a native call.
    pub fn resize_cipher_output(&self, ticket: &OperationTicket, capacity: usize) -> Result<()> {
        resize(self, ticket, capacity)
    }
    /// Initialize native cipher encryption and stop after Init.
    /// The key argument is explicit; the module decides whether it is accepted.
    /// IVs, output storage and route are explicit; no fallback or auxiliary MAC.
    pub fn begin_encrypt_cipher(
        &self,
        key: CipherKeyReference<'_>,
        parameters: CipherParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
        output: CipherOutputPlan,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        start_common(
            self,
            CipherKey::Native(key),
            parameters,
            Direction::Encrypt,
            route,
            parts,
            limits,
            output,
            false,
            &mut 1,
            &mut retirement,
        )
    }
    /// Complete the selected native cipher route using mechanism-sized storage.
    /// A native refusal is returned without an implicit retry. Insufficient space
    /// returns Error::CipherBufferRequired: take_cipher_ticket retrieves its
    /// continuation once. The session remains occupied until completion or cleanup.
    /// Decryption establishes no authenticity; caller copies have independent lifetimes.
    pub fn encrypt_cipher(
        &self,
        key: CipherKeyReference<'_>,
        parameters: CipherParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<crate::Ciphertext> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        let mut facade = super::synchronous::Facade::start(
            self,
            CipherKey::Native(key),
            parameters,
            Direction::Encrypt,
            route,
            parts,
            limits,
            &mut retirement,
        )?;
        facade.poll(self, |progress| match progress {
            OperationProgress::CipherEncrypted(output) => Ok(output),
            _ => Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::SynchronousCipherDidNotComplete,
            ))),
        })
    }
    /// Initialize native cipher decryption and stop after Init.
    /// The key argument is explicit; the module decides whether it is accepted.
    /// IVs, output storage and route are explicit; no fallback or auxiliary MAC.
    pub fn begin_decrypt_cipher(
        &self,
        key: CipherKeyReference<'_>,
        parameters: CipherParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
        output: CipherOutputPlan,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        start_common(
            self,
            CipherKey::Native(key),
            parameters,
            Direction::Decrypt,
            route,
            parts,
            limits,
            output,
            false,
            &mut 1,
            &mut retirement,
        )
    }
    /// Complete the selected native cipher route using mechanism-sized storage.
    /// A native refusal is returned without an implicit retry. Insufficient space
    /// returns Error::CipherBufferRequired: take_cipher_ticket retrieves its
    /// continuation once. The session remains occupied until completion or cleanup.
    /// Decryption establishes no authenticity; caller copies have independent lifetimes.
    pub fn decrypt_cipher(
        &self,
        key: CipherKeyReference<'_>,
        parameters: CipherParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<crate::UnauthenticatedCipherPlaintext> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        let mut facade = super::synchronous::Facade::start(
            self,
            CipherKey::Native(key),
            parameters,
            Direction::Decrypt,
            route,
            parts,
            limits,
            &mut retirement,
        )?;
        facade.poll(self, |progress| match progress {
            OperationProgress::CipherDecrypted(output) => Ok(output),
            _ => Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::SynchronousCipherDidNotComplete,
            ))),
        })
    }
}

impl AdvancedSession {
    /// Select the next output buffer after CipherBufferRequired, without a native call.
    pub fn resize_cipher_output(&self, ticket: &OperationTicket, capacity: usize) -> Result<()> {
        resize(&self.session, ticket, capacity)
    }
    /// Start the selected native cipher with this facade's pacing and validation.
    /// Generic poll returns CipherEncrypted, CipherDecrypted or CipherBufferRequired.
    /// Validation observations do not authenticate an unauthenticated cipher.
    pub fn start_encrypt_cipher(
        &self,
        key: CipherKeyReference<'_>,
        parameters: CipherParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
        output: CipherOutputPlan,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        start_common(
            &self.session,
            CipherKey::Native(key),
            parameters,
            Direction::Encrypt,
            route,
            parts,
            limits,
            output,
            self.validation_capture == crate::advanced::ValidationCaptureMode::Capture,
            &mut self.pacing.budget(),
            &mut retirement,
        )
    }
    /// Complete the native route synchronously through the same session owner.
    /// Use start_encrypt_cipher and poll for paced execution and validation capture.
    pub fn encrypt_cipher(
        &self,
        key: CipherKeyReference<'_>,
        parameters: CipherParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<crate::Ciphertext> {
        self.session
            .encrypt_cipher(key, parameters, route, parts, limits)
    }
    /// Start the selected native cipher with this facade's pacing and validation.
    /// Generic poll returns CipherEncrypted, CipherDecrypted or CipherBufferRequired.
    /// Validation observations do not authenticate an unauthenticated cipher.
    pub fn start_decrypt_cipher(
        &self,
        key: CipherKeyReference<'_>,
        parameters: CipherParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
        output: CipherOutputPlan,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        start_common(
            &self.session,
            CipherKey::Native(key),
            parameters,
            Direction::Decrypt,
            route,
            parts,
            limits,
            output,
            self.validation_capture == crate::advanced::ValidationCaptureMode::Capture,
            &mut self.pacing.budget(),
            &mut retirement,
        )
    }
    /// Complete the native route synchronously through the same session owner.
    /// Use start_decrypt_cipher and poll for paced execution and validation capture.
    pub fn decrypt_cipher(
        &self,
        key: CipherKeyReference<'_>,
        parameters: CipherParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<crate::UnauthenticatedCipherPlaintext> {
        self.session
            .decrypt_cipher(key, parameters, route, parts, limits)
    }
}

mod preparation;
use preparation::resize;
use preparation::start;
pub(super) use preparation::start_common;
pub(super) use preparation::start_common_with_input;
pub(super) use preparation::start_retained;
