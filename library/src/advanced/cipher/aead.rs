// SPDX-License-Identifier: Apache-2.0
//! Classic AEAD facades over the registered cipher driver.
use super::{
    api, AdvancedSession, CipherKeyReference, CipherOutputPlan, Direction, MessageRoute,
    OperationProgress, OperationTicket, Selection,
};
use crate::symmetric::memory::{Buffer, Credit};
use crate::{
    AeadPlaintext, ClassicAeadCiphertext, ClassicAeadParameters, InputLimits, NativeObjectRef,
};
use crate::{Error, Result, Session};

fn begin_stream(
    session: &Session,
    key: &NativeObjectRef,
    parameters: ClassicAeadParameters<'_>,
    ccm_plaintext_length: Option<u64>,
    direction: Direction,
    output: CipherOutputPlan,
    capture: bool,
    retirement: &mut crate::advanced::PollDiagnostics,
) -> Result<OperationTicket> {
    if matches!(parameters, ClassicAeadParameters::Ccm { .. }) != ccm_plaintext_length.is_some() {
        return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
            crate::CipherContinuationRejection::OnlyCcmRequiresAnExplicitStreamPlaintextLength,
        )));
    }
    let limits = InputLimits {
        maximum_parts: session.inner.crypto_options.limits.maximum_parts,
        maximum_total_bytes: session.inner.crypto_options.limits.maximum_total_bytes,
    };
    api::start_common_with_input(
        session,
        api::CipherKey::Native(CipherKeyReference::Secret(key)),
        parameters,
        direction,
        MessageRoute::Multipart,
        &[],
        limits,
        output,
        capture,
        &mut 1,
        crate::advanced::input::InputState::open(),
        ccm_plaintext_length,
        retirement,
    )
}

impl Session {
    /// Initialize classic AEAD encryption, then supply cipher_update calls and
    /// finish_cipher_stream. CCM requires its exact native ulDataLen (plaintext
    /// bytes); other layouts take None because they carry no total-input field.
    pub fn begin_encrypt_classic_aead_stream(
        &self,
        key: &NativeObjectRef,
        parameters: ClassicAeadParameters<'_>,
        ccm_plaintext_length: Option<u64>,
        output: CipherOutputPlan,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        begin_stream(
            self,
            key,
            parameters,
            ccm_plaintext_length,
            Direction::Encrypt,
            output,
            false,
            &mut retirement,
        )
    }

    /// Initialize classic AEAD decryption without buffering future input.
    /// All plaintext remains owned and inaccessible until successful native Final.
    /// CCM's explicit length excludes the tag; other layouts take None.
    pub fn begin_decrypt_classic_aead_stream(
        &self,
        key: &NativeObjectRef,
        parameters: ClassicAeadParameters<'_>,
        ccm_plaintext_length: Option<u64>,
        output: CipherOutputPlan,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        begin_stream(
            self,
            key,
            parameters,
            ccm_plaintext_length,
            Direction::Decrypt,
            output,
            false,
            &mut retirement,
        )
    }
}

impl AdvancedSession {
    /// Initialize the shared AEAD stream owner, stopping after Init.
    /// Supply Some(plaintext bytes) only for CCM's required ulDataLen.
    pub fn begin_encrypt_classic_aead_stream(
        &self,
        key: &NativeObjectRef,
        parameters: ClassicAeadParameters<'_>,
        ccm_plaintext_length: Option<u64>,
        output: CipherOutputPlan,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        begin_stream(
            &self.session,
            key,
            parameters,
            ccm_plaintext_length,
            Direction::Encrypt,
            output,
            self.validation_capture == crate::advanced::ValidationCaptureMode::Capture,
            &mut retirement,
        )
    }

    /// Initialize the shared AEAD decryption stream owner. Capture/restore keeps
    /// its unauthenticated plaintext private and preserves the exact CCM framing.
    pub fn begin_decrypt_classic_aead_stream(
        &self,
        key: &NativeObjectRef,
        parameters: ClassicAeadParameters<'_>,
        ccm_plaintext_length: Option<u64>,
        output: CipherOutputPlan,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        begin_stream(
            &self.session,
            key,
            parameters,
            ccm_plaintext_length,
            Direction::Decrypt,
            output,
            self.validation_capture == crate::advanced::ValidationCaptureMode::Capture,
            &mut retirement,
        )
    }
}

impl Session {
    /// Initialize classic AEAD encryption with owned parameters and input.
    /// Stops after Init; poll_cipher continues the operation.
    /// CipherBufferRequired retains the exact pending native call. Explicitly
    /// resize_cipher_output before polling again. No plaintext is published until
    /// terminal verification succeeds. Save/restore uses the ordinary ticket and
    /// requires native Get/SetOperationState support; native refusals are retained.
    pub fn begin_encrypt_classic_aead(
        &self,
        key: &NativeObjectRef,
        parameters: ClassicAeadParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
        output: CipherOutputPlan,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        api::start_common(
            self,
            api::CipherKey::Native(CipherKeyReference::Secret(key)),
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
    /// Initialize classic AEAD decryption with owned parameters and input.
    /// Stops after Init; poll_cipher continues the operation.
    /// CipherBufferRequired retains the exact pending native call. Explicitly
    /// resize_cipher_output before polling again. No plaintext is published until
    /// terminal verification succeeds. Save/restore uses the ordinary ticket and
    /// requires native Get/SetOperationState support; native refusals are retained.
    pub fn begin_decrypt_classic_aead(
        &self,
        key: &NativeObjectRef,
        parameters: ClassicAeadParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
        output: CipherOutputPlan,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        api::start_common(
            self,
            api::CipherKey::Native(CipherKeyReference::Secret(key)),
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
}
impl AdvancedSession {
    /// Initialize classic AEAD encryption with owned parameters and input.
    /// Uses this facade's pacing; poll continues the operation.
    /// CipherBufferRequired retains the exact pending native call. Explicitly
    /// resize_cipher_output before polling again. No plaintext is published until
    /// terminal verification succeeds. Save/restore uses the ordinary ticket and
    /// requires native Get/SetOperationState support; native refusals are retained.
    pub fn start_encrypt_classic_aead(
        &self,
        key: &NativeObjectRef,
        parameters: ClassicAeadParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
        output: CipherOutputPlan,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        api::start_common(
            &self.session,
            api::CipherKey::Native(CipherKeyReference::Secret(key)),
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
    /// Initialize classic AEAD decryption with owned parameters and input.
    /// Uses this facade's pacing; poll continues the operation.
    /// CipherBufferRequired retains the exact pending native call. Explicitly
    /// resize_cipher_output before polling again. No plaintext is published until
    /// terminal verification succeeds. Save/restore uses the ordinary ticket and
    /// requires native Get/SetOperationState support; native refusals are retained.
    pub fn start_decrypt_classic_aead(
        &self,
        key: &NativeObjectRef,
        parameters: ClassicAeadParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
        output: CipherOutputPlan,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        api::start_common(
            &self.session,
            api::CipherKey::Native(CipherKeyReference::Secret(key)),
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
impl Session {
    /// Complete classic AEAD encryption with the same registered owner.
    /// An insufficient native output buffer returns Error::CipherBufferRequired;
    /// take_cipher_ticket retrieves the continuation once, without another Init.
    /// Dropping a ticket does not cancel the native operation; explicit cleanup
    /// remains required. The module decides mechanism and multipart support.
    pub fn encrypt_classic_aead(
        &self,
        key: &NativeObjectRef,
        parameters: ClassicAeadParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<ClassicAeadCiphertext> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        let mut facade = super::synchronous::Facade::start(
            self,
            api::CipherKey::Native(CipherKeyReference::Secret(key)),
            parameters,
            Direction::Encrypt,
            route,
            parts,
            limits,
            &mut retirement,
        )?;
        facade.poll(self, |progress| match progress {
            OperationProgress::ClassicAeadEncrypted(output) => Ok(output),
            _ => Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::SynchronousClassicAeadDidNotComplete,
            ))),
        })
    }
    /// Complete classic AEAD decryption with the same registered owner.
    /// An insufficient native output buffer returns Error::CipherBufferRequired;
    /// take_cipher_ticket retrieves the continuation once, without another Init.
    /// Dropping a ticket does not cancel the native operation; explicit cleanup
    /// remains required. The module decides mechanism and multipart support.
    pub fn decrypt_classic_aead(
        &self,
        key: &NativeObjectRef,
        parameters: ClassicAeadParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<AeadPlaintext> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        let mut facade = super::synchronous::Facade::start(
            self,
            api::CipherKey::Native(CipherKeyReference::Secret(key)),
            parameters,
            Direction::Decrypt,
            route,
            parts,
            limits,
            &mut retirement,
        )?;
        facade.poll(self, |progress| match progress {
            OperationProgress::ClassicAeadDecrypted(output) => Ok(output),
            _ => Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::SynchronousClassicAeadDidNotComplete,
            ))),
        })
    }
}

impl Session {
    // Compatibility facades transfer their retained request metadata through the
    // same graph admission. The returned tuple is private, after terminal success;
    // on a size report the generic ticket takes over without retaining a facade.
    pub(crate) fn classic_aead_retained(
        &self,
        key: &NativeObjectRef,
        parameters: ClassicAeadParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
        decrypt: bool,
        retained: usize,
        retirement: &mut crate::advanced::PollDiagnostics,
    ) -> Result<(Buffer, Buffer, Credit)> {
        let mut facade = super::synchronous::Facade::start(
            self,
            api::CipherKey::Native(CipherKeyReference::Secret(key)),
            Selection::Aead(parameters, retained),
            if decrypt {
                Direction::Decrypt
            } else {
                Direction::Encrypt
            },
            route,
            parts,
            limits,
            retirement,
        )?;
        facade.poll(self, |progress| match progress {
            OperationProgress::ClassicAeadEncrypted(value) if !decrypt => {
                Ok((value.bytes, value.nonce, value.retention))
            }
            OperationProgress::ClassicAeadDecrypted(value) if decrypt => value.into_classic_parts(),
            _ => Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::ClassicAeadResultDirectionMismatch,
            ))),
        })
    }
}
