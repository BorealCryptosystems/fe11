// SPDX-License-Identifier: Apache-2.0
//! The declaration selects the ABI; the existing cipher owner drives native calls.
use super::{api, extension::Source, CipherKeyReference, CipherOutputPlan, Direction, Selection};
use crate::advanced::{input::InputState, AdvancedSession, OperationTicket, ValidationCaptureMode};
use crate::{
    Error, ExtensionOperation, ExtensionRequest, InputLimits, NativeObjectRef,
    NativeRsaCipherParameters, Result, Session,
};

/// Prepare a complete input, but dispatch only its initialization. The shared
/// owner keeps the copied graph, key lease and buffers alive until continuation
/// or explicit cleanup. A single step is intentional even for an eager facade:
/// an Init-only API must never consume input before returning its ticket.
pub(crate) fn begin_single(
    session: &Session,
    key: CipherKeyReference<'_>,
    request: ExtensionRequest<'_>,
    input: &[u8],
    limits: InputLimits,
    output: CipherOutputPlan,
    capture: bool,
    retirement: &mut crate::advanced::PollDiagnostics,
) -> Result<OperationTicket> {
    let direction = match request.contract.operation() {
        ExtensionOperation::Encrypt => Direction::Encrypt,
        ExtensionOperation::Decrypt => Direction::Decrypt,
        _ => {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::SinglePartCipherDeclarationRequired,
            )))
        }
    };
    api::start_common(
        session,
        api::CipherKey::Native(key),
        Selection::Extension(Source::Declared(request.into())),
        direction,
        crate::MessageRoute::Single,
        &[input],
        limits,
        output,
        capture,
        &mut 1,
        retirement,
    )
}

fn begin(
    session: &Session,
    key: CipherKeyReference<'_>,
    request: ExtensionRequest<'_>,
    output: CipherOutputPlan,
    capture: bool,
    retirement: &mut crate::advanced::PollDiagnostics,
) -> Result<OperationTicket> {
    let direction = match request.contract.operation() {
        ExtensionOperation::EncryptMultipart => Direction::Encrypt,
        ExtensionOperation::DecryptMultipart => Direction::Decrypt,
        _ => {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::MultipartCipherDeclarationRequired,
            )))
        }
    };
    api::start_common_with_input(
        session,
        api::CipherKey::Native(key),
        Selection::Extension(Source::Declared(request.into())),
        direction,
        crate::MessageRoute::Multipart,
        &[],
        InputLimits {
            maximum_parts: session.inner.crypto_options.limits.maximum_parts,
            maximum_total_bytes: session.inner.crypto_options.limits.maximum_total_bytes,
        },
        output,
        capture,
        &mut 1,
        InputState::open(),
        None,
        retirement,
    )
}

impl Session {
    /// Initialize an explicitly declared native cipher with no predicted input.
    /// Use cipher_update and finish_cipher_stream to provide input and close it.
    /// Buffer or LengthOnly selects output storage; no bound is inferred from an
    /// arbitrary mechanism. Returned plaintext carries no local authentication claim.
    pub fn begin_extension_cipher_stream(
        &self,
        key: CipherKeyReference<'_>,
        request: ExtensionRequest<'_>,
        output: CipherOutputPlan,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        begin(self, key, request, output, false, &mut retirement)
    }
}
impl AdvancedSession {
    /// Invoke only C_EncryptInit, even when this facade uses eager pacing.
    /// Input is copied before Init; poll explicitly to obtain ExtensionEncrypted.
    /// Validation capture follows this facade's configuration. Buffer selection,
    /// native refusals and abandonment follow Session::begin_encrypt_native_rsa.
    pub fn begin_encrypt_native_rsa(
        &self,
        key: &NativeObjectRef,
        parameters: NativeRsaCipherParameters<'_>,
        plaintext: &[u8],
        output_capacity: usize,
        limits: InputLimits,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        crate::native_rsa_cipher::begin(
            &self.session,
            key,
            parameters,
            plaintext,
            output_capacity,
            limits,
            ExtensionOperation::Encrypt,
            self.validation_capture == ValidationCaptureMode::Capture,
            &mut retirement,
        )
    }

    /// Invoke only C_DecryptInit and retain the copied ciphertext for poll.
    /// Contextual authentication is explicit between Init and poll. Completion
    /// yields ExtensionDecrypted, without a local authentication guarantee.
    /// Validation capture follows this facade's configuration.
    pub fn begin_decrypt_native_rsa(
        &self,
        key: &NativeObjectRef,
        parameters: NativeRsaCipherParameters<'_>,
        ciphertext: &[u8],
        output_capacity: usize,
        limits: InputLimits,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        crate::native_rsa_cipher::begin(
            &self.session,
            key,
            parameters,
            ciphertext,
            output_capacity,
            limits,
            ExtensionOperation::Decrypt,
            self.validation_capture == ValidationCaptureMode::Capture,
            &mut retirement,
        )
    }

    /// Initialize the shared native cipher owner and preserve validation capture.
    pub fn begin_extension_cipher_stream(
        &self,
        key: CipherKeyReference<'_>,
        request: ExtensionRequest<'_>,
        output: CipherOutputPlan,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        begin(
            &self.session,
            key,
            request,
            output,
            self.validation_capture == ValidationCaptureMode::Capture,
            &mut retirement,
        )
    }
}
