// SPDX-License-Identifier: Apache-2.0
//! Single-part RSA encryption with provider-owned padding and arithmetic.
//! Init-only entry points share the retained cipher owner and its explicit
//! continuation; synchronous convenience calls keep their existing behavior.
use crate::{
    CipherKeyReference, CipherOutputPlan, ContextAuthentication, ExtensionInput,
    ExtensionOperation, ExtensionResult, InputLimits, NativeOaepParameters, NativeObjectRef,
    NativeTransportMechanism, NativeTransportParameters, OperationTicket, Result, Session,
};

/// Exact native RSA encryption selection. This does not validate a key's
/// mathematics, implement padding, or infer mechanism support from its presence.
pub enum NativeRsaCipherParameters<'a> {
    /// CKM_RSA_PKCS, PKCS#1 v1.5 padding performed by the module.
    Pkcs1v15,
    /// CKM_RSA_X_509, raw RSA without padding or an authentication guarantee.
    X509,
    /// CKM_RSA_PKCS_OAEP with the exact caller-supplied native parameters.
    Oaep(NativeOaepParameters<'a>),
    /// CKM_RSA_PKCS_TPM_1_1, including the native TPM-bound-data formatting.
    Tpm11Pkcs1,
    /// CKM_RSA_PKCS_OAEP_TPM_1_1; its format has no mechanism parameter.
    Tpm11Oaep,
}
impl<'a> NativeRsaCipherParameters<'a> {
    fn parameters(self) -> NativeTransportParameters<'a> {
        let mechanism = match self {
            Self::Pkcs1v15 => NativeTransportMechanism::RSA_PKCS,
            Self::X509 => NativeTransportMechanism::RSA_X_509,
            Self::Oaep(parameters) => return NativeTransportParameters::RsaOaep(parameters),
            Self::Tpm11Pkcs1 => NativeTransportMechanism::RSA_PKCS_TPM_1_1,
            Self::Tpm11Oaep => NativeTransportMechanism::RSA_PKCS_OAEP_TPM_1_1,
        };
        NativeTransportParameters::Fixed {
            mechanism,
            bytes: None,
        }
    }
}
pub(crate) fn begin(
    session: &Session,
    key: &NativeObjectRef,
    parameters: NativeRsaCipherParameters<'_>,
    input: &[u8],
    output_capacity: usize,
    limits: InputLimits,
    operation: ExtensionOperation,
    capture: bool,
    retirement: &mut crate::advanced::PollDiagnostics,
) -> Result<OperationTicket> {
    crate::native_transport::with_parameters(
        session,
        parameters.parameters(),
        operation,
        |request, _| {
            crate::advanced::cipher::begin_native_single(
                session,
                CipherKeyReference::from(key),
                request,
                input,
                limits,
                CipherOutputPlan::Buffer {
                    capacity: output_capacity,
                },
                capture,
                retirement,
            )
        },
    )
}

fn execute(
    session: &Session,
    key: &NativeObjectRef,
    parameters: NativeRsaCipherParameters<'_>,
    input: &[u8],
    output_capacity: usize,
    limits: InputLimits,
    authentication: Option<ContextAuthentication>,
    decrypt: bool,
    extension_diagnostics: &mut crate::mechanism_extension::operation::Invocation,
) -> Result<ExtensionResult> {
    let operation = if decrypt {
        ExtensionOperation::Decrypt
    } else {
        ExtensionOperation::Encrypt
    };
    crate::native_transport::with_parameters(
        session,
        parameters.parameters(),
        operation,
        |request, _| {
            let input = if decrypt {
                ExtensionInput::Decrypt {
                    key,
                    input,
                    output_capacity,
                }
            } else {
                ExtensionInput::Encrypt {
                    key,
                    input,
                    output_capacity,
                }
            };
            crate::mechanism_extension::operation::execute(
                session,
                request,
                input,
                limits,
                authentication,
                extension_diagnostics,
            )
        },
    )
}
impl Session {
    /// Invoke C_EncryptInit for the selected RSA mechanism and stop there.
    /// The plaintext and parameters are copied before Init, but C_Encrypt is
    /// called only by an explicit poll_cipher. No padding or key-type policy is
    /// evaluated locally; a native Init refusal retains its function and code.
    ///
    /// Polling returns ExtensionEncrypted on completion. If more output space
    /// is required, use resize_cipher_output before polling again; Init is not
    /// repeated. Dropping a ticket does not cancel the native operation. Use
    /// the existing cancellation or session-close API when abandoning it.
    pub fn begin_encrypt_native_rsa(
        &self,
        key: &NativeObjectRef,
        parameters: NativeRsaCipherParameters<'_>,
        plaintext: &[u8],
        output_capacity: usize,
        limits: InputLimits,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        begin(
            self,
            key,
            parameters,
            plaintext,
            output_capacity,
            limits,
            ExtensionOperation::Encrypt,
            false,
            &mut retirement,
        )
    }

    /// Invoke C_DecryptInit and stop before consuming the copied ciphertext.
    /// If required, call authenticate_context with the returned ticket before
    /// poll_cipher. Completion yields ExtensionDecrypted; this provides no
    /// authentication guarantee for the selected RSA padding or raw operation.
    /// Buffer selection and abandonment follow begin_encrypt_native_rsa.
    pub fn begin_decrypt_native_rsa(
        &self,
        key: &NativeObjectRef,
        parameters: NativeRsaCipherParameters<'_>,
        ciphertext: &[u8],
        output_capacity: usize,
        limits: InputLimits,
    ) -> Result<OperationTicket> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        begin(
            self,
            key,
            parameters,
            ciphertext,
            output_capacity,
            limits,
            ExtensionOperation::Decrypt,
            false,
            &mut retirement,
        )
    }

    /// Encrypt once using the selected RSA mechanism. Capacity is chosen by the
    /// caller; no size probe, retry or alternative padding is performed. Input
    /// and parameters are copied into the retained native frame before Init.
    /// Native errors remain observable. Output is published only after success.
    pub fn encrypt_native_rsa(
        &self,
        key: &NativeObjectRef,
        parameters: NativeRsaCipherParameters<'_>,
        plaintext: &[u8],
        output_capacity: usize,
        limits: InputLimits,
    ) -> Result<ExtensionResult> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.encrypt_native_rsa_with_diagnostics(
            key,
            parameters,
            plaintext,
            output_capacity,
            limits,
            &mut extension_diagnostics,
        )
    }

    // Internal callers supply their outer publication owner; no helper
    // return may release the credit of an error still being projected.
    pub(crate) fn encrypt_native_rsa_with_diagnostics(
        &self,
        key: &NativeObjectRef,
        parameters: NativeRsaCipherParameters<'_>,
        plaintext: &[u8],
        output_capacity: usize,
        limits: InputLimits,
        extension_diagnostics: &mut crate::mechanism_extension::operation::Invocation,
    ) -> Result<ExtensionResult> {
        execute(
            self,
            key,
            parameters,
            plaintext,
            output_capacity,
            limits,
            None,
            false,
            extension_diagnostics,
        )
    }
    /// Decrypt once, optionally authenticating after Init. All output remains
    /// withheld until native completion and context validation. This API adds
    /// no authentication guarantee to the selected RSA padding or raw operation.
    pub fn decrypt_native_rsa(
        &self,
        key: &NativeObjectRef,
        parameters: NativeRsaCipherParameters<'_>,
        ciphertext: &[u8],
        output_capacity: usize,
        limits: InputLimits,
        authentication: Option<ContextAuthentication>,
    ) -> Result<ExtensionResult> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.decrypt_native_rsa_with_diagnostics(
            key,
            parameters,
            ciphertext,
            output_capacity,
            limits,
            authentication,
            &mut extension_diagnostics,
        )
    }

    // Internal callers supply their outer publication owner; no helper
    // return may release the credit of an error still being projected.
    pub(crate) fn decrypt_native_rsa_with_diagnostics(
        &self,
        key: &NativeObjectRef,
        parameters: NativeRsaCipherParameters<'_>,
        ciphertext: &[u8],
        output_capacity: usize,
        limits: InputLimits,
        authentication: Option<ContextAuthentication>,
        extension_diagnostics: &mut crate::mechanism_extension::operation::Invocation,
    ) -> Result<ExtensionResult> {
        execute(
            self,
            key,
            parameters,
            ciphertext,
            output_capacity,
            limits,
            authentication,
            true,
            extension_diagnostics,
        )
    }
}
impl crate::AdvancedSession {
    /// Synchronous native RSA encryption through the common Session owner.
    pub fn encrypt_native_rsa(
        &self,
        key: &NativeObjectRef,
        parameters: NativeRsaCipherParameters<'_>,
        plaintext: &[u8],
        output_capacity: usize,
        limits: InputLimits,
    ) -> Result<ExtensionResult> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.session.encrypt_native_rsa_with_diagnostics(
            key,
            parameters,
            plaintext,
            output_capacity,
            limits,
            &mut extension_diagnostics,
        )
    }
    /// Synchronous native RSA decryption through the common Session owner.
    pub fn decrypt_native_rsa(
        &self,
        key: &NativeObjectRef,
        parameters: NativeRsaCipherParameters<'_>,
        ciphertext: &[u8],
        output_capacity: usize,
        limits: InputLimits,
        authentication: Option<ContextAuthentication>,
    ) -> Result<ExtensionResult> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.session.decrypt_native_rsa_with_diagnostics(
            key,
            parameters,
            ciphertext,
            output_capacity,
            limits,
            authentication,
            &mut extension_diagnostics,
        )
    }
}
