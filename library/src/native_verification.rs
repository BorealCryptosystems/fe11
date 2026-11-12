// SPDX-License-Identifier: Apache-2.0
//! General PKCS#11 3.2 verification with the signature supplied at Init.
use crate::mechanism_extension::operation;
use crate::{
    ContextAuthentication, Error, ExtensionInput, ExtensionOperation, InputLimits, MessageRoute,
    NativeCmsParameters, NativeKipParameters, NativeMacParameters, NativeObjectRef,
    NativeOtpAlgorithm, NativeOtpLimits, NativeOtpParameter, NativeSignatureParameters, Result,
    Session,
};

/// Typed parameter families for verification. PKCS#11 3.2 requires mechanisms
/// supporting VerifyInit to support VerifySignatureInit as well. Actual native
/// availability and refusals remain observable; no other family is substituted.
pub enum NativeVerificationParameters<'a> {
    /// Classical, stateful or PQC signature parameters.
    Signature(NativeSignatureParameters<'a>),
    /// Standard MAC parameters, including caller-selected truncation lengths.
    Mac(NativeMacParameters<'a>),
    /// Native CMS signature composition and its exact nested mechanisms.
    Cms(NativeCmsParameters<'a>),
    /// CT-KIP MAC composition.
    Kip(NativeKipParameters<'a>),
    /// Native OTP verification parameters. The signature argument is the OTP
    /// value, never a pointer-bearing CK_OTP_SIGNATURE_INFO representation.
    Otp {
        /// Exact mechanism.
        algorithm: NativeOtpAlgorithm,
        /// Exact native parameter values.
        parameters: &'a [NativeOtpParameter<'a>],
        /// Caller-selected bounds for their owned representation.
        limits: NativeOtpLimits,
    },
}
impl Session {
    /// Verify through C_VerifySignatureInit and the selected single/multipart
    /// family. Signature, input and parameters remain owned through completion.
    /// An empty multipart list makes no Update calls. Errors remain native;
    /// no signature-length policy, implicit prehash, or fallback is added.
    pub fn verify_native_at_init(
        &self,
        key: &NativeObjectRef,
        parameters: NativeVerificationParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        signature: &[u8],
        limits: InputLimits,
        authentication: Option<ContextAuthentication>,
    ) -> Result<()> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.verify_native_at_init_with_diagnostics(
            key,
            parameters,
            route,
            parts,
            signature,
            limits,
            authentication,
            &mut extension_diagnostics,
        )
    }

    // Internal callers supply their outer publication owner; no helper
    // return may release the credit of an error still being projected.
    pub(crate) fn verify_native_at_init_with_diagnostics(
        &self,
        key: &NativeObjectRef,
        parameters: NativeVerificationParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        signature: &[u8],
        limits: InputLimits,
        authentication: Option<ContextAuthentication>,
        extension_diagnostics: &mut crate::mechanism_extension::operation::Invocation,
    ) -> Result<()> {
        let (input, function) = match route {
            MessageRoute::Single => {
                if parts.len() != 1 {
                    return Err(Error::Rejected(crate::RejectionReason::NativeSignature(
                        crate::NativeSignatureRejection::SingleVerificationRequiresOneInput,
                    )));
                }
                (
                    ExtensionInput::VerifySignature {
                        key,
                        input: parts[0],
                        signature,
                    },
                    ExtensionOperation::VerifySignature,
                )
            }
            MessageRoute::Multipart => (
                ExtensionInput::VerifySignatureMultipart {
                    key,
                    parts,
                    signature,
                },
                ExtensionOperation::VerifySignatureMultipart,
            ),
        };
        let result = match parameters {
            NativeVerificationParameters::Signature(parameters) => {
                crate::native_signature::with_parameters(self, parameters, function, |request| {
                    operation::execute(
                        self,
                        request,
                        input,
                        limits,
                        authentication,
                        extension_diagnostics,
                    )
                })
            }
            NativeVerificationParameters::Mac(parameters) => {
                crate::native_mac::with_parameters(self, parameters, function, |request| {
                    operation::execute(
                        self,
                        request,
                        input,
                        limits,
                        authentication,
                        extension_diagnostics,
                    )
                })
            }
            NativeVerificationParameters::Cms(parameters) => {
                crate::native_protocol::cms(self, parameters, function, |request, sources| {
                    operation::execute_with_sources(
                        self,
                        request,
                        input,
                        limits,
                        authentication,
                        1,
                        sources,
                        extension_diagnostics,
                    )
                })
            }
            NativeVerificationParameters::Kip(parameters) => crate::native_protocol::kip(
                self,
                parameters,
                fe11_sys::CKM_KIP_MAC,
                function,
                |request, sources| {
                    operation::execute_with_sources(
                        self,
                        request,
                        input,
                        limits,
                        authentication,
                        1,
                        sources,
                        extension_diagnostics,
                    )
                },
            ),
            NativeVerificationParameters::Otp {
                algorithm,
                parameters,
                limits: parameter_limits,
            } => crate::native_otp::perform(
                self,
                algorithm,
                parameters,
                parameter_limits,
                input,
                function,
                limits,
                authentication,
                extension_diagnostics,
            ),
        };
        result.map(|_| ())
    }
}
impl crate::AdvancedSession {
    /// Synchronous signature-bearing verification through the common owner.
    pub fn verify_native_at_init(
        &self,
        key: &NativeObjectRef,
        parameters: NativeVerificationParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        signature: &[u8],
        limits: InputLimits,
        authentication: Option<ContextAuthentication>,
    ) -> Result<()> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.session.verify_native_at_init_with_diagnostics(
            key,
            parameters,
            route,
            parts,
            signature,
            limits,
            authentication,
            &mut extension_diagnostics,
        )
    }
}
