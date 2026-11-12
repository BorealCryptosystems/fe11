// SPDX-License-Identifier: Apache-2.0
//! Expose native signature, verification and recovery-signature entry points.
//! Selected mechanisms and diagnostic variants share the same operation semantics.

use super::*;

impl Session {
    /// Sign exact caller input using a managed native key. No SPKI profile,
    /// local hash, RSA/DSA mathematics, digest substitution or DER conversion is
    /// required. Single requires one supplied fragment; Multipart preserves each
    /// Update boundary and lets the module reject unsupported combinations.
    /// HSS/XMSS observations are invalidated before dispatch and never revived.
    pub fn sign_native(
        &self,
        key: &NativeObjectRef,
        parameters: NativeSignatureParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
        output_capacity: usize,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<NativeSignature> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.sign_native_with_diagnostics(
            key,
            parameters,
            route,
            parts,
            limits,
            output_capacity,
            authentication,
            &mut extension_diagnostics,
        )
    }

    // Internal callers supply their outer publication owner; no helper
    // return may release the credit of an error still being projected.
    pub(crate) fn sign_native_with_diagnostics(
        &self,
        key: &NativeObjectRef,
        parameters: NativeSignatureParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
        output_capacity: usize,
        authentication: Option<crate::ContextAuthentication>,
        extension_diagnostics: &mut crate::mechanism_extension::operation::Invocation,
    ) -> Result<NativeSignature> {
        let mechanism = parameters.mechanism_number();
        let (input, operation) = match route {
            MessageRoute::Single => {
                if parts.len() != 1 {
                    return Err(Error::Rejected(crate::RejectionReason::NativeSignature(
                        crate::NativeSignatureRejection::SinglePartSignatureRequiresOneInput,
                    )));
                }
                (
                    ExtensionInput::Sign {
                        key,
                        input: parts[0],
                        output_capacity,
                    },
                    ExtensionOperation::Sign,
                )
            }
            MessageRoute::Multipart => (
                ExtensionInput::SignMultipart {
                    key,
                    parts,
                    output_capacity,
                },
                ExtensionOperation::SignMultipart,
            ),
        };
        let result = perform(
            self,
            parameters,
            input,
            operation,
            limits,
            authentication,
            extension_diagnostics,
        )?;
        Ok(NativeSignature {
            bytes: result.bytes,
            mechanism,
        })
    }

    /// Native verification; exact signature bytes and native refusal codes are
    /// retained. In particular, short ECDSA signatures are not padded locally.
    pub fn verify_native(
        &self,
        key: &NativeObjectRef,
        parameters: NativeSignatureParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        signature: &[u8],
        limits: InputLimits,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<()> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.verify_native_with_diagnostics(
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
    pub(crate) fn verify_native_with_diagnostics(
        &self,
        key: &NativeObjectRef,
        parameters: NativeSignatureParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        signature: &[u8],
        limits: InputLimits,
        authentication: Option<crate::ContextAuthentication>,
        extension_diagnostics: &mut crate::mechanism_extension::operation::Invocation,
    ) -> Result<()> {
        let (input, operation) = match route {
            MessageRoute::Single => {
                if parts.len() != 1 {
                    return Err(Error::Rejected(crate::RejectionReason::NativeSignature(
                        crate::NativeSignatureRejection::SinglePartVerificationRequiresOneInput,
                    )));
                }
                (
                    ExtensionInput::Verify {
                        key,
                        input: parts[0],
                        signature,
                    },
                    ExtensionOperation::Verify,
                )
            }
            MessageRoute::Multipart => (
                ExtensionInput::VerifyMultipart {
                    key,
                    parts,
                    signature,
                },
                ExtensionOperation::VerifyMultipart,
            ),
        };
        perform(
            self,
            parameters,
            input,
            operation,
            limits,
            authentication,
            extension_diagnostics,
        )
        .map(|_| ())
    }

    /// Verify a signature through C_VerifySignatureInit, passing the expected
    /// bytes at Init. Single and Multipart retain their exact native calls;
    /// no fallback to C_VerifyInit or local comparison is performed.
    /// The module decides whether this standard mechanism supports the route.
    pub fn verify_signature_native(
        &self,
        key: &NativeObjectRef,
        parameters: NativeSignatureParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        signature: &[u8],
        limits: InputLimits,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<()> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        let (input, operation) = match route {
            MessageRoute::Single => {
                if parts.len() != 1 {
                    return Err(Error::Rejected(crate::RejectionReason::NativeSignature(
                        crate::NativeSignatureRejection::SinglePartVerificationRequiresOneInput,
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
        perform(
            self,
            parameters,
            input,
            operation,
            limits,
            authentication,
            &mut extension_diagnostics,
        )
        .map(|_| ())
    }

    /// Exact C_SignRecover route with caller-sized output; never substitutes Sign.
    pub fn sign_native_recover(
        &self,
        key: &NativeObjectRef,
        parameters: NativeSignatureParameters<'_>,
        message: &[u8],
        limits: InputLimits,
        output_capacity: usize,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<NativeSignature> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.sign_native_recover_with_diagnostics(
            key,
            parameters,
            message,
            limits,
            output_capacity,
            authentication,
            &mut extension_diagnostics,
        )
    }

    // Internal callers supply their outer publication owner; no helper
    // return may release the credit of an error still being projected.
    pub(crate) fn sign_native_recover_with_diagnostics(
        &self,
        key: &NativeObjectRef,
        parameters: NativeSignatureParameters<'_>,
        message: &[u8],
        limits: InputLimits,
        output_capacity: usize,
        authentication: Option<crate::ContextAuthentication>,
        extension_diagnostics: &mut crate::mechanism_extension::operation::Invocation,
    ) -> Result<NativeSignature> {
        let mechanism = parameters.mechanism_number();
        let result = perform(
            self,
            parameters,
            ExtensionInput::SignRecover {
                key,
                input: message,
                output_capacity,
            },
            ExtensionOperation::SignRecover,
            limits,
            authentication,
            extension_diagnostics,
        )?;
        Ok(NativeSignature {
            bytes: result.bytes,
            mechanism,
        })
    }

    /// Exact C_VerifyRecover route; publishes recovered bytes only after success.
    pub fn verify_native_recover(
        &self,
        key: &NativeObjectRef,
        parameters: NativeSignatureParameters<'_>,
        signature: &[u8],
        limits: InputLimits,
        output_capacity: usize,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<NativeRecoveredMessage> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.verify_native_recover_with_diagnostics(
            key,
            parameters,
            signature,
            limits,
            output_capacity,
            authentication,
            &mut extension_diagnostics,
        )
    }

    // Internal callers supply their outer publication owner; no helper
    // return may release the credit of an error still being projected.
    pub(crate) fn verify_native_recover_with_diagnostics(
        &self,
        key: &NativeObjectRef,
        parameters: NativeSignatureParameters<'_>,
        signature: &[u8],
        limits: InputLimits,
        output_capacity: usize,
        authentication: Option<crate::ContextAuthentication>,
        extension_diagnostics: &mut crate::mechanism_extension::operation::Invocation,
    ) -> Result<NativeRecoveredMessage> {
        let mechanism = parameters.mechanism_number();
        let result = perform(
            self,
            parameters,
            ExtensionInput::VerifyRecover {
                key,
                signature,
                output_capacity,
            },
            ExtensionOperation::VerifyRecover,
            limits,
            authentication,
            extension_diagnostics,
        )?;
        Ok(NativeRecoveredMessage {
            bytes: result.bytes,
            mechanism,
        })
    }
}

impl crate::AdvancedSession {
    /// Synchronous native signing through the common owner; no native asynchronous mode protocol.
    pub fn sign_native(
        &self,
        key: &NativeObjectRef,
        parameters: NativeSignatureParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
        output_capacity: usize,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<NativeSignature> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.session.sign_native_with_diagnostics(
            key,
            parameters,
            route,
            parts,
            limits,
            output_capacity,
            authentication,
            &mut extension_diagnostics,
        )
    }

    /// Synchronous native verification through the common owner.
    pub fn verify_native(
        &self,
        key: &NativeObjectRef,
        parameters: NativeSignatureParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        signature: &[u8],
        limits: InputLimits,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<()> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.session.verify_native_with_diagnostics(
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

    /// Verify through C_VerifySignature with the selected validation capture.
    /// Ok reports native verification success; Some contains the requested
    /// observations, while None means capture was disabled. Flags do not assert
    /// certification. Exact native refusals remain errors, without route fallback.
    /// This synchronous facade preserves context authentication and input chunks.
    pub fn verify_signature_native(
        &self,
        key: &NativeObjectRef,
        parameters: NativeSignatureParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        signature: &[u8],
        limits: InputLimits,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<Option<crate::ValidationReport>> {
        let mut signature_diagnostics = crate::advanced::signature::batch::Invocation::default();
        let (input, operation) = match route {
            MessageRoute::Single => {
                if parts.len() != 1 {
                    return Err(Error::Rejected(crate::RejectionReason::NativeSignature(
                        crate::NativeSignatureRejection::SinglePartVerificationRequiresOneInput,
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
        with_parameters(&self.session, parameters, operation, |request| {
            self.execute_signature_batch(
                request,
                input,
                limits,
                authentication,
                &mut signature_diagnostics,
            )
            .map(|(_result, report)| report)
        })
    }

    /// Synchronous signature with recovery; no replacement mechanism.
    pub fn sign_native_recover(
        &self,
        key: &NativeObjectRef,
        parameters: NativeSignatureParameters<'_>,
        message: &[u8],
        limits: InputLimits,
        output_capacity: usize,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<NativeSignature> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.session.sign_native_recover_with_diagnostics(
            key,
            parameters,
            message,
            limits,
            output_capacity,
            authentication,
            &mut extension_diagnostics,
        )
    }

    /// Synchronous verification with message recovery.
    pub fn verify_native_recover(
        &self,
        key: &NativeObjectRef,
        parameters: NativeSignatureParameters<'_>,
        signature: &[u8],
        limits: InputLimits,
        output_capacity: usize,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<NativeRecoveredMessage> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.session.verify_native_recover_with_diagnostics(
            key,
            parameters,
            signature,
            limits,
            output_capacity,
            authentication,
            &mut extension_diagnostics,
        )
    }
}
