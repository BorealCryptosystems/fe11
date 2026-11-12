// SPDX-License-Identifier: Apache-2.0
//! Expose native KIP derivation and transport with explicit parameter selections.
//! Output-bearing calls retain their diagnostic and creation ownership.

use super::*;

impl Session {
    /// CT-KIP derivation with an exact template, optional auxiliary key and seed.
    pub fn derive_native_kip(
        &self,
        base: &crate::NativeObjectRef,
        parameters: NativeKipParameters<'_>,
        template: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<crate::NativeObjectView>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.derive_native_kip_selected(base, parameters, template, &mut diagnostics)
            .map(|outcome| outcome.map(|created| created.object))
    }

    /// CT-KIP derivation retaining parameter-layout provenance, including a
    /// caller-asserted nested ABI. Native success does not certify that ABI.
    pub fn derive_native_kip_with_output(
        &self,
        base: &crate::NativeObjectRef,
        parameters: NativeKipParameters<'_>,
        template: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<crate::NativeDerivedObject>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.derive_native_kip_selected(base, parameters, template, &mut diagnostics)
    }

    pub(super) fn derive_native_kip_selected(
        &self,
        base: &crate::NativeObjectRef,
        parameters: NativeKipParameters<'_>,
        template: GenerationTemplate<'_>,
        diagnostics: &mut crate::error::PreparedCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<crate::NativeDerivedObject>> {
        kip(
            self,
            parameters,
            CKM_KIP_DERIVE,
            ExtensionOperation::DeriveKey,
            |request, sources| {
                self.derive_native_recipe(
                    base,
                    request,
                    ManagedClass::SecretKey,
                    template,
                    sources,
                    diagnostics,
                )
            },
        )
    }

    /// CT-KIP wrapping; no local cipher or encryption fallback is performed.
    pub fn wrap_native_kip(
        &self,
        wrapping_key: &crate::NativeObjectRef,
        target: &crate::NativeObjectRef,
        parameters: NativeKipParameters<'_>,
        output_capacity: usize,
    ) -> Result<ExtensionResult> {
        let mut diagnostic = None;
        self.wrap_native_kip_with_diagnostic(
            wrapping_key,
            target,
            parameters,
            output_capacity,
            &mut diagnostic,
        )
    }

    pub(super) fn wrap_native_kip_with_diagnostic(
        &self,
        wrapping_key: &crate::NativeObjectRef,
        target: &crate::NativeObjectRef,
        parameters: NativeKipParameters<'_>,
        output_capacity: usize,
        diagnostic: &mut Option<crate::symmetric::memory::Credit>,
    ) -> Result<ExtensionResult> {
        let fixed_prefix = match &parameters.mechanism {
            NativeNestedMechanism::Transport(inner) => {
                let parent_blocks = if parameters.seed.is_some() { 2 } else { 1 };
                transport::fixed_prefix::from_transport(inner, parent_blocks + 1)?
            }
            _ => None,
        };
        kip(
            self,
            parameters,
            CKM_KIP_WRAP,
            ExtensionOperation::WrapKey,
            |request, sources| {
                transport::wrap_with_fixed_prefix(
                    self,
                    request,
                    wrapping_key,
                    Some(target),
                    output_capacity,
                    sources,
                    fixed_prefix,
                    diagnostic,
                )
            },
        )
    }

    /// CT-KIP unwrapping through common creation, observation and cleanup.
    pub fn unwrap_native_kip(
        &self,
        key: &crate::NativeObjectRef,
        blob: &[u8],
        parameters: NativeKipParameters<'_>,
        template: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<NativeUnwrappedObject>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.unwrap_native_kip_selected(key, blob, parameters, template, &mut diagnostics)
    }

    pub(super) fn unwrap_native_kip_selected(
        &self,
        key: &crate::NativeObjectRef,
        blob: &[u8],
        parameters: NativeKipParameters<'_>,
        template: GenerationTemplate<'_>,
        diagnostics: &mut crate::error::PreparedCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<NativeUnwrappedObject>> {
        kip(
            self,
            parameters,
            CKM_KIP_WRAP,
            ExtensionOperation::UnwrapKey,
            |request, sources| {
                self.unwrap_key_with_sources(
                    key,
                    blob,
                    request,
                    ManagedClass::SecretKey,
                    template,
                    sources,
                    diagnostics,
                )
            },
        )
    }

    /// CT-KIP MAC: requested_bytes is the desired MAC length passed in
    /// pulSignatureLen, not a locally inferred strength or default length.
    pub fn compute_native_kip_mac(
        &self,
        key: &crate::NativeObjectRef,
        parameters: NativeKipParameters<'_>,
        input: &[u8],
        limits: InputLimits,
        requested_bytes: usize,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<ExtensionResult> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.compute_native_kip_mac_with_diagnostics(
            key,
            parameters,
            input,
            limits,
            requested_bytes,
            authentication,
            &mut extension_diagnostics,
        )
    }

    // Internal callers supply their outer publication owner; no helper
    // return may release the credit of an error still being projected.
    pub(crate) fn compute_native_kip_mac_with_diagnostics(
        &self,
        key: &crate::NativeObjectRef,
        parameters: NativeKipParameters<'_>,
        input: &[u8],
        limits: InputLimits,
        requested_bytes: usize,
        authentication: Option<crate::ContextAuthentication>,
        extension_diagnostics: &mut crate::mechanism_extension::operation::Invocation,
    ) -> Result<ExtensionResult> {
        kip(
            self,
            parameters,
            CKM_KIP_MAC,
            ExtensionOperation::Sign,
            |request, sources| {
                operation::execute_with_sources_and_publish(
                    self,
                    request,
                    ExtensionInput::Sign {
                        key,
                        input,
                        output_capacity: requested_bytes,
                    },
                    limits,
                    authentication,
                    1,
                    sources,
                    |result| {
                        if result.as_bytes().len() == requested_bytes {
                            Ok(result)
                        } else {
                            Err(Error::Rejected(
                                crate::RejectionReason::NativeProtocols(crate::NativeProtocolsRejection::NativeKipMacLengthDiffersFromRequestedLength),
                            ))
                        }
                    },
                    extension_diagnostics,
                )
            },
        )
    }

    /// CT-KIP verification, preserving the native refusal code.
    pub fn verify_native_kip_mac(
        &self,
        key: &crate::NativeObjectRef,
        parameters: NativeKipParameters<'_>,
        input: &[u8],
        signature: &[u8],
        limits: InputLimits,
    ) -> Result<()> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.verify_native_kip_mac_with_diagnostics(
            key,
            parameters,
            input,
            signature,
            limits,
            &mut extension_diagnostics,
        )
    }

    // Internal callers supply their outer publication owner; no helper
    // return may release the credit of an error still being projected.
    pub(crate) fn verify_native_kip_mac_with_diagnostics(
        &self,
        key: &crate::NativeObjectRef,
        parameters: NativeKipParameters<'_>,
        input: &[u8],
        signature: &[u8],
        limits: InputLimits,
        extension_diagnostics: &mut crate::mechanism_extension::operation::Invocation,
    ) -> Result<()> {
        kip(
            self,
            parameters,
            CKM_KIP_MAC,
            ExtensionOperation::Verify,
            |request, sources| {
                operation::execute_with_sources(
                    self,
                    request,
                    ExtensionInput::Verify {
                        key,
                        input,
                        signature,
                    },
                    limits,
                    None,
                    1,
                    sources,
                    extension_diagnostics,
                )
                .map(|_| ())
            },
        )
    }

    /// CMS signing returns the native DER SignerInfo bytes. Exact input and
    /// Update boundaries are preserved; Fe11 performs no prehash or DER rewrite.
    pub fn sign_native_cms(
        &self,
        key: &crate::NativeObjectRef,
        parameters: NativeCmsParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
        capacity: usize,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<ExtensionResult> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.sign_native_cms_with_diagnostics(
            key,
            parameters,
            route,
            parts,
            limits,
            capacity,
            authentication,
            &mut extension_diagnostics,
        )
    }

    // Internal callers supply their outer publication owner; no helper
    // return may release the credit of an error still being projected.
    pub(crate) fn sign_native_cms_with_diagnostics(
        &self,
        key: &crate::NativeObjectRef,
        parameters: NativeCmsParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
        capacity: usize,
        authentication: Option<crate::ContextAuthentication>,
        extension_diagnostics: &mut crate::mechanism_extension::operation::Invocation,
    ) -> Result<ExtensionResult> {
        let (input, kind) = match route {
            MessageRoute::Single => {
                if parts.len() != 1 {
                    return Err(Error::Rejected(crate::RejectionReason::NativeProtocols(
                        crate::NativeProtocolsRejection::SingleCmsCallRequiresOneInput,
                    )));
                }
                (
                    ExtensionInput::Sign {
                        key,
                        input: parts[0],
                        output_capacity: capacity,
                    },
                    ExtensionOperation::Sign,
                )
            }
            MessageRoute::Multipart => (
                ExtensionInput::SignMultipart {
                    key,
                    parts,
                    output_capacity: capacity,
                },
                ExtensionOperation::SignMultipart,
            ),
        };
        cms(self, parameters, kind, |request, sources| {
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

    /// CMS sign-recover route, retaining the native output without ASN.1 rewriting.
    pub fn sign_native_cms_recover(
        &self,
        key: &crate::NativeObjectRef,
        parameters: NativeCmsParameters<'_>,
        input: &[u8],
        limits: InputLimits,
        capacity: usize,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<ExtensionResult> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.sign_native_cms_recover_with_diagnostics(
            key,
            parameters,
            input,
            limits,
            capacity,
            authentication,
            &mut extension_diagnostics,
        )
    }

    // Internal callers supply their outer publication owner; no helper
    // return may release the credit of an error still being projected.
    pub(crate) fn sign_native_cms_recover_with_diagnostics(
        &self,
        key: &crate::NativeObjectRef,
        parameters: NativeCmsParameters<'_>,
        input: &[u8],
        limits: InputLimits,
        capacity: usize,
        authentication: Option<crate::ContextAuthentication>,
        extension_diagnostics: &mut crate::mechanism_extension::operation::Invocation,
    ) -> Result<ExtensionResult> {
        cms(
            self,
            parameters,
            ExtensionOperation::SignRecover,
            |request, sources| {
                operation::execute_with_sources(
                    self,
                    request,
                    ExtensionInput::SignRecover {
                        key,
                        input,
                        output_capacity: capacity,
                    },
                    limits,
                    authentication,
                    1,
                    sources,
                    extension_diagnostics,
                )
            },
        )
    }

    /// CMS native verification. No local certificate, signature or content policy.
    pub fn verify_native_cms(
        &self,
        key: &crate::NativeObjectRef,
        parameters: NativeCmsParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        signature: &[u8],
        limits: InputLimits,
    ) -> Result<()> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.verify_native_cms_with_diagnostics(
            key,
            parameters,
            route,
            parts,
            signature,
            limits,
            &mut extension_diagnostics,
        )
    }

    // Internal callers supply their outer publication owner; no helper
    // return may release the credit of an error still being projected.
    pub(crate) fn verify_native_cms_with_diagnostics(
        &self,
        key: &crate::NativeObjectRef,
        parameters: NativeCmsParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        signature: &[u8],
        limits: InputLimits,
        extension_diagnostics: &mut crate::mechanism_extension::operation::Invocation,
    ) -> Result<()> {
        let (input, kind) = match route {
            MessageRoute::Single => {
                if parts.len() != 1 {
                    return Err(Error::Rejected(crate::RejectionReason::NativeProtocols(
                        crate::NativeProtocolsRejection::SingleCmsCallRequiresOneInput,
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
        cms(self, parameters, kind, |request, sources| {
            operation::execute_with_sources(
                self,
                request,
                input,
                limits,
                None,
                1,
                sources,
                extension_diagnostics,
            )
        })
        .map(|_| ())
    }

    /// CMS native verify-recover, with no local reinterpretation of recovered bytes.
    pub fn verify_native_cms_recover(
        &self,
        key: &crate::NativeObjectRef,
        parameters: NativeCmsParameters<'_>,
        signature: &[u8],
        limits: InputLimits,
        capacity: usize,
    ) -> Result<ExtensionResult> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.verify_native_cms_recover_with_diagnostics(
            key,
            parameters,
            signature,
            limits,
            capacity,
            &mut extension_diagnostics,
        )
    }

    // Internal callers supply their outer publication owner; no helper
    // return may release the credit of an error still being projected.
    pub(crate) fn verify_native_cms_recover_with_diagnostics(
        &self,
        key: &crate::NativeObjectRef,
        parameters: NativeCmsParameters<'_>,
        signature: &[u8],
        limits: InputLimits,
        capacity: usize,
        extension_diagnostics: &mut crate::mechanism_extension::operation::Invocation,
    ) -> Result<ExtensionResult> {
        cms(
            self,
            parameters,
            ExtensionOperation::VerifyRecover,
            |request, sources| {
                operation::execute_with_sources(
                    self,
                    request,
                    ExtensionInput::VerifyRecover {
                        key,
                        signature,
                        output_capacity: capacity,
                    },
                    limits,
                    None,
                    1,
                    sources,
                    extension_diagnostics,
                )
            },
        )
    }
}

impl crate::AdvancedSession {
    /// Synchronous CT-KIP derivation retaining layout provenance.
    pub fn derive_native_kip_with_output(
        &self,
        base: &crate::NativeObjectRef,
        parameters: NativeKipParameters<'_>,
        template: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<crate::NativeDerivedObject>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.session
            .derive_native_kip_selected(base, parameters, template, &mut diagnostics)
    }

    /// Synchronous derive native kip through the common Session owner.
    pub fn derive_native_kip(
        &self,
        base: &crate::NativeObjectRef,
        parameters: NativeKipParameters<'_>,
        template: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<crate::NativeObjectView>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.session
            .derive_native_kip_selected(base, parameters, template, &mut diagnostics)
            .map(|outcome| outcome.map(|created| created.object))
    }

    /// Synchronous wrap native kip through the common Session owner.
    pub fn wrap_native_kip(
        &self,
        wrapping_key: &crate::NativeObjectRef,
        target: &crate::NativeObjectRef,
        parameters: NativeKipParameters<'_>,
        output_capacity: usize,
    ) -> Result<ExtensionResult> {
        let mut diagnostic = None;
        self.session.wrap_native_kip_with_diagnostic(
            wrapping_key,
            target,
            parameters,
            output_capacity,
            &mut diagnostic,
        )
    }

    /// Synchronous unwrap native kip through the common Session owner.
    pub fn unwrap_native_kip(
        &self,
        key: &crate::NativeObjectRef,
        blob: &[u8],
        parameters: NativeKipParameters<'_>,
        template: GenerationTemplate<'_>,
    ) -> Result<crate::CreatedObjects<NativeUnwrappedObject>> {
        let mut diagnostics = crate::error::PreparedCreationDiagnostics::default();
        self.session
            .unwrap_native_kip_selected(key, blob, parameters, template, &mut diagnostics)
    }

    /// Synchronous compute native kip mac through the common Session owner.
    pub fn compute_native_kip_mac(
        &self,
        key: &crate::NativeObjectRef,
        parameters: NativeKipParameters<'_>,
        input: &[u8],
        limits: InputLimits,
        requested_bytes: usize,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<ExtensionResult> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.session.compute_native_kip_mac_with_diagnostics(
            key,
            parameters,
            input,
            limits,
            requested_bytes,
            authentication,
            &mut extension_diagnostics,
        )
    }

    /// Synchronous verify native kip mac through the common Session owner.
    pub fn verify_native_kip_mac(
        &self,
        key: &crate::NativeObjectRef,
        parameters: NativeKipParameters<'_>,
        input: &[u8],
        signature: &[u8],
        limits: InputLimits,
    ) -> Result<()> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.session.verify_native_kip_mac_with_diagnostics(
            key,
            parameters,
            input,
            signature,
            limits,
            &mut extension_diagnostics,
        )
    }

    /// Synchronous sign native cms through the common Session owner.
    pub fn sign_native_cms(
        &self,
        key: &crate::NativeObjectRef,
        parameters: NativeCmsParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
        capacity: usize,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<ExtensionResult> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.session.sign_native_cms_with_diagnostics(
            key,
            parameters,
            route,
            parts,
            limits,
            capacity,
            authentication,
            &mut extension_diagnostics,
        )
    }

    /// Synchronous sign native cms recover through the common Session owner.
    pub fn sign_native_cms_recover(
        &self,
        key: &crate::NativeObjectRef,
        parameters: NativeCmsParameters<'_>,
        input: &[u8],
        limits: InputLimits,
        capacity: usize,
        authentication: Option<crate::ContextAuthentication>,
    ) -> Result<ExtensionResult> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.session.sign_native_cms_recover_with_diagnostics(
            key,
            parameters,
            input,
            limits,
            capacity,
            authentication,
            &mut extension_diagnostics,
        )
    }

    /// Synchronous verify native cms through the common Session owner.
    pub fn verify_native_cms(
        &self,
        key: &crate::NativeObjectRef,
        parameters: NativeCmsParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        signature: &[u8],
        limits: InputLimits,
    ) -> Result<()> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.session.verify_native_cms_with_diagnostics(
            key,
            parameters,
            route,
            parts,
            signature,
            limits,
            &mut extension_diagnostics,
        )
    }

    /// Synchronous verify native cms recover through the common Session owner.
    pub fn verify_native_cms_recover(
        &self,
        key: &crate::NativeObjectRef,
        parameters: NativeCmsParameters<'_>,
        signature: &[u8],
        limits: InputLimits,
        capacity: usize,
    ) -> Result<ExtensionResult> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.session.verify_native_cms_recover_with_diagnostics(
            key,
            parameters,
            signature,
            limits,
            capacity,
            &mut extension_diagnostics,
        )
    }
}
