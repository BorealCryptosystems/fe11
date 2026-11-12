// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::{InputLimits, Session, Verification};
#[path = "aead_selection.rs"]
mod aead_selection;
use aead_selection::{AeadCompletion, OwnedAeadSelection};

impl Session {
    /// Native one-part authenticated encryption. No nonce-strategy fallback.
    pub fn encrypt_aead(
        &self,
        key: &SymmetricKey,
        parameters: AeadParameters<'_>,
        message: &[u8],
        limits: InputLimits,
    ) -> Result<AeadCiphertext> {
        let mut message_diagnostics = None;
        let mut retirement = crate::advanced::PollDiagnostics::default();
        self.symmetric_aead(
            key.view(),
            parameters,
            &[message],
            limits,
            false,
            false,
            &mut retirement,
            &mut message_diagnostics,
        )
    }
    /// Encrypt one native GCM message with an explicitly selected Init layout.
    /// Init, message and Final form one sequence. The same owned IV/tag targets
    /// are retained throughout; Init output is never published. Both supplied
    /// and generated IV requests are supported without probing or fallback.
    pub fn encrypt_gcm_message(
        &self,
        key: &SymmetricKey,
        parameters: AeadParameters<'_>,
        message: &[u8],
        limits: InputLimits,
        init: MessageInitLayout,
    ) -> Result<AeadCiphertext> {
        let mut message_diagnostics = None;
        let mut retirement = crate::advanced::PollDiagnostics::default();
        self.symmetric_aead_route(
            key.view(),
            parameters,
            &[message],
            limits,
            false,
            false,
            Some(init),
            &mut retirement,
            &mut message_diagnostics,
        )
    }
    /// Native Update/Final encryption of already available fragments.
    pub fn encrypt_aead_multipart(
        &self,
        key: &SymmetricKey,
        parameters: AeadParameters<'_>,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<AeadCiphertext> {
        let mut message_diagnostics = None;
        let mut retirement = crate::advanced::PollDiagnostics::default();
        self.symmetric_aead(
            key.view(),
            parameters,
            parts,
            limits,
            true,
            false,
            &mut retirement,
            &mut message_diagnostics,
        )
    }
    /// Native authenticated decryption. A bad tag returns no plaintext.
    pub fn decrypt_aead(
        &self,
        key: &SymmetricKey,
        parameters: AeadParameters<'_>,
        ciphertext: &[u8],
        limits: InputLimits,
    ) -> Result<AeadPlaintext> {
        let mut message_diagnostics = None;
        let mut retirement = crate::advanced::PollDiagnostics::default();
        self.symmetric_aead(
            key.view(),
            parameters,
            &[ciphertext],
            limits,
            false,
            true,
            &mut retirement,
            &mut message_diagnostics,
        )
        .map(AeadCiphertext::into_plaintext)
    }
    /// Real native Update/Final; intermediate plaintext remains internal and erasable.
    pub fn decrypt_aead_multipart(
        &self,
        key: &SymmetricKey,
        parameters: AeadParameters<'_>,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<AeadPlaintext> {
        let mut message_diagnostics = None;
        let mut retirement = crate::advanced::PollDiagnostics::default();
        self.symmetric_aead(
            key.view(),
            parameters,
            parts,
            limits,
            true,
            true,
            &mut retirement,
            &mut message_diagnostics,
        )
        .map(AeadCiphertext::into_plaintext)
    }
    pub(crate) fn symmetric_aead(
        &self,
        key: SymmetricKeyView<'_>,
        parameters: AeadParameters<'_>,
        parts: &[&[u8]],
        limits: InputLimits,
        multipart: bool,
        decrypt: bool,
        retirement: &mut crate::advanced::PollDiagnostics,
        message_diagnostics: &mut Option<crate::advanced::AeadMessageDiagnostics>,
    ) -> Result<AeadCiphertext> {
        self.symmetric_aead_route(
            key,
            parameters,
            parts,
            limits,
            multipart,
            decrypt,
            None,
            retirement,
            message_diagnostics,
        )
    }
    fn symmetric_aead_route(
        &self,
        key: SymmetricKeyView<'_>,
        parameters: AeadParameters<'_>,
        parts: &[&[u8]],
        limits: InputLimits,
        multipart: bool,
        decrypt: bool,
        message_init: Option<MessageInitLayout>,
        retirement: &mut crate::advanced::PollDiagnostics,
        message_diagnostics: &mut Option<crate::advanced::AeadMessageDiagnostics>,
    ) -> Result<AeadCiphertext> {
        self.owned_aead_route(
            key.managed,
            OwnedAeadSelection::Legacy {
                algorithm: key.algorithm,
                nonce: parameters.nonce,
            },
            parameters.aad,
            parts,
            limits,
            multipart,
            decrypt,
            message_init,
            retirement,
            message_diagnostics,
        )?
        .into_legacy()
    }
    pub(super) fn stream_aead(
        &self,
        key: &ManagedObjectRef,
        parameters: StreamAeadParameters<'_>,
        parts: &[&[u8]],
        route: crate::MessageRoute,
        limits: InputLimits,
        decrypt: bool,
        retirement: &mut crate::advanced::PollDiagnostics,
        message_diagnostics: &mut Option<crate::advanced::AeadMessageDiagnostics>,
    ) -> Result<StreamAeadEncrypted> {
        if key.identity.class != crate::ManagedClass::SecretKey || key.identity.key_type.is_none() {
            return Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::AeadRequiresAnAdmittedSecretKey,
                ),
            ));
        }
        self.owned_aead_route(
            key,
            OwnedAeadSelection::Stream(parameters.nonce),
            parameters.aad,
            parts,
            limits,
            route == crate::MessageRoute::Multipart,
            decrypt,
            None,
            retirement,
            message_diagnostics,
        )?
        .into_stream()
    }
    fn owned_aead_route(
        &self,
        key: &ManagedObjectRef,
        selection: OwnedAeadSelection,
        aad: &[u8],
        parts: &[&[u8]],
        limits: InputLimits,
        multipart: bool,
        decrypt: bool,
        message_init: Option<MessageInitLayout>,
        retirement: &mut crate::advanced::PollDiagnostics,
        message_diagnostics: &mut Option<crate::advanced::AeadMessageDiagnostics>,
    ) -> Result<AeadCompletion> {
        let generated = selection.generated();
        let message_route = generated || message_init.is_some();
        selection.validate(aad.len(), message_route)?;
        let tag_bytes = selection.tag_bytes()?;
        let input_len = input_size(
            self.inner.crypto_options.limits,
            limits,
            parts,
            aad,
            if decrypt { tag_bytes } else { 0 },
        )?;
        if decrypt && input_len < tag_bytes {
            return Err(Error::InvalidCiphertext);
        }
        if message_init.is_some() && (decrypt || multipart || !selection.gcm_message_capable()) {
            return Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::GcmMessageEncryptionRouteRequired,
                ),
            ));
        }
        if generated && (decrypt || multipart || !selection.gcm_message_capable()) {
            return Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::NativeNonceRoute,
                ),
            ));
        }
        if !message_route {
            let parameters = match &selection {
                OwnedAeadSelection::Stream(nonce) => {
                    ClassicAeadParameters::Stream { nonce: *nonce, aad }
                }
                OwnedAeadSelection::Legacy {
                    algorithm: SymmetricAlgorithm::ChaCha20,
                    nonce,
                } => {
                    let nonce: [u8; 12] = nonce.iv().try_into().map_err(|_| {
                        Error::Rejected(crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::IetfAeadNonceWidth,
                        ))
                    })?;
                    match self.inner.chacha_nonce_length_encoding {
                        ChaChaNonceLengthEncoding::Bits => ClassicAeadParameters::Stream {
                            nonce: StreamAeadNonce::ChaCha20Ietf(nonce),
                            aad,
                        },
                        ChaChaNonceLengthEncoding::BytesCompatibility => {
                            ClassicAeadParameters::ChaCha20IetfBytes { nonce, aad }
                        }
                    }
                }
                OwnedAeadSelection::Legacy { nonce, .. } => ClassicAeadParameters::Gcm {
                    iv: nonce.iv(),
                    aad,
                    tag_bits: nonce.tag_bits(),
                },
            };
            let retained = std::mem::size_of::<OwnedAeadSelection>()
                .checked_add(selection.retained_bytes())
                .ok_or(Error::Rejected(
                    crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::AeadRetainedSelectionAccounting,
                    ),
                ))?;
            let result = self.classic_aead_retained(
                key,
                parameters,
                if multipart {
                    crate::MessageRoute::Multipart
                } else {
                    crate::MessageRoute::Single
                },
                parts,
                limits,
                decrypt,
                retained,
                retirement,
            );
            // Preserve the legacy convenience facade's invalid-ciphertext contract.
            // The generic continuation facade retains the native CK_RV instead.
            let (bytes, nonce, credit) = result.map_err(|error| match error {
                Error::Native {
                    function: "C_Decrypt" | "C_DecryptFinal",
                    code,
                    ..
                } if decrypt
                    && (code == CKR_ENCRYPTED_DATA_INVALID as u64
                        || code == CKR_ENCRYPTED_DATA_LEN_RANGE as u64) =>
                {
                    Error::InvalidCiphertext
                }
                other => other,
            })?;
            return Ok(selection.complete(bytes, nonce, None, credit));
        }
        let nonce = match &selection {
            OwnedAeadSelection::Legacy { nonce, .. } => nonce.clone(),
            OwnedAeadSelection::Stream(_) => {
                return Err(Error::Rejected(
                    crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::GcmMessageSelectionRequired,
                    ),
                ))
            }
        };
        let retained = std::mem::size_of::<OwnedAeadSelection>()
            .checked_add(selection.retained_bytes())
            .ok_or(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::AeadRetainedSelectionAccounting,
                ),
            ))?;
        let init = message_init.unwrap_or(MessageInitLayout::InitWithoutParameters);
        let (bytes, nonce, credit) = self.gcm_message_buffers(
            key,
            nonce,
            aad,
            parts,
            limits,
            init,
            retained,
            message_diagnostics,
        )?;
        Ok(selection.complete(
            bytes,
            nonce,
            Some(CallerSelectedInitLayout::gcm(init)),
            credit,
        ))
    }

    /// Compute one complete native HMAC.
    pub fn compute_mac(
        &self,
        key: &SymmetricKey,
        message: &[u8],
        limits: InputLimits,
    ) -> Result<MessageAuthenticationCode> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.symmetric_mac(
            key.view(),
            &[message],
            limits,
            false,
            None,
            &mut extension_diagnostics,
        )
        .and_then(|r| {
            r.0.ok_or(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::MacOutputUnavailable,
                ),
            ))
        })
    }
    /// Compute HMAC through real native Update/Final calls.
    pub fn compute_mac_multipart(
        &self,
        key: &SymmetricKey,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<MessageAuthenticationCode> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.symmetric_mac(
            key.view(),
            parts,
            limits,
            true,
            None,
            &mut extension_diagnostics,
        )
        .and_then(|r| {
            r.0.ok_or(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::MacOutputUnavailable,
                ),
            ))
        })
    }
    /// Native HMAC verification; native signature/length refusals become Invalid.
    pub fn verify_mac(
        &self,
        key: &SymmetricKey,
        message: &[u8],
        mac: &[u8],
        limits: InputLimits,
    ) -> Result<Verification> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.symmetric_mac(
            key.view(),
            &[message],
            limits,
            false,
            Some(mac),
            &mut extension_diagnostics,
        )
        .map(|r| r.1)
    }
    /// Native multipart verification without re-hashing or software fallback.
    pub fn verify_mac_multipart(
        &self,
        key: &SymmetricKey,
        parts: &[&[u8]],
        mac: &[u8],
        limits: InputLimits,
    ) -> Result<Verification> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.symmetric_mac(
            key.view(),
            parts,
            limits,
            true,
            Some(mac),
            &mut extension_diagnostics,
        )
        .map(|r| r.1)
    }
    pub(crate) fn symmetric_mac(
        &self,
        key: SymmetricKeyView<'_>,
        parts: &[&[u8]],
        limits: InputLimits,
        multipart: bool,
        expected: Option<&[u8]>,
        extension_diagnostics: &mut crate::mechanism_extension::operation::Invocation,
    ) -> Result<(Option<MessageAuthenticationCode>, Verification)> {
        let algorithm = match key.algorithm {
            SymmetricAlgorithm::HmacSha256 { .. } => crate::NativeMacAlgorithm::SHA256_HMAC,
            SymmetricAlgorithm::HmacSha384 { .. } => crate::NativeMacAlgorithm::SHA384_HMAC,
            SymmetricAlgorithm::HmacSha512 { .. } => crate::NativeMacAlgorithm::SHA512_HMAC,
            _ => {
                return Err(Error::Rejected(
                    crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::AeadKeyUsedForMac,
                    ),
                ))
            }
        };
        let output_length = key.algorithm.mac_length().ok_or(Error::Rejected(
            crate::RejectionReason::SymmetricParameters(
                crate::SymmetricParametersRejection::AeadKeyUsedForMac,
            ),
        ))?;
        let route = if multipart {
            crate::MessageRoute::Multipart
        } else {
            crate::MessageRoute::Single
        };
        let parameters = crate::NativeMacParameters::Full(algorithm);
        if let Some(expected) = expected {
            let result = self.verify_native_mac_with_diagnostics(
                key.managed,
                parameters,
                route,
                parts,
                expected,
                limits,
                None,
                extension_diagnostics,
            );
            match result {
                Ok(()) => Ok((None, Verification::Valid)),
                Err(Error::Native { code, .. })
                    if code == CKR_SIGNATURE_INVALID as u64
                        || code == CKR_SIGNATURE_LEN_RANGE as u64 =>
                {
                    // Preserve this established convenience result only after
                    // checking the reference/context again. The generic method
                    // retains the exact native refusal for callers needing it.
                    let state = self.access()?;
                    self.managed_handle(&state, key.managed)?;
                    key.managed.identity.access.result(
                        self,
                        &state,
                        Ok((None, Verification::Invalid)),
                    )
                }
                Err(cause) => Err(cause),
            }
        } else {
            let mac = self.compute_native_mac_with_diagnostics(
                key.managed,
                parameters,
                route,
                parts,
                limits,
                output_length,
                None,
                extension_diagnostics,
            )?;
            // Full HMAC parameters already validate the exact output width in
            // compute_native_mac's credited publication path. Forward that
            // result without allocating a second, unreachable diagnostic here.
            Ok((
                Some(MessageAuthenticationCode { bytes: mac.bytes }),
                Verification::Valid,
            ))
        }
    }
}
