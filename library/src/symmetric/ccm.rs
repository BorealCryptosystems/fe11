// SPDX-License-Identifier: Apache-2.0
//! CCM layouts are selected by the native function family, never by provider.
use super::{
    input_size, memory, Buffer, CallerSelectedInitLayout, MessageInitLayout, SymmetricAlgorithm,
    SymmetricKey,
};
use crate::{bounds, AeadPlaintext, Error, InputLimits, Result, Session};
use fe11_sys::*;
use std::sync::Arc;

/// Explicit nonce bytes and the generator fields of CCM message parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CcmNonce {
    /// Seven to thirteen nonce bytes, or initial bytes for native generation.
    pub bytes: Arc<[u8]>,
    /// Exact CK_GENERATOR_FUNCTION value; CKG_NO_GENERATE supplies the nonce.
    /// Message decryption ignores this field as specified by PKCS#11.
    pub generator: u64,
    /// Most significant nonce bits preserved by native message encryption.
    /// Message decryption ignores this field as specified by PKCS#11.
    pub fixed_bits: u64,
}
/// CCM input parameters. The data length is derived from the complete request.
pub struct CcmParameters<'a> {
    /// Requested nonce and explicit message generation fields.
    pub nonce: CcmNonce,
    /// Additional authenticated data, never encrypted.
    pub aad: &'a [u8],
    /// MAC length in bytes: 4, 6, 8, 10, 12, 14 or 16.
    pub mac_length: u64,
}
/// Completed CCM ciphertext, MAC and nonce retained as one owned result.
pub struct CcmCiphertext {
    bytes: Buffer,
    nonce: Buffer,
    origin: CcmNonce,
    mac_length: usize,
    message_init: Option<CallerSelectedInitLayout>,
    _credit: memory::Credit,
}
impl CcmCiphertext {
    fn into_plaintext(self) -> AeadPlaintext {
        AeadPlaintext {
            bytes: self.bytes,
            tag_bits: self.mac_length as u64 * 8,
            message_init: self.message_init,
            classic: None,
        }
    }

    /// Selected Message Init layout; absent for a traditional CCM operation.
    pub fn message_init(&self) -> Option<CallerSelectedInitLayout> {
        self.message_init
    }
    /// Ciphertext followed by its MAC, suitable for traditional CCM decryption.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
    /// Ciphertext only, suitable for message decryption with a separate MAC.
    pub fn ciphertext(&self) -> &[u8] {
        &self.bytes.as_slice()[..self.bytes.as_slice().len() - self.mac_length]
    }
    /// MAC associated with this ciphertext and nonce.
    pub fn mac(&self) -> &[u8] {
        &self.bytes.as_slice()[self.bytes.as_slice().len() - self.mac_length..]
    }
    /// Nonce actually used by the completed operation.
    pub fn nonce(&self) -> &[u8] {
        self.nonce.as_slice()
    }
    /// Original caller-selected nonce/generator fields, not a uniqueness proof.
    pub fn nonce_request(&self) -> &CcmNonce {
        &self.origin
    }
}
#[derive(Clone, Copy)]
enum Route {
    Traditional {
        multipart: bool,
    },
    Message {
        multipart: bool,
        init: MessageInitLayout,
    },
}
impl Route {
    fn message(self) -> bool {
        matches!(self, Self::Message { .. })
    }
    fn multipart(self) -> bool {
        match self {
            Self::Traditional { multipart } | Self::Message { multipart, .. } => multipart,
        }
    }
}
#[derive(Clone, Copy)]
enum Request<'a> {
    Encrypt,
    DecryptAppended,
    DecryptSeparate(&'a [u8]),
}
impl Request<'_> {
    fn decrypt(self) -> bool {
        !matches!(self, Self::Encrypt)
    }
}
pub(crate) fn validate_ccm_message(
    nonce: &CcmNonce,
    aad_length: usize,
    mac_length: u64,
    data_length: usize,
    decrypt: bool,
) -> Result<()> {
    validate_ccm_fields(
        super::AeadParameterLayout::Message,
        nonce.bytes.len(),
        nonce.generator,
        nonce.fixed_bits,
        aad_length,
        mac_length,
        data_length,
        decrypt,
    )
}
pub(crate) fn validate_ccm_fields(
    layout: super::AeadParameterLayout,
    nonce_length: usize,
    generator: u64,
    fixed_bits: u64,
    aad_length: usize,
    mac_length: u64,
    data_length: usize,
    decrypt: bool,
) -> Result<()> {
    if !(7..=13).contains(&nonce_length) {
        return Err(Error::Rejected(
            crate::RejectionReason::SymmetricParameters(
                crate::SymmetricParametersRejection::CcmNonceLength,
            ),
        ));
    }
    if !matches!(mac_length, 4 | 6 | 8 | 10 | 12 | 14 | 16) {
        return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
            crate::AeadMessagesRejection::CcmMacLength,
        )));
    }
    if layout == super::AeadParameterLayout::Classic && aad_length as u128 > u32::MAX as u128 {
        return Err(Error::Rejected(
            crate::RejectionReason::SymmetricParameters(
                crate::SymmetricParametersRejection::CcmAadLength,
            ),
        ));
    }
    bounds::ck_length(aad_length)?;
    CK_GENERATOR_FUNCTION::try_from(generator).map_err(|_| {
        Error::Rejected(crate::RejectionReason::AeadMessages(
            crate::AeadMessagesRejection::CcmGeneratorAbiWidth,
        ))
    })?;
    CK_ULONG::try_from(fixed_bits).map_err(|_| {
        Error::Rejected(crate::RejectionReason::SymmetricParameters(
            crate::SymmetricParametersRejection::CcmFixedBitsAbiWidth,
        ))
    })?;
    if !decrypt && fixed_bits > nonce_length as u64 * 8 {
        return Err(Error::Rejected(
            crate::RejectionReason::SymmetricParameters(
                crate::SymmetricParametersRejection::CcmFixedBitsExceedNonce,
            ),
        ));
    }
    let length = u64::try_from(data_length).map_err(|_| {
        Error::Rejected(crate::RejectionReason::SymmetricParameters(
            crate::SymmetricParametersRejection::CcmDataLength,
        ))
    })?;
    let q = 15 - nonce_length;
    if q < 8 && length >= (1u64 << (8 * q)) {
        return Err(Error::Rejected(
            crate::RejectionReason::SymmetricParameters(
                crate::SymmetricParametersRejection::CcmDataLengthExceedsNonceEncoding,
            ),
        ));
    }
    bounds::ck_length(data_length)?;
    Ok(())
}
fn dimensions(
    parameters: &CcmParameters<'_>,
    input: usize,
    route: Route,
    request: Request<'_>,
) -> Result<(usize, usize)> {
    if !route.message()
        && (parameters.nonce.generator != CKG_NO_GENERATE as u64
            || parameters.nonce.fixed_bits != 0)
    {
        return Err(Error::Rejected(
            crate::RejectionReason::SymmetricParameters(
                crate::SymmetricParametersRejection::TraditionalCcmHasNoNonceGenerationFields,
            ),
        ));
    }
    let mac = usize::try_from(parameters.mac_length).map_err(|_| {
        Error::Rejected(crate::RejectionReason::SymmetricParameters(
            crate::SymmetricParametersRejection::CcmMacWidth,
        ))
    })?;
    let data = match request {
        Request::Encrypt => input,
        Request::DecryptAppended if !route.message() => input.checked_sub(mac).ok_or(
            Error::Rejected(crate::RejectionReason::SymmetricParameters(
                crate::SymmetricParametersRejection::CcmCiphertextShorterThanMac,
            )),
        )?,
        Request::DecryptSeparate(expected) if route.message() && expected.len() == mac => input,
        _ => {
            return Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::CcmMacRepresentationDoesNotMatchRoute,
                ),
            ))
        }
    };
    validate_ccm_fields(
        if route.message() {
            super::AeadParameterLayout::Message
        } else {
            super::AeadParameterLayout::Classic
        },
        parameters.nonce.bytes.len(),
        parameters.nonce.generator,
        parameters.nonce.fixed_bits,
        parameters.aad.len(),
        parameters.mac_length,
        data,
        request.decrypt(),
    )?;
    Ok((data, mac))
}

impl Session {
    /// Traditional CCM encryption. The returned byte representation appends its MAC.
    pub fn encrypt_ccm(
        &self,
        key: &SymmetricKey,
        parameters: CcmParameters<'_>,
        message: &[u8],
        limits: InputLimits,
    ) -> Result<CcmCiphertext> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        self.classic_ccm(
            key,
            parameters,
            &[message],
            limits,
            Route::Traditional { multipart: false },
            Request::Encrypt,
            &mut retirement,
        )
    }
    /// Traditional CCM Update/Final; no implicit single-call fallback.
    pub fn encrypt_ccm_multipart(
        &self,
        key: &SymmetricKey,
        parameters: CcmParameters<'_>,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<CcmCiphertext> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        self.classic_ccm(
            key,
            parameters,
            parts,
            limits,
            Route::Traditional { multipart: true },
            Request::Encrypt,
            &mut retirement,
        )
    }
    /// Decrypt ciphertext with its appended MAC; native refusals retain their CK_RV.
    pub fn decrypt_ccm(
        &self,
        key: &SymmetricKey,
        parameters: CcmParameters<'_>,
        ciphertext_and_mac: &[u8],
        limits: InputLimits,
    ) -> Result<AeadPlaintext> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        self.classic_ccm(
            key,
            parameters,
            &[ciphertext_and_mac],
            limits,
            Route::Traditional { multipart: false },
            Request::DecryptAppended,
            &mut retirement,
        )
        .map(CcmCiphertext::into_plaintext)
    }
    /// Decrypt traditional fragments containing the appended MAC. No intermediate
    /// plaintext is published, including when the native operation later refuses.
    pub fn decrypt_ccm_multipart(
        &self,
        key: &SymmetricKey,
        parameters: CcmParameters<'_>,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<AeadPlaintext> {
        let mut retirement = crate::advanced::PollDiagnostics::default();
        self.classic_ccm(
            key,
            parameters,
            parts,
            limits,
            Route::Traditional { multipart: true },
            Request::DecryptAppended,
            &mut retirement,
        )
        .map(CcmCiphertext::into_plaintext)
    }
    /// Encrypt one CCM message using explicit Init layout and separate native MAC.
    pub fn encrypt_ccm_message(
        &self,
        key: &SymmetricKey,
        parameters: CcmParameters<'_>,
        message: &[u8],
        limits: InputLimits,
        init: MessageInitLayout,
    ) -> Result<CcmCiphertext> {
        let mut message_diagnostics = None;
        self.ccm(
            key,
            parameters,
            &[message],
            limits,
            Route::Message {
                multipart: false,
                init,
            },
            Request::Encrypt,
            &mut message_diagnostics,
        )
    }
    /// Encrypt one message through Begin/Next with END_OF_MESSAGE on the last part.
    pub fn encrypt_ccm_message_multipart(
        &self,
        key: &SymmetricKey,
        parameters: CcmParameters<'_>,
        parts: &[&[u8]],
        limits: InputLimits,
        init: MessageInitLayout,
    ) -> Result<CcmCiphertext> {
        let mut message_diagnostics = None;
        self.ccm(
            key,
            parameters,
            parts,
            limits,
            Route::Message {
                multipart: true,
                init,
            },
            Request::Encrypt,
            &mut message_diagnostics,
        )
    }
    /// Decrypt one CCM message with a separate MAC; generation fields are ignored
    /// by the native decrypt operation as specified, and are passed unchanged.
    pub fn decrypt_ccm_message(
        &self,
        key: &SymmetricKey,
        parameters: CcmParameters<'_>,
        ciphertext: &[u8],
        mac: &[u8],
        limits: InputLimits,
        init: MessageInitLayout,
    ) -> Result<AeadPlaintext> {
        let mut message_diagnostics = None;
        self.ccm(
            key,
            parameters,
            &[ciphertext],
            limits,
            Route::Message {
                multipart: false,
                init,
            },
            Request::DecryptSeparate(mac),
            &mut message_diagnostics,
        )
        .map(CcmCiphertext::into_plaintext)
    }
    /// Decrypt message fragments and a separate MAC without publishing partial data.
    pub fn decrypt_ccm_message_multipart(
        &self,
        key: &SymmetricKey,
        parameters: CcmParameters<'_>,
        parts: &[&[u8]],
        mac: &[u8],
        limits: InputLimits,
        init: MessageInitLayout,
    ) -> Result<AeadPlaintext> {
        let mut message_diagnostics = None;
        self.ccm(
            key,
            parameters,
            parts,
            limits,
            Route::Message {
                multipart: true,
                init,
            },
            Request::DecryptSeparate(mac),
            &mut message_diagnostics,
        )
        .map(CcmCiphertext::into_plaintext)
    }
    fn classic_ccm(
        &self,
        key: &SymmetricKey,
        parameters: CcmParameters<'_>,
        parts: &[&[u8]],
        limits: InputLimits,
        route: Route,
        request: Request<'_>,
        retirement: &mut crate::advanced::PollDiagnostics,
    ) -> Result<CcmCiphertext> {
        if !matches!(
            key.algorithm,
            SymmetricAlgorithm::Aes128 | SymmetricAlgorithm::Aes192 | SymmetricAlgorithm::Aes256
        ) {
            return Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::CcmRequiresAnAesKey,
                ),
            ));
        }
        let framing = if request.decrypt() {
            usize::try_from(parameters.mac_length).map_err(|_| {
                Error::Rejected(crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::CcmMacWidth,
                ))
            })?
        } else {
            0
        };
        let input = input_size(
            self.inner.crypto_options.limits,
            limits,
            parts,
            parameters.aad,
            framing,
        )?;
        let (_, mac_length) = dimensions(&parameters, input, route, request)?;
        let retained = std::mem::size_of::<CcmNonce>()
            .checked_add(parameters.nonce.bytes.len())
            .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::CcmRetainedSelectionAccounting,
            )))?;
        let (bytes, nonce, credit) = self.classic_aead_retained(
            &key.managed,
            crate::ClassicAeadParameters::Ccm {
                nonce: &parameters.nonce.bytes,
                aad: parameters.aad,
                mac_length: parameters.mac_length,
            },
            if route.multipart() {
                crate::MessageRoute::Multipart
            } else {
                crate::MessageRoute::Single
            },
            parts,
            limits,
            request.decrypt(),
            retained,
            retirement,
        )?;
        Ok(CcmCiphertext {
            bytes,
            nonce,
            origin: parameters.nonce,
            mac_length,
            message_init: None,
            _credit: credit,
        })
    }
    fn ccm(
        &self,
        key: &SymmetricKey,
        parameters: CcmParameters<'_>,
        parts: &[&[u8]],
        limits: InputLimits,
        route: Route,
        request: Request<'_>,
        message_diagnostics: &mut Option<crate::advanced::AeadMessageDiagnostics>,
    ) -> Result<CcmCiphertext> {
        let Route::Message { multipart, init } = route else {
            return Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::CcmMessageRouteRequired,
                ),
            ));
        };
        let input = input_size(
            self.inner.crypto_options.limits,
            limits,
            parts,
            parameters.aad,
            0,
        )?;
        let (_, mac_length) = dimensions(&parameters, input, route, request)?;
        let mac = match request {
            Request::Encrypt => None,
            Request::DecryptSeparate(mac) => Some(mac),
            Request::DecryptAppended => {
                return Err(Error::Rejected(
                    crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::CcmMessageRequiresSeparateMac,
                    ),
                ))
            }
        };
        let (bytes, nonce, credit) = self.ccm_message_buffers(
            key,
            &parameters,
            parts,
            limits,
            if multipart {
                crate::MessageRoute::Multipart
            } else {
                crate::MessageRoute::Single
            },
            init,
            mac,
            message_diagnostics,
        )?;
        Ok(CcmCiphertext {
            bytes,
            nonce,
            origin: parameters.nonce,
            mac_length,
            message_init: Some(CallerSelectedInitLayout::ccm(init)),
            _credit: credit,
        })
    }
}
