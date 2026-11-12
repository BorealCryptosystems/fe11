// SPDX-License-Identifier: Apache-2.0
//! Selection retained by the classic AEAD owner through native completion.
use super::*;

pub(super) enum OwnedAeadSelection {
    Legacy {
        algorithm: SymmetricAlgorithm,
        nonce: AeadNonce,
    },
    Stream(StreamAeadNonce),
}
impl OwnedAeadSelection {
    pub(super) fn validate(&self, aad: usize, message_route: bool) -> Result<()> {
        match self {
            Self::Legacy { algorithm, nonce } => {
                if algorithm.mac() {
                    return Err(Error::Rejected(
                        crate::RejectionReason::SymmetricParameters(
                            crate::SymmetricParametersRejection::MacKeyUsedForAead,
                        ),
                    ));
                }
                if *algorithm == SymmetricAlgorithm::ChaCha20 {
                    bounds::ck_length(aad)?;
                    if nonce.iv().len() != 12
                        || nonce.tag_bits() != 128
                        || nonce.generated()
                        || nonce.fixed_bits() != 0
                    {
                        return Err(Error::Rejected(
                            crate::RejectionReason::SymmetricParameters(
                                crate::SymmetricParametersRejection::IetfChacha20Poly1305Parameters,
                            ),
                        ));
                    }
                } else if message_route {
                    nonce.validate_gcm_message_encrypt(aad)?;
                } else {
                    nonce.validate_gcm(aad)?;
                }
                Ok(())
            }
            Self::Stream(_) => bounds::ck_length(aad).map(|_| ()),
        }
    }

    pub(super) fn gcm_message_capable(&self) -> bool {
        matches!(
            self,
            Self::Legacy {
                algorithm: SymmetricAlgorithm::Aes128
                    | SymmetricAlgorithm::Aes192
                    | SymmetricAlgorithm::Aes256,
                ..
            }
        )
    }

    pub(super) fn tag_bytes(&self) -> Result<usize> {
        match self {
            Self::Legacy { nonce, .. } => nonce.tag_bytes(),
            Self::Stream(_) => Ok(16),
        }
    }
    pub(super) fn generated(&self) -> bool {
        match self {
            Self::Legacy { nonce, .. } => nonce.generated(),
            Self::Stream(_) => false,
        }
    }
    pub(super) fn retained_bytes(&self) -> usize {
        match self {
            Self::Legacy { nonce, .. } => nonce.retained_bytes(),
            Self::Stream(_) => 0,
        }
    }

    pub(super) fn complete(
        self,
        bytes: Buffer,
        nonce: Buffer,
        message_init: Option<CallerSelectedInitLayout>,
        credit: memory::Credit,
    ) -> AeadCompletion {
        match self {
            Self::Legacy {
                algorithm,
                nonce: origin,
            } => AeadCompletion::Legacy(AeadCiphertext {
                bytes,
                nonce,
                origin,
                algorithm,
                message_init,
                _parameters: credit,
            }),
            Self::Stream(origin) => AeadCompletion::Stream(StreamAeadEncrypted {
                bytes,
                nonce: origin,
                _parameters: credit,
            }),
        }
    }
}

pub(super) enum AeadCompletion {
    Legacy(AeadCiphertext),
    Stream(StreamAeadEncrypted),
}
impl AeadCompletion {
    pub(super) fn into_legacy(self) -> Result<AeadCiphertext> {
        match self {
            Self::Legacy(result) => Ok(result),
            Self::Stream(_) => Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::AeadCompletionSelectionMismatch,
                ),
            )),
        }
    }
    pub(super) fn into_stream(self) -> Result<StreamAeadEncrypted> {
        match self {
            Self::Stream(result) => Ok(result),
            Self::Legacy(_) => Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::AeadCompletionSelectionMismatch,
                ),
            )),
        }
    }
}
