// SPDX-License-Identifier: Apache-2.0
//! Map digest selections to mechanisms, result lengths and terminal calls.
//! Length acceptance follows the selected representation, including OID-bearing input.

use super::*;

impl DigestSelection {
    pub(in crate::advanced) fn route(self) -> MessageRoute {
        match self {
            Self::NativeSingle(_) => MessageRoute::Single,
            Self::GostOid(route) | Self::Extension { route, .. } => route,
            _ => MessageRoute::Multipart,
        }
    }

    pub(in crate::advanced) fn has_oid(self) -> bool {
        matches!(self, Self::GostOid(_))
    }

    pub(in crate::advanced) fn terminal_function(self) -> &'static str {
        if self.route() == MessageRoute::Single {
            "C_Digest"
        } else {
            "C_DigestFinal"
        }
    }

    pub(in crate::advanced) fn mechanism(self) -> CK_MECHANISM_TYPE {
        match self {
            Self::Extension { mechanism, .. } => mechanism,
            Self::GostOid(_) => CKM_GOSTR3411,
            Self::LegacySha256 => CKM_SHA256,
            Self::Typed(algorithm) => algorithm.mechanism(),
            Self::Native(algorithm) | Self::NativeSingle(algorithm) => algorithm.mechanism(),
        }
    }

    pub(in crate::advanced) fn mechanism_number(self) -> u64 {
        self.mechanism() as u64
    }

    pub(in crate::advanced) fn length(self) -> usize {
        match self {
            Self::Extension { capacity, .. } => capacity,
            Self::GostOid(_) | Self::LegacySha256 => 32,
            Self::Typed(algorithm) => algorithm.output_length(),
            Self::Native(algorithm) | Self::NativeSingle(algorithm) => algorithm.output_length(),
        }
    }

    pub(in crate::advanced) fn accepts_length(self, length: usize) -> bool {
        match self {
            Self::Extension { capacity, .. } => length <= capacity,
            Self::Native(algorithm) | Self::NativeSingle(algorithm) => {
                algorithm.accepts_length(length)
            }
            _ => length == self.length(),
        }
    }

    pub(in crate::advanced) fn checkpoint_profile(self) -> u8 {
        match self {
            Self::Extension {
                route: MessageRoute::Multipart,
                ..
            } => 11,
            Self::Extension {
                route: MessageRoute::Single,
                ..
            } => 12,
            Self::Native(crate::NativeDigestAlgorithm::Null(_)) => 9,
            Self::NativeSingle(crate::NativeDigestAlgorithm::Null(_)) => 10,
            Self::GostOid(MessageRoute::Multipart) => 7,
            Self::GostOid(MessageRoute::Single) => 8,
            Self::LegacySha256 => 1,
            Self::Typed(_) => 2,
            Self::Native(crate::NativeDigestAlgorithm::Sha512T(_)) => 5,
            Self::NativeSingle(crate::NativeDigestAlgorithm::Sha512T(_)) => 6,
            Self::Native(_) => 3,
            Self::NativeSingle(_) => 4,
        }
    }

    pub(in crate::advanced) fn parameter(self) -> Option<CK_ULONG> {
        match self {
            Self::Native(algorithm) | Self::NativeSingle(algorithm) => algorithm.parameter(),
            _ => None,
        }
    }

    pub(in crate::advanced) fn from_descriptor(descriptor: record::Descriptor) -> Result<Self> {
        if let Some(bits) = descriptor.digest_bits {
            if descriptor.mechanism != CKM_SHA512_T as u64 || descriptor.cipher_options.is_some() {
                return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::RecordDigestParameterMechanism,
                )));
            }
            let algorithm =
                crate::NativeDigestAlgorithm::Sha512T(crate::NativeDigestTruncation::new(bits)?);
            let selection = match descriptor.profile {
                5 => Self::Native(algorithm),
                6 => Self::NativeSingle(algorithm),
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                        crate::DigestContinuationRejection::RecordParameterizedDigestProfile,
                    )))
                }
            };
            if selection.length() != descriptor.size {
                return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::RecordDigestParameterWidth,
                )));
            }
            Ok(selection)
        } else {
            Self::from_checkpoint(descriptor.profile, descriptor.mechanism, descriptor.size)
        }
    }

    pub(in crate::advanced) fn from_checkpoint(
        profile: u8,
        mechanism: u64,
        size: usize,
    ) -> Result<Self> {
        let selection = match profile {
            1 if mechanism == crate::HashAlgorithm::Sha256.mechanism_number() => Self::LegacySha256,
            2 => {
                let algorithm = crate::HashAlgorithm::from_mechanism(mechanism).ok_or(
                    Error::Rejected(crate::RejectionReason::DigestContinuation(
                        crate::DigestContinuationRejection::RecordDigestMechanism,
                    )),
                )?;
                Self::Typed(algorithm)
            }
            3 => Self::Native(
                crate::NativeDigestAlgorithm::from_mechanism(mechanism).ok_or(Error::Rejected(
                    crate::RejectionReason::DigestContinuation(
                        crate::DigestContinuationRejection::RecordNativeDigestMechanism,
                    ),
                ))?,
            ),
            4 => Self::NativeSingle(
                crate::NativeDigestAlgorithm::from_mechanism(mechanism).ok_or(Error::Rejected(
                    crate::RejectionReason::DigestContinuation(
                        crate::DigestContinuationRejection::RecordNativeDigestMechanism,
                    ),
                ))?,
            ),
            11 | 12 => {
                bounds::ck_length(size)?;
                Self::Extension {
                    mechanism: CK_MECHANISM_TYPE::try_from(mechanism).map_err(|_| {
                        Error::Rejected(crate::RejectionReason::DigestContinuation(
                            crate::DigestContinuationRejection::DigestMechanismWidth,
                        ))
                    })?,
                    capacity: size,
                    route: if profile == 11 {
                        MessageRoute::Multipart
                    } else {
                        MessageRoute::Single
                    },
                }
            }
            7 if mechanism == CKM_GOSTR3411 as u64 => Self::GostOid(MessageRoute::Multipart),
            8 if mechanism == CKM_GOSTR3411 as u64 => Self::GostOid(MessageRoute::Single),
            9 | 10 if mechanism == CKM_NULL as u64 => {
                let algorithm =
                    crate::NativeDigestAlgorithm::Null(crate::NativeNullDigestCapacity::new(size)?);
                if profile == 9 {
                    Self::Native(algorithm)
                } else {
                    Self::NativeSingle(algorithm)
                }
            }
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::RecordDigestProfile,
                )))
            }
        };
        if selection.length() != size {
            return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                crate::DigestContinuationRejection::RecordDigestWidth,
            )));
        }
        Ok(selection)
    }

    pub(in crate::advanced) fn result(
        self,
        bytes: &mut Buffer,
        validation: Option<SessionValidation>,
    ) -> Result<OperationProgress> {
        Ok(match self {
            Self::Extension { .. } => {
                return Err(Error::Rejected(crate::RejectionReason::DigestContinuation(
                    crate::DigestContinuationRejection::ExtensionDigestRequiresParameterOutputOwner,
                )))
            }
            Self::GostOid(_) => {
                return Self::Native(crate::NativeDigestAlgorithm::GostR3411)
                    .result(bytes, validation)
            }
            Self::LegacySha256 => {
                let digest = bytes.as_slice().try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::DigestOutputLength,
                    ))
                })?;
                match validation {
                    Some(validation) => {
                        OperationProgress::Sha256WithValidation { digest, validation }
                    }
                    None => OperationProgress::Sha256(digest),
                }
            }
            Self::Native(algorithm) | Self::NativeSingle(algorithm) => {
                let digest = crate::NativeDigest::take(algorithm, bytes)?;
                match validation {
                    Some(validation) => {
                        OperationProgress::NativeDigestWithValidation { digest, validation }
                    }
                    None => OperationProgress::NativeDigest(digest),
                }
            }
            Self::Typed(algorithm) => {
                let digest = crate::PreparedDigest::take_budgeted(algorithm, bytes)?;
                match validation {
                    Some(validation) => {
                        OperationProgress::DigestWithValidation { digest, validation }
                    }
                    None => OperationProgress::Digest(digest),
                }
            }
        })
    }
}
