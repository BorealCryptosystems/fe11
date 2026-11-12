// SPDX-License-Identifier: Apache-2.0
//! Closed operation families in BPKIOP09. Numeric codes exist only at the wire.
use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::advanced) enum Family {
    Digest,
    MessageEncrypt,
    MessageDecrypt,
    MessageSign,
    MessageVerify,
    DigestEncrypt,
    DecryptDigest,
    SignEncrypt,
    DecryptVerify,
    SignRecover,
    VerifyRecover,
    CipherEncrypt,
    CipherDecrypt,
    Signature,
    NativeMessages,
}

impl Family {
    pub(in crate::advanced) fn from_wire(code: u8) -> Result<Self> {
        match code {
            1 => Ok(Self::Digest),
            2 => Ok(Self::MessageEncrypt),
            3 => Ok(Self::MessageDecrypt),
            4 => Ok(Self::MessageSign),
            5 => Ok(Self::MessageVerify),
            6 => Ok(Self::DigestEncrypt),
            7 => Ok(Self::DecryptDigest),
            8 => Ok(Self::SignEncrypt),
            9 => Ok(Self::DecryptVerify),
            10 => Ok(Self::SignRecover),
            11 => Ok(Self::VerifyRecover),
            12 => Ok(Self::CipherEncrypt),
            13 => Ok(Self::CipherDecrypt),
            14 => Ok(Self::Signature),
            15 => Ok(Self::NativeMessages),
            _ => Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::RecordOperationFamily,
            ))),
        }
    }

    pub(in crate::advanced) fn wire(self) -> u8 {
        match self {
            Self::Digest => 1,
            Self::MessageEncrypt => 2,
            Self::MessageDecrypt => 3,
            Self::MessageSign => 4,
            Self::MessageVerify => 5,
            Self::DigestEncrypt => 6,
            Self::DecryptDigest => 7,
            Self::SignEncrypt => 8,
            Self::DecryptVerify => 9,
            Self::SignRecover => 10,
            Self::VerifyRecover => 11,
            Self::CipherEncrypt => 12,
            Self::CipherDecrypt => 13,
            Self::Signature => 14,
            Self::NativeMessages => 15,
        }
    }

    pub(in crate::advanced) fn is_cipher(self) -> bool {
        matches!(self, Self::CipherEncrypt | Self::CipherDecrypt)
    }

    pub(in crate::advanced) fn is_recover(self) -> bool {
        matches!(self, Self::SignRecover | Self::VerifyRecover)
    }

    pub(in crate::advanced) fn is_dual(self) -> bool {
        matches!(
            self,
            Self::DigestEncrypt | Self::DecryptDigest | Self::SignEncrypt | Self::DecryptVerify
        )
    }

    pub(in crate::advanced) fn is_dual_mac(self) -> bool {
        matches!(self, Self::SignEncrypt | Self::DecryptVerify)
    }
}
