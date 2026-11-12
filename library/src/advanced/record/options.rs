// SPDX-License-Identifier: Apache-2.0
//! Closed descriptor-extension tags for the current record format. The descriptor
//! checks their operation-family constraints at the decoding boundary. These
//! numbers are archive codes, not PKCS#11 constants.
use crate::{Error, Result};

#[derive(Clone, Copy)]
pub(super) enum OptionsTag {
    None,
    Rc2,
    Rc5,
    Stream,
    TokenIv,
    ChaChaIetfBytes,
    DigestBits,
    GcmWithoutIvBits,
    CcmDataLength,
}

impl OptionsTag {
    pub(super) fn wire(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Rc2 => 1,
            Self::Rc5 => 2,
            Self::Stream => 3,
            Self::TokenIv => 4,
            Self::ChaChaIetfBytes => 5,
            Self::DigestBits => 6,
            Self::GcmWithoutIvBits => 7,
            Self::CcmDataLength => 8,
        }
    }

    pub(super) fn from_wire(tag: u8) -> Result<Self> {
        match tag {
            0 => Ok(Self::None),
            1 => Ok(Self::Rc2),
            2 => Ok(Self::Rc5),
            3 => Ok(Self::Stream),
            4 => Ok(Self::TokenIv),
            5 => Ok(Self::ChaChaIetfBytes),
            6 => Ok(Self::DigestBits),
            7 => Ok(Self::GcmWithoutIvBits),
            8 => Ok(Self::CcmDataLength),
            _ => Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordCipherOptionsTag,
            ))),
        }
    }
}
