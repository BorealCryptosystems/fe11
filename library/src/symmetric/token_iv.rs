// SPDX-License-Identifier: Apache-2.0
//! Historical ciphers whose 24-byte IV is an output of native encryption.
use crate::{Error, Result};
use fe11_sys::*;

/// Native mechanisms with a token-generated encryption IV.
///
/// These selections express historical PKCS#11 contracts, not a recommendation
/// to use these algorithms or evidence that a module implements them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenIvCipher {
    /// CKM_SKIPJACK_ECB64.
    SkipjackEcb64,
    /// CKM_SKIPJACK_CBC64.
    SkipjackCbc64,
    /// CKM_SKIPJACK_OFB64.
    SkipjackOfb64,
    /// CKM_SKIPJACK_CFB64.
    SkipjackCfb64,
    /// CKM_SKIPJACK_CFB32.
    SkipjackCfb32,
    /// CKM_SKIPJACK_CFB16.
    SkipjackCfb16,
    /// CKM_SKIPJACK_CFB8.
    SkipjackCfb8,
    /// CKM_BATON_ECB128.
    BatonEcb128,
    /// CKM_BATON_ECB96.
    BatonEcb96,
    /// CKM_BATON_CBC128.
    BatonCbc128,
    /// CKM_BATON_COUNTER.
    BatonCounter,
    /// CKM_BATON_SHUFFLE.
    BatonShuffle,
    /// CKM_JUNIPER_ECB128.
    JuniperEcb128,
    /// CKM_JUNIPER_CBC128.
    JuniperCbc128,
    /// CKM_JUNIPER_COUNTER.
    JuniperCounter,
    /// CKM_JUNIPER_SHUFFLE.
    JuniperShuffle,
}

/// Direction of the IV parameter, checked before the native operation begins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenIv {
    /// Encrypt: the module supplies the IV, available on the completed ciphertext.
    /// The initial zeroed allocation is output storage, not a requested zero IV.
    Generate,
    /// Decrypt: use exactly the IV returned with the corresponding ciphertext.
    Provided([u8; 24]),
}

impl TokenIv {
    pub(crate) fn bytes(&self) -> &[u8; 24] {
        match self {
            Self::Generate => &[0; 24],
            Self::Provided(iv) => iv,
        }
    }

    pub(crate) fn generated(self) -> bool {
        matches!(self, Self::Generate)
    }

    pub(crate) fn validate_direction(self, decrypt: bool) -> Result<()> {
        match (self, decrypt) {
            (Self::Generate, false) | (Self::Provided(_), true) => Ok(()),
            _ => Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::TokenIvDirectionDiffersFromCipherOperation,
                ),
            )),
        }
    }
}

impl TokenIvCipher {
    /// Exact native mechanism identifier; this does not query capabilities.
    pub fn mechanism_number(self) -> u64 {
        self.kind() as u64
    }

    pub(crate) fn kind(self) -> CK_MECHANISM_TYPE {
        match self {
            Self::SkipjackEcb64 => CKM_SKIPJACK_ECB64,
            Self::SkipjackCbc64 => CKM_SKIPJACK_CBC64,
            Self::SkipjackOfb64 => CKM_SKIPJACK_OFB64,
            Self::SkipjackCfb64 => CKM_SKIPJACK_CFB64,
            Self::SkipjackCfb32 => CKM_SKIPJACK_CFB32,
            Self::SkipjackCfb16 => CKM_SKIPJACK_CFB16,
            Self::SkipjackCfb8 => CKM_SKIPJACK_CFB8,
            Self::BatonEcb128 => CKM_BATON_ECB128,
            Self::BatonEcb96 => CKM_BATON_ECB96,
            Self::BatonCbc128 => CKM_BATON_CBC128,
            Self::BatonCounter => CKM_BATON_COUNTER,
            Self::BatonShuffle => CKM_BATON_SHUFFLE,
            Self::JuniperEcb128 => CKM_JUNIPER_ECB128,
            Self::JuniperCbc128 => CKM_JUNIPER_CBC128,
            Self::JuniperCounter => CKM_JUNIPER_COUNTER,
            Self::JuniperShuffle => CKM_JUNIPER_SHUFFLE,
        }
    }

    pub(crate) fn from_native(kind: CK_MECHANISM_TYPE) -> Option<Self> {
        Some(match kind {
            CKM_SKIPJACK_ECB64 => Self::SkipjackEcb64,
            CKM_SKIPJACK_CBC64 => Self::SkipjackCbc64,
            CKM_SKIPJACK_OFB64 => Self::SkipjackOfb64,
            CKM_SKIPJACK_CFB64 => Self::SkipjackCfb64,
            CKM_SKIPJACK_CFB32 => Self::SkipjackCfb32,
            CKM_SKIPJACK_CFB16 => Self::SkipjackCfb16,
            CKM_SKIPJACK_CFB8 => Self::SkipjackCfb8,
            CKM_BATON_ECB128 => Self::BatonEcb128,
            CKM_BATON_ECB96 => Self::BatonEcb96,
            CKM_BATON_CBC128 => Self::BatonCbc128,
            CKM_BATON_COUNTER => Self::BatonCounter,
            CKM_BATON_SHUFFLE => Self::BatonShuffle,
            CKM_JUNIPER_ECB128 => Self::JuniperEcb128,
            CKM_JUNIPER_CBC128 => Self::JuniperCbc128,
            CKM_JUNIPER_COUNTER => Self::JuniperCounter,
            CKM_JUNIPER_SHUFFLE => Self::JuniperShuffle,
            _ => return None,
        })
    }

    fn input_unit(self) -> usize {
        match self {
            Self::SkipjackEcb64
            | Self::SkipjackCbc64
            | Self::SkipjackOfb64
            | Self::SkipjackCfb64 => 8,
            Self::SkipjackCfb32 | Self::SkipjackCfb16 | Self::SkipjackCfb8 => 4,
            Self::BatonEcb96 => 12,
            _ => 16,
        }
    }

    pub(crate) fn terminal_lengths(self, input: u128, output: u128) -> bool {
        input % self.input_unit() as u128 == 0 && output == input
    }

    pub(crate) fn output_bounds(self, input: usize) -> Result<(usize, usize)> {
        // PKCS#11 Historical Mechanisms 2.40, tables 32–38, 40–44 and 46–49.
        // Tables 37/38 specify multiples of four even for CFB16/CFB8;
        // do not infer a different data contract from the feedback-bit name.
        let unit = self.input_unit();
        if input % unit != 0 {
            return Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::TokenIvCipherInputAlignment,
                ),
            ));
        }
        Ok((input, input))
    }
}
