// SPDX-License-Identifier: Apache-2.0
//! Terminal length relations use cumulative counters, never allocation widths.
use super::{CipherParameters, FixedContract, LengthRule};
use fe11_sys::*;

impl CipherParameters<'_> {
    pub(crate) fn terminal_lengths(self, input: u128, output: u128, decrypt: bool) -> bool {
        match self {
            Self::Gost28147 { .. } => {
                output == input || input.checked_add((8 - input % 8) % 8) == Some(output)
            }
            Self::TokenIv { cipher, .. } => cipher.terminal_lengths(input, output),
            Self::Stream(_) | Self::CamelliaCtr { .. } => input == output,
            Self::Rc(value) => value.terminal_lengths(input, output, decrypt),
            _ => {
                // Conversion can fail on targets with a narrower CK_ULONG.
                let Some(kind) = CK_MECHANISM_TYPE::try_from(self.mechanism_number()).ok() else {
                    return false;
                };
                if let Some(contract) = FixedContract::from_native(kind) {
                    return contract.terminal_lengths(input, output, decrypt);
                }
                let length = match kind {
                    CKM_AES_ECB | CKM_AES_CBC => LengthRule::Aligned,
                    CKM_AES_CBC_PAD => LengthRule::Padded,
                    CKM_AES_CTR | CKM_AES_OFB | CKM_AES_CFB8 | CKM_AES_CFB64 | CKM_AES_CFB128 => {
                        LengthRule::Stream
                    }
                    _ => return false,
                };
                FixedContract {
                    kind,
                    block: 16,
                    iv: 0,
                    length,
                }
                .terminal_lengths(input, output, decrypt)
            }
        }
    }
}

impl FixedContract {
    pub(crate) fn terminal_lengths(self, input: u128, output: u128, decrypt: bool) -> bool {
        let block = self.block as u128;
        match self.length {
            LengthRule::Aligned => input % block == 0 && output == input,
            LengthRule::Stealing => input >= block && output == input,
            LengthRule::Stream => output == input,
            LengthRule::Padded if decrypt => {
                input > 0 && input % block == 0 && (input - block..input).contains(&output)
            }
            LengthRule::Padded => input.checked_add(block - input % block) == Some(output),
            // PAD's historical specifications do not define one unambiguous
            // result interval. Actual native buffer bounds remain mandatory.
            LengthRule::KeyWrap if self.kind == CKM_AES_KEY_WRAP_PAD => true,
            LengthRule::KeyWrap if decrypt => output <= input.saturating_sub(8),
            LengthRule::KeyWrap => {
                let padded = match self.kind {
                    CKM_AES_KEY_WRAP => Some(input),
                    CKM_AES_KEY_WRAP_KWP => {
                        input.checked_add((8 - input % 8) % 8).map(|n| n.max(8))
                    }
                    CKM_AES_KEY_WRAP_PKCS7 => input.checked_add(8 - input % 8),
                    _ => None,
                };
                padded.and_then(|n| n.checked_add(8)) == Some(output)
            }
        }
    }
}
