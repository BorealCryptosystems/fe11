// SPDX-License-Identifier: Apache-2.0
//! Encrypt-data derivation owns the algorithm-specific CBC structure and input.
use super::*;
use crate::NativeEncryptData;

enum Raw {
    Ecb(CK_KEY_DERIVATION_STRING_DATA),
    Des {
        raw: CK_DES_CBC_ENCRYPT_DATA_PARAMS,
        iv: [u8; 8],
    },
    Aes {
        raw: CK_AES_CBC_ENCRYPT_DATA_PARAMS,
        iv: [u8; 16],
    },
    Camellia {
        raw: CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS,
        iv: [u8; 16],
    },
    Aria {
        raw: CK_ARIA_CBC_ENCRYPT_DATA_PARAMS,
        iv: [u8; 16],
    },
    Seed {
        raw: CK_SEED_CBC_ENCRYPT_DATA_PARAMS,
        iv: [u8; 16],
    },
}
pub(super) struct EncryptData {
    raw: Raw,
    data: InputBytes,
}
impl EncryptData {
    pub(super) fn from_storage(
        input: &NativeEncryptData<'_>,
        storage: InputBytesStorage,
        credit: &mut Credit,
    ) -> Result<Self> {
        let mut data = storage.bind(input.data(), credit)?;
        let pointer = data.pointer();
        let length = data.length();
        let raw = match input {
            NativeEncryptData::DesCbc { iv, .. } | NativeEncryptData::Des3Cbc { iv, .. } => {
                Raw::Des {
                    raw: CK_DES_CBC_ENCRYPT_DATA_PARAMS {
                        iv: *iv,
                        pData: pointer,
                        length,
                    },
                    iv: *iv,
                }
            }
            NativeEncryptData::AesCbc { iv, .. } => Raw::Aes {
                raw: CK_AES_CBC_ENCRYPT_DATA_PARAMS {
                    iv: *iv,
                    pData: pointer,
                    length,
                },
                iv: *iv,
            },
            NativeEncryptData::CamelliaCbc { iv, .. } => Raw::Camellia {
                raw: CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS {
                    iv: *iv,
                    pData: pointer,
                    length,
                },
                iv: *iv,
            },
            NativeEncryptData::AriaCbc { iv, .. } => Raw::Aria {
                raw: CK_ARIA_CBC_ENCRYPT_DATA_PARAMS {
                    iv: *iv,
                    pData: pointer,
                    length,
                },
                iv: *iv,
            },
            NativeEncryptData::SeedCbc { iv, .. } => Raw::Seed {
                raw: CK_SEED_CBC_ENCRYPT_DATA_PARAMS {
                    iv: *iv,
                    pData: pointer,
                    length,
                },
                iv: *iv,
            },
            NativeEncryptData::DesEcb(_)
            | NativeEncryptData::Des3Ecb(_)
            | NativeEncryptData::AesEcb(_)
            | NativeEncryptData::CamelliaEcb(_)
            | NativeEncryptData::AriaEcb(_)
            | NativeEncryptData::SeedEcb(_) => Raw::Ecb(CK_KEY_DERIVATION_STRING_DATA {
                pData: pointer,
                ulLen: length,
            }),
        };
        Ok(Self { raw, data })
    }
    pub(super) fn projection(&mut self) -> (CK_VOID_PTR, CK_ULONG) {
        match &mut self.raw {
            Raw::Ecb(raw) => (
                (raw as *mut CK_KEY_DERIVATION_STRING_DATA).cast(),
                size_of::<CK_KEY_DERIVATION_STRING_DATA>() as CK_ULONG,
            ),
            Raw::Des { raw, .. } => (
                (raw as *mut CK_DES_CBC_ENCRYPT_DATA_PARAMS).cast(),
                size_of::<CK_DES_CBC_ENCRYPT_DATA_PARAMS>() as CK_ULONG,
            ),
            Raw::Aes { raw, .. } => (
                (raw as *mut CK_AES_CBC_ENCRYPT_DATA_PARAMS).cast(),
                size_of::<CK_AES_CBC_ENCRYPT_DATA_PARAMS>() as CK_ULONG,
            ),
            Raw::Camellia { raw, .. } => (
                (raw as *mut CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS).cast(),
                size_of::<CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS>() as CK_ULONG,
            ),
            Raw::Aria { raw, .. } => (
                (raw as *mut CK_ARIA_CBC_ENCRYPT_DATA_PARAMS).cast(),
                size_of::<CK_ARIA_CBC_ENCRYPT_DATA_PARAMS>() as CK_ULONG,
            ),
            Raw::Seed { raw, .. } => (
                (raw as *mut CK_SEED_CBC_ENCRYPT_DATA_PARAMS).cast(),
                size_of::<CK_SEED_CBC_ENCRYPT_DATA_PARAMS>() as CK_ULONG,
            ),
        }
    }

    pub(super) fn unchanged(&self) -> bool {
        let data = self.data.unchanged();
        data && match &self.raw {
            Raw::Ecb(raw) => {
                raw.pData == self.data.expected_pointer() && raw.ulLen == self.data.length()
            }
            Raw::Des { raw, iv } => {
                raw.iv == *iv
                    && raw.pData == self.data.expected_pointer()
                    && raw.length == self.data.length()
            }
            Raw::Aes { raw, iv } => {
                raw.iv == *iv
                    && raw.pData == self.data.expected_pointer()
                    && raw.length == self.data.length()
            }
            Raw::Camellia { raw, iv } => {
                raw.iv == *iv
                    && raw.pData == self.data.expected_pointer()
                    && raw.length == self.data.length()
            }
            Raw::Aria { raw, iv } => {
                raw.iv == *iv
                    && raw.pData == self.data.expected_pointer()
                    && raw.length == self.data.length()
            }
            Raw::Seed { raw, iv } => {
                raw.iv == *iv
                    && raw.pData == self.data.expected_pointer()
                    && raw.length == self.data.length()
            }
        }
    }
}


