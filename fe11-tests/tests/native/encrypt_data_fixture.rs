// SPDX-License-Identifier: Apache-2.0
//! Published block-cipher answers used as native derived-key values.
use super::{
    arguments::hex, derived_value_case::DerivedValueCase, object_owner::Owner, outcome::Failure,
};
use fe11::*;
use std::{fs::File, io::Read, path::Path};

enum Cipher {
    Aes,
    Des,
    Des3,
}
enum Mode {
    Ecb,
    Cbc8([u8; 8]),
    Cbc16([u8; 16]),
}
pub struct Vector {
    advanced: bool,
    cipher: Cipher,
    mode: Mode,
    key: Vec<u8>,
    data: Vec<u8>,
    expected: Vec<u8>,
}

impl DerivedValueCase for Vector {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("vector_open"))?
            .take(1048577)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("vector_read"))?;
        if bytes.len() > 1048576 {
            return Err(Failure::Input("vector_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("vector_encoding"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if fields.len() != 6 || !matches!(fields[0], "session" | "advanced") {
            return Err(Failure::Input("encrypt_data_fields"));
        }
        let (cipher, cbc) = match fields[1] {
            "CKM_AES_ECB_ENCRYPT_DATA" => (Cipher::Aes, false),
            "CKM_AES_CBC_ENCRYPT_DATA" => (Cipher::Aes, true),
            "CKM_DES_ECB_ENCRYPT_DATA" => (Cipher::Des, false),
            "CKM_DES_CBC_ENCRYPT_DATA" => (Cipher::Des, true),
            "CKM_DES3_ECB_ENCRYPT_DATA" => (Cipher::Des3, false),
            "CKM_DES3_CBC_ENCRYPT_DATA" => (Cipher::Des3, true),
            _ => return Err(Failure::Input("encrypt_data_selector")),
        };
        let key = hex(fields[2], 32).map_err(Failure::Input)?;
        let iv = hex(fields[3], 16).map_err(Failure::Input)?;
        let data = hex(fields[4], 262144).map_err(Failure::Input)?;
        let expected = hex(fields[5], 262144).map_err(Failure::Input)?;
        let block = if matches!(cipher, Cipher::Aes) { 16 } else { 8 };
        let key_valid = match cipher {
            Cipher::Aes => matches!(key.len(), 16 | 24 | 32),
            Cipher::Des => key.len() == 8,
            Cipher::Des3 => matches!(key.len(), 16 | 24),
        };
        if !key_valid || data.len() != expected.len() || data.is_empty() || data.len() % block != 0
        {
            return Err(Failure::Input("encrypt_data_dimensions"));
        }
        let mode = if !cbc {
            if !iv.is_empty() {
                return Err(Failure::Input("ecb_iv_present"));
            }
            Mode::Ecb
        } else if block == 16 {
            Mode::Cbc16(iv.try_into().map_err(|_| Failure::Input("aes_iv_length"))?)
        } else {
            Mode::Cbc8(iv.try_into().map_err(|_| Failure::Input("des_iv_length"))?)
        };
        Ok(Self {
            advanced: fields[0] == "advanced",
            cipher,
            mode,
            key,
            data,
            expected,
        })
    }
    fn advanced(&self) -> bool {
        self.advanced
    }
    fn import(&self, owner: &Owner) -> Result<NativeObjectRef> {
        self.import_usage(owner, true)
    }
    fn parameters(&self) -> NativeKeyDerivation<'_> {
        let data = self.data.as_slice();
        let parameters = match (&self.cipher, &self.mode) {
            (Cipher::Aes, Mode::Ecb) => NativeEncryptData::AesEcb(data),
            (Cipher::Des, Mode::Ecb) => NativeEncryptData::DesEcb(data),
            (Cipher::Des3, Mode::Ecb) => NativeEncryptData::Des3Ecb(data),
            (Cipher::Aes, Mode::Cbc16(iv)) => NativeEncryptData::AesCbc { iv: *iv, data },
            (Cipher::Des, Mode::Cbc8(iv)) => NativeEncryptData::DesCbc { iv: *iv, data },
            (Cipher::Des3, Mode::Cbc8(iv)) => NativeEncryptData::Des3Cbc { iv: *iv, data },
            // Private representation is constructed exclusively by the checked parser.
            _ => unreachable!("cipher and IV width checked when reading the fixture"),
        };
        NativeKeyDerivation::EncryptData(parameters)
    }
    fn expected(&self) -> &[u8] {
        &self.expected
    }
}

impl Vector {
    pub(super) fn import_usage(&self, owner: &Owner, allowed: bool) -> Result<NativeObjectRef> {
        let key_type = match self.cipher {
            Cipher::Aes => fe11_sys::CKK_AES,
            Cipher::Des => fe11_sys::CKK_DES,
            Cipher::Des3 if self.key.len() == 16 => fe11_sys::CKK_DES2,
            Cipher::Des3 => fe11_sys::CKK_DES3,
        };
        owner.import_secret_usages(
            &self.key,
            key_type,
            [
                (StandardAttribute::DERIVE, allowed),
                (StandardAttribute::ENCRYPT, false),
            ],
        )
    }
}
