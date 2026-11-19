// SPDX-License-Identifier: Apache-2.0
//! Exact symmetric transport tuples, with no implicit padding or IV conversion.
use super::{arguments::hex, outcome::Failure};
use fe11::*;
use std::{fs::File, io::Read, path::Path};

pub struct Case {
    pub wrap: bool,
    pub usage: bool,
    pub template_mutation: String,
    pub key: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub iv: Vec<u8>,
    pub mechanism: NativeTransportMechanism,
    pub key_type: fe11_sys::CK_KEY_TYPE,
}
impl Case {
    pub fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(8193)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if bytes.len() > 8192 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("fixture_encoding"))?;
        let f: Vec<_> = text.split_terminator('\n').collect();
        if f.len() != 7
            || !matches!(f[1], "wrap" | "unwrap")
            || !matches!(
                f[2],
                "usage" | "template" | "missing-type" | "conflicting-type" | "read-only"
            )
            || (f[1] == "wrap" && f[2] != "usage")
        {
            return Err(Failure::Input("transport_fields"));
        }
        let (mechanism, key_type, iv_length) = match f[0] {
            "CKM_DES_ECB" => (NativeTransportMechanism::DES_ECB, fe11_sys::CKK_DES, 0),
            "CKM_DES_CBC" => (NativeTransportMechanism::DES_CBC, fe11_sys::CKK_DES, 8),
            "CKM_DES_CBC_PAD" => (NativeTransportMechanism::DES_CBC_PAD, fe11_sys::CKK_DES, 8),
            "CKM_DES3_CBC" => (NativeTransportMechanism::DES3_CBC, fe11_sys::CKK_DES3, 8),
            "CKM_DES3_CBC_PAD" => (
                NativeTransportMechanism::DES3_CBC_PAD,
                fe11_sys::CKK_DES3,
                8,
            ),
            "CKM_AES_CBC" => (NativeTransportMechanism::AES_CBC, fe11_sys::CKK_AES, 16),
            "CKM_AES_CBC_PAD" => (NativeTransportMechanism::AES_CBC_PAD, fe11_sys::CKK_AES, 16),
            "CKM_AES_KEY_WRAP" => (NativeTransportMechanism::AES_KEY_WRAP, fe11_sys::CKK_AES, 0),
            "CKM_AES_KEY_WRAP_PAD" => (
                NativeTransportMechanism::AES_KEY_WRAP_PAD,
                fe11_sys::CKK_AES,
                0,
            ),
            _ => return Err(Failure::Input("transport_mechanism")),
        };
        let key = hex(f[3], 32).map_err(Failure::Input)?;
        let plaintext = hex(f[4], 1024).map_err(Failure::Input)?;
        let ciphertext = hex(f[5], 1056).map_err(Failure::Input)?;
        let iv = hex(f[6], 16).map_err(Failure::Input)?;
        if iv.len() != iv_length || plaintext.is_empty() || ciphertext.is_empty() {
            return Err(Failure::Input("transport_dimensions"));
        }
        if (key_type == fe11_sys::CKK_DES && key.len() != 8)
            || (key_type == fe11_sys::CKK_DES3 && !matches!(key.len(), 16 | 24))
            || (key_type == fe11_sys::CKK_AES && !matches!(key.len(), 16 | 24 | 32))
        {
            return Err(Failure::Input("transport_key_length"));
        }
        Ok(Self {
            wrap: f[1] == "wrap",
            usage: f[2] == "usage",
            template_mutation: f[2].into(),
            key,
            plaintext,
            ciphertext,
            iv,
            mechanism,
            key_type,
        })
    }
    pub fn parameters(&self) -> NativeTransportParameters<'_> {
        NativeTransportParameters::Fixed {
            mechanism: self.mechanism,
            bytes: if self.iv.is_empty() {
                None
            } else {
                Some(&self.iv)
            },
        }
    }
}
