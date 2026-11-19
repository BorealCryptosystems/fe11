// SPDX-License-Identifier: Apache-2.0
//! Publicly distributed RSA test keys and explicit OAEP algorithm selectors.
use super::{arguments::hex, object_owner::Owner, outcome::Failure};
use fe11::*;
use std::{fs::File, io::Read, path::Path};

pub struct Vector {
    pub advanced: bool,
    pub valid: bool,
    pub hash: u64,
    pub mgf: u64,
    pub key: Vec<Vec<u8>>,
    pub label: Vec<u8>,
    pub label_present: bool,
    pub contract: Option<String>,
    pub ciphertext: Vec<u8>,
    pub plaintext: Vec<u8>,
}

impl Vector {
    pub fn read(path: &Path) -> std::result::Result<Self, Failure> {
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
        if !matches!(fields.len(), 15 | 16) {
            return Err(Failure::Input("vector_fields"));
        }
        let advanced = match fields[0] {
            "session" => false,
            "advanced" => true,
            _ => return Err(Failure::Input("cipher_owner")),
        };
        let valid = match fields[1] {
            "valid" => true,
            "invalid" => false,
            _ => return Err(Failure::Input("cipher_oracle")),
        };
        let hash = match fields[2] {
            "SHA-1" => fe11_sys::CKM_SHA_1,
            "SHA-224" => fe11_sys::CKM_SHA224,
            "SHA-256" => fe11_sys::CKM_SHA256,
            "SHA-384" => fe11_sys::CKM_SHA384,
            "SHA-512" => fe11_sys::CKM_SHA512,
            "SHA3-224" => fe11_sys::CKM_SHA3_224,
            "SHA3-256" => fe11_sys::CKM_SHA3_256,
            "SHA3-384" => fe11_sys::CKM_SHA3_384,
            "SHA3-512" => fe11_sys::CKM_SHA3_512,
            "SHA-512/224" => fe11_sys::CKM_SHA512_224,
            "SHA-512/256" => fe11_sys::CKM_SHA512_256,
            _ => return Err(Failure::Input("oaep_hash")),
        } as u64;
        let mgf = match fields[3] {
            "SHA-1" => fe11_sys::CKG_MGF1_SHA1,
            "SHA-224" => fe11_sys::CKG_MGF1_SHA224,
            "SHA-256" => fe11_sys::CKG_MGF1_SHA256,
            "SHA-384" => fe11_sys::CKG_MGF1_SHA384,
            "SHA-512" => fe11_sys::CKG_MGF1_SHA512,
            "SHA3-224" => fe11_sys::CKG_MGF1_SHA3_224,
            "SHA3-256" => fe11_sys::CKG_MGF1_SHA3_256,
            "SHA3-384" => fe11_sys::CKG_MGF1_SHA3_384,
            "SHA3-512" => fe11_sys::CKG_MGF1_SHA3_512,
            _ => return Err(Failure::Input("oaep_mask")),
        } as u64;
        let key = fields[4..12]
            .iter()
            .map(|value| hex(value, 1024).map_err(Failure::Input))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if key.iter().any(Vec::is_empty) {
            return Err(Failure::Input("rsa_key_component"));
        }
        let contract = fields.get(15).copied();
        if contract.is_some_and(|name| {
            !matches!(
                name,
                "roundtrip" | "wrong-key" | "wrong-label" | "altered" | "length" | "continuation"
            )
        }) || (contract.is_none() && fields[12] == "-")
        {
            return Err(Failure::Input("oaep_contract"));
        }
        Ok(Self {
            advanced,
            valid,
            hash,
            mgf,
            key,
            label: if fields[12] == "-" {
                Vec::new()
            } else {
                hex(fields[12], 65536).map_err(Failure::Input)?
            },
            label_present: fields[12] != "-",
            contract: contract.map(str::to_owned),
            ciphertext: hex(fields[13], 65536).map_err(Failure::Input)?,
            plaintext: hex(fields[14], 65536).map_err(Failure::Input)?,
        })
    }

    pub fn parameters(&self) -> NativeRsaCipherParameters<'_> {
        NativeRsaCipherParameters::Oaep(NativeOaepParameters {
            hash: self.hash,
            mgf: self.mgf,
            source: fe11_sys::CKZ_DATA_SPECIFIED as u64,
            data: self.label_present.then_some(self.label.as_slice()),
        })
    }

    pub fn import(&self, owner: &Owner) -> Result<NativeObjectRef> {
        owner.import_rsa_private(&self.key, StandardAttribute::DECRYPT)
    }

    pub fn decrypt(&self, owner: &Owner, key: &NativeObjectRef) -> Result<ExtensionResult> {
        let limits = InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: self.ciphertext.len(),
        };
        match owner {
            Owner::Session(session) => session.decrypt_native_rsa(
                key,
                self.parameters(),
                &self.ciphertext,
                self.key[0].len(),
                limits,
                None,
            ),
            Owner::Advanced(session) => session.decrypt_native_rsa(
                key,
                self.parameters(),
                &self.ciphertext,
                self.key[0].len(),
                limits,
                None,
            ),
        }
    }
}
