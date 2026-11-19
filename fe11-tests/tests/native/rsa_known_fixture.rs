// SPDX-License-Identifier: Apache-2.0
//! Bounded known-answer RSA fixtures with explicit operation and encoding.
use super::{arguments::hex, outcome::Failure, rsa_parameters};
use fe11::*;
use std::{fs::File, io::Read, path::Path};

pub enum Algorithm {
    Cipher(NativeRsaCipherParameters<'static>),
    Signature(NativeSignatureParameters<'static>),
}

#[derive(Clone, Copy)]
pub enum NegativeKind {
    ChangedMessage,
    WrongKey,
    PssDigestLength,
    PssHashMismatch,
}

pub struct Vector {
    pub advanced: bool,
    pub action: String,
    pub algorithm: Algorithm,
    pub multipart: bool,
    pub randomized: bool,
    pub length_boundaries: bool,
    pub cipher_refusal: Option<u64>,
    pub negative: Option<NegativeKind>,
    pub negative_signature: Option<Vec<u8>>,
    pub key: Vec<Vec<u8>>,
    pub input: Vec<u8>,
    pub expected: Vec<u8>,
    pub lengths: Vec<usize>,
}

impl Vector {
    pub fn signature(&self) -> std::result::Result<NativeSignatureParameters<'static>, Failure> {
        match &self.algorithm {
            Algorithm::Signature(NativeSignatureParameters::Parameterless(algorithm)) => {
                Ok(NativeSignatureParameters::Parameterless(*algorithm))
            }
            Algorithm::Signature(NativeSignatureParameters::RsaPss {
                algorithm,
                hash,
                mgf,
                salt_bytes,
            }) => Ok(NativeSignatureParameters::RsaPss {
                algorithm: *algorithm,
                hash: *hash,
                mgf: *mgf,
                salt_bytes: *salt_bytes,
            }),
            _ => Err(Failure::Input("rsa_known_signature_route")),
        }
    }

    pub fn cipher(&self) -> std::result::Result<NativeRsaCipherParameters<'static>, Failure> {
        match &self.algorithm {
            Algorithm::Cipher(NativeRsaCipherParameters::Pkcs1v15) => {
                Ok(NativeRsaCipherParameters::Pkcs1v15)
            }
            Algorithm::Cipher(NativeRsaCipherParameters::X509) => {
                Ok(NativeRsaCipherParameters::X509)
            }
            _ => Err(Failure::Input("rsa_known_cipher_route")),
        }
    }

    pub fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("vector_open"))?
            .take(32769)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("vector_read"))?;
        if bytes.len() > 32768 {
            return Err(Failure::Input("vector_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("vector_encoding"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if !matches!(fields.len(), 17 | 18)
            || !matches!(fields[0], "session" | "advanced")
            || !matches!(fields[1], "sign" | "verify" | "encrypt" | "decrypt")
            || !matches!(
                fields[3],
                "exact"
                    | "randomized"
                    | "length-boundaries"
                    | "changed-message"
                    | "wrong-key"
                    | "pss-digest-length"
                    | "pss-hash-mismatch"
                    | "cipher-length"
                    | "cipher-range"
            )
        {
            return Err(Failure::Input("rsa_known_fields"));
        }
        if (fields[3] == "wrong-key") != (fields.len() == 18) {
            return Err(Failure::Input("rsa_wrong_key_fields"));
        }
        if fields[3] == "length-boundaries"
            && (fields[1] != "verify" || fields[2] != "CKM_SHA256_RSA_PKCS")
        {
            return Err(Failure::Input("rsa_length_boundary_route"));
        }
        let negative = match fields[3] {
            "changed-message" if fields[1] == "verify" && fields[2] == "CKM_SHA256_RSA_PKCS" => {
                Some(NegativeKind::ChangedMessage)
            }
            "wrong-key" if fields[1] == "verify" && fields[2] == "CKM_SHA256_RSA_PKCS" => {
                Some(NegativeKind::WrongKey)
            }
            "pss-digest-length"
                if matches!(fields[1], "sign" | "verify")
                    && fields[2] == "CKM_RSA_PKCS_PSS"
                    && fields[4] == "SHA256" =>
            {
                Some(NegativeKind::PssDigestLength)
            }
            "pss-hash-mismatch"
                if matches!(fields[1], "sign" | "verify")
                    && fields[2] == "CKM_SHA256_RSA_PKCS_PSS"
                    && fields[4] == "SHA256" =>
            {
                Some(NegativeKind::PssHashMismatch)
            }
            "exact" | "randomized" | "length-boundaries" => None,
            "cipher-length" if fields[1] == "encrypt" && fields[2] == "CKM_RSA_PKCS" => None,
            "cipher-range" if fields[1] == "encrypt" && fields[2] == "CKM_RSA_X_509" => None,
            _ => return Err(Failure::Input("rsa_negative_route")),
        };
        let cipher = matches!(fields[1], "encrypt" | "decrypt");
        let algorithm = if cipher {
            Algorithm::Cipher(match fields[2] {
                "CKM_RSA_PKCS" => NativeRsaCipherParameters::Pkcs1v15,
                "CKM_RSA_X_509" => NativeRsaCipherParameters::X509,
                _ => return Err(Failure::Input("rsa_known_cipher")),
            })
        } else if fields[2].ends_with("_PSS") {
            let raw = fields[2] == "CKM_RSA_PKCS_PSS";
            let name = if raw {
                fields[4]
            } else {
                fields[2]
                    .strip_prefix("CKM_")
                    .and_then(|s| s.strip_suffix("_RSA_PKCS_PSS"))
                    .ok_or(Failure::Input("rsa_known_pss"))?
            };
            let hash = rsa_parameters::hash(name)?;
            let salt_bytes = fields[5]
                .parse()
                .map_err(|_| Failure::Input("rsa_known_salt"))?;
            if salt_bytes != hash.bytes as u64 {
                return Err(Failure::Input("rsa_known_salt"));
            }
            Algorithm::Signature(NativeSignatureParameters::RsaPss {
                algorithm: if raw {
                    NativePssAlgorithm::RSA_PKCS_PSS
                } else {
                    hash.combined
                },
                hash: hash.number,
                mgf: hash.mgf,
                salt_bytes,
            })
        } else {
            let algorithm = match fields[2] {
                "CKM_RSA_PKCS" => NativeSignatureAlgorithm::RSA_PKCS,
                "CKM_RSA_X_509" => NativeSignatureAlgorithm::RSA_X_509,
                "CKM_MD5_RSA_PKCS" => NativeSignatureAlgorithm::MD5_RSA_PKCS,
                "CKM_SHA1_RSA_PKCS" => NativeSignatureAlgorithm::SHA1_RSA_PKCS,
                "CKM_SHA224_RSA_PKCS" => NativeSignatureAlgorithm::SHA224_RSA_PKCS,
                "CKM_SHA256_RSA_PKCS" => NativeSignatureAlgorithm::SHA256_RSA_PKCS,
                "CKM_SHA384_RSA_PKCS" => NativeSignatureAlgorithm::SHA384_RSA_PKCS,
                "CKM_SHA512_RSA_PKCS" => NativeSignatureAlgorithm::SHA512_RSA_PKCS,
                "CKM_SHA3_224_RSA_PKCS" => NativeSignatureAlgorithm::SHA3_224_RSA_PKCS,
                "CKM_SHA3_256_RSA_PKCS" => NativeSignatureAlgorithm::SHA3_256_RSA_PKCS,
                "CKM_SHA3_384_RSA_PKCS" => NativeSignatureAlgorithm::SHA3_384_RSA_PKCS,
                "CKM_SHA3_512_RSA_PKCS" => NativeSignatureAlgorithm::SHA3_512_RSA_PKCS,
                _ => return Err(Failure::Input("rsa_known_signature")),
            };
            Algorithm::Signature(NativeSignatureParameters::Parameterless(algorithm))
        };
        let key = fields[6..14]
            .iter()
            .map(|v| hex(v, 1024).map_err(Failure::Input))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if key.iter().any(Vec::is_empty) || key[0].len() != 256 {
            return Err(Failure::Input("rsa_known_key"));
        }
        let input = hex(fields[14], 256).map_err(Failure::Input)?;
        let expected = hex(fields[15], 256).map_err(Failure::Input)?;
        let cipher_refusal = match fields[3] {
            "cipher-length" if input.len() == 246 && expected.is_empty() => {
                Some(fe11_sys::CKR_DATA_LEN_RANGE as u64)
            }
            "cipher-range"
                if input.len() == 256
                    && input.as_slice() >= key[0].as_slice()
                    && expected.is_empty() =>
            {
                Some(fe11_sys::CKR_GENERAL_ERROR as u64)
            }
            "cipher-length" | "cipher-range" => return Err(Failure::Input("rsa_cipher_boundary")),
            _ => None,
        };
        let negative_signature = fields
            .get(17)
            .map(|value| hex(value, 256).map_err(Failure::Input))
            .transpose()?;
        if negative_signature
            .as_ref()
            .is_some_and(|value| value.len() != 256)
        {
            return Err(Failure::Input("rsa_wrong_key_signature_width"));
        }
        let lengths = fields[16]
            .split(',')
            .map(|n| {
                n.parse::<usize>()
                    .map_err(|_| Failure::Input("part_length"))
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if lengths.is_empty()
            || lengths.len() > 16
            || lengths.iter().try_fold(0usize, |a, b| a.checked_add(*b)) != Some(input.len())
        {
            return Err(Failure::Input("part_dimensions"));
        }
        Ok(Self {
            advanced: fields[0] == "advanced",
            action: fields[1].to_owned(),
            algorithm,
            multipart: !cipher
                && !matches!(
                    fields[2],
                    "CKM_RSA_X_509" | "CKM_RSA_PKCS" | "CKM_RSA_PKCS_PSS"
                ),
            randomized: fields[3] == "randomized",
            length_boundaries: fields[3] == "length-boundaries",
            cipher_refusal,
            negative,
            negative_signature,
            key,
            input,
            expected,
            lengths,
        })
    }
}
