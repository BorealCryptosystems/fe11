// SPDX-License-Identifier: Apache-2.0
//! Bounded DSA/ECDSA signing vectors with public known test private scalars.
use super::{arguments::hex, outcome::Failure};
use fe11::NativeSignatureAlgorithm;
use std::{fs::File, io::Read, path::Path};

pub struct Vector {
    pub advanced: bool,
    pub ecdsa: bool,
    pub algorithm: NativeSignatureAlgorithm,
    pub multipart: bool,
    pub width: usize,
    pub lengths: Vec<usize>,
    pub parameters: Vec<Vec<u8>>,
    pub input: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Vector {
    pub fn read(path: &Path) -> Result<Self, Failure> {
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
        let f: Vec<_> = text.split_terminator('\n').collect();
        if f.len() != 14
            || !matches!(f[0], "session" | "advanced")
            || !matches!(f[1], "ecdsa" | "dsa")
            || !matches!(f[3], "single" | "both")
        {
            return Err(Failure::Input("classical_signature_fields"));
        }
        let algorithm = match f[2] {
            "CKM_ECDSA" => NativeSignatureAlgorithm::ECDSA,
            "CKM_ECDSA_SHA1" => NativeSignatureAlgorithm::ECDSA_SHA1,
            "CKM_ECDSA_SHA224" => NativeSignatureAlgorithm::ECDSA_SHA224,
            "CKM_ECDSA_SHA256" => NativeSignatureAlgorithm::ECDSA_SHA256,
            "CKM_ECDSA_SHA384" => NativeSignatureAlgorithm::ECDSA_SHA384,
            "CKM_ECDSA_SHA512" => NativeSignatureAlgorithm::ECDSA_SHA512,
            "CKM_ECDSA_SHA3_224" => NativeSignatureAlgorithm::ECDSA_SHA3_224,
            "CKM_ECDSA_SHA3_256" => NativeSignatureAlgorithm::ECDSA_SHA3_256,
            "CKM_ECDSA_SHA3_384" => NativeSignatureAlgorithm::ECDSA_SHA3_384,
            "CKM_ECDSA_SHA3_512" => NativeSignatureAlgorithm::ECDSA_SHA3_512,
            "CKM_DSA" => NativeSignatureAlgorithm::DSA,
            "CKM_DSA_SHA1" => NativeSignatureAlgorithm::DSA_SHA1,
            "CKM_DSA_SHA224" => NativeSignatureAlgorithm::DSA_SHA224,
            "CKM_DSA_SHA256" => NativeSignatureAlgorithm::DSA_SHA256,
            "CKM_DSA_SHA384" => NativeSignatureAlgorithm::DSA_SHA384,
            "CKM_DSA_SHA512" => NativeSignatureAlgorithm::DSA_SHA512,
            "CKM_DSA_SHA3_224" => NativeSignatureAlgorithm::DSA_SHA3_224,
            "CKM_DSA_SHA3_256" => NativeSignatureAlgorithm::DSA_SHA3_256,
            "CKM_DSA_SHA3_384" => NativeSignatureAlgorithm::DSA_SHA3_384,
            "CKM_DSA_SHA3_512" => NativeSignatureAlgorithm::DSA_SHA3_512,
            _ => return Err(Failure::Input("classical_signature_algorithm")),
        };
        let ecdsa = f[1] == "ecdsa";
        if ecdsa != f[2].starts_with("CKM_ECDSA")
            || (f[3] == "single") != matches!(f[2], "CKM_DSA" | "CKM_ECDSA")
        {
            return Err(Failure::Input("classical_signature_route"));
        }
        let width: usize = f[4]
            .parse()
            .map_err(|_| Failure::Input("signature_width"))?;
        if width == 0 || width > 72 {
            return Err(Failure::Input("signature_width"));
        }
        let lengths: Vec<usize> = f[5]
            .split(',')
            .map(|n| n.parse().map_err(|_| Failure::Input("part_length")))
            .collect::<Result<_, _>>()?;
        let input = hex(f[12], 262144).map_err(Failure::Input)?;
        let signature = hex(f[13], 2 * width).map_err(Failure::Input)?;
        if signature.len() != 2 * width {
            return Err(Failure::Input("published_signature_width"));
        }
        if lengths.is_empty()
            || lengths.len() > 1024
            || lengths
                .iter()
                .try_fold(0usize, |sum, n| sum.checked_add(*n))
                != Some(input.len())
        {
            return Err(Failure::Input("part_dimensions"));
        }
        let parameters = f[7..12]
            .iter()
            .map(|p| hex(p, 512).map_err(Failure::Input))
            .collect::<Result<Vec<_>, _>>()?;
        if parameters[0].is_empty()
            || parameters[3].is_empty()
            || parameters[4].is_empty()
            || (!ecdsa && (parameters[1].is_empty() || parameters[2].is_empty()))
        {
            return Err(Failure::Input("classical_signature_key"));
        }
        Ok(Self {
            advanced: f[0] == "advanced",
            ecdsa,
            algorithm,
            multipart: f[3] == "both",
            width,
            lengths,
            parameters,
            input,
            signature,
        })
    }
}
