// SPDX-License-Identifier: Apache-2.0
//! Exact external-message PQC vectors; no prehash or context rewriting.
use super::{arguments::hex, outcome::Failure, pqc_parameters::Parameters};
use fe11::*;
use std::{fs::File, io::Read, path::Path};

pub struct Vector {
    pub advanced: bool,
    pub sign: bool,
    pub valid: bool,
    pub randomized: bool,
    pub multipart: bool,
    pub preferred_hedging: bool,
    /// Read the private VALUE with an explicitly selected sensitivity flag.
    pub export_sensitive: Option<bool>,
    pub parameters: Parameters,
    pub public: Vec<u8>,
    pub private: Vec<u8>,
    pub context: Vec<u8>,
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
    pub(super) absent: Option<super::pqc_absent::Selector>,
}

impl Vector {
    pub fn mechanism(&self) -> NativeSignatureParameters<'_> {
        NativeSignatureParameters::PqcPure {
            family: self.parameters.family,
            parameters: Some(NativePqcContext {
                hedging: if self.preferred_hedging {
                    PqcHedging::Preferred
                } else if self.randomized {
                    PqcHedging::Required
                } else {
                    PqcHedging::DeterministicRequired
                },
                context: Some(&self.context),
            }),
        }
    }

    pub fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("vector_open"))?
            .take(262145)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("vector_read"))?;
        if bytes.len() > 262144 {
            return Err(Failure::Input("vector_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("vector_encoding"))?;
        let f: Vec<_> = text.split_terminator('\n').collect();
        if !matches!(f.len(), 9 | 11)
            || !matches!(f[0], "session" | "advanced")
            || !matches!(f[1], "sign" | "verify")
            || !matches!(
                f[2],
                "valid"
                    | "multipart"
                    | "invalid"
                    | "randomized"
                    | "preferred"
                    | "export-value"
                    | "export-sensitive"
            )
        {
            return Err(Failure::Input("pqc_fields"));
        }
        let parameters = Parameters::parse(f[3])?;
        let absent = if f.len() == 11 {
            if f[0] != "session" || f[2] != "valid" {
                return Err(Failure::Input("pqc_absent_control"));
            }
            Some(super::pqc_absent::Selector::read(
                f[9],
                f[10],
                parameters.family,
            )?)
        } else {
            None
        };
        let decode = |index, limit| hex(f[index], limit).map_err(Failure::Input);
        let vector = Self {
            advanced: f[0] == "advanced",
            sign: f[1] == "sign",
            valid: f[2] != "invalid",
            randomized: matches!(f[2], "randomized" | "preferred"),
            multipart: f[2] == "multipart",
            preferred_hedging: f[2] == "preferred",
            export_sensitive: match f[2] {
                "export-value" => Some(false),
                "export-sensitive" => Some(true),
                _ => None,
            },
            parameters,
            public: decode(4, 2592)?,
            private: decode(5, 4896)?,
            context: decode(6, 255)?,
            message: decode(7, 65536)?,
            signature: decode(8, 49857)?,
            absent,
        };
        if ((vector.randomized || vector.export_sensitive.is_some()) && !vector.sign)
            || vector.public.len() != vector.parameters.public_bytes
            || (vector.sign
                && (vector.private.len() != vector.parameters.private_bytes || !vector.valid))
            || (vector.valid && vector.signature.len() != vector.parameters.signature_bytes)
        {
            return Err(Failure::Input("pqc_dimensions"));
        }
        Ok(vector)
    }
}
