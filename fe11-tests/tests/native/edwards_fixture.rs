// SPDX-License-Identifier: Apache-2.0
//! Edwards vectors retain the seed, public point, context and prehash flag verbatim.
use super::{arguments::hex, outcome::Failure};
use fe11::*;
use std::{fs::File, io::Read, path::Path};

pub struct Vector {
    pub advanced: bool,
    pub sign: bool,
    pub valid: bool,
    pub width: usize,
    pub signature_width: usize,
    pub parameters: Vec<u8>,
    pub prehash: bool,
    pub context: Vec<u8>,
    pub public: Vec<u8>,
    pub private: Vec<u8>,
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Vector {
    pub fn mechanism(&self, present: bool) -> NativeSignatureParameters<'_> {
        NativeSignatureParameters::EdDsa(Some(NativeEdDsaParameters {
            prehash: self.prehash,
            context: if present { Some(&self.context) } else { None },
        }))
    }

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
        let f: Vec<_> = text.split_terminator('\n').collect();
        if f.len() != 11
            || !matches!(f[0], "session" | "advanced")
            || !matches!(f[1], "sign" | "verify")
            || !matches!(f[2], "valid" | "invalid")
            || !matches!(f[5], "false" | "true")
        {
            return Err(Failure::Input("edwards_fields"));
        }
        let (width, signature_width) = match f[3] {
            "ED-25519" => (32, 64),
            "ED-448" => (57, 114),
            _ => return Err(Failure::Input("edwards_curve")),
        };
        let decode = |index, limit| hex(f[index], limit).map_err(Failure::Input);
        let v = Self {
            advanced: f[0] == "advanced",
            sign: f[1] == "sign",
            valid: f[2] == "valid",
            width,
            signature_width,
            parameters: decode(4, 32)?,
            prehash: f[5] == "true",
            context: decode(6, 255)?,
            public: decode(7, 57)?,
            private: decode(8, 57)?,
            message: decode(9, 262144)?,
            signature: decode(10, 115)?,
        };
        if v.public.len() != v.width
            || v.parameters.is_empty()
            || (v.sign && (!v.valid || v.private.len() != v.width))
            || (v.valid && v.signature.len() != v.signature_width)
        {
            return Err(Failure::Input("edwards_dimensions"));
        }
        Ok(v)
    }
}
