// SPDX-License-Identifier: Apache-2.0
//! Bounded published key material and explicit direct-operation transitions.
use super::{arguments::hex, outcome::Failure};
use std::{fs::File, io::Read, path::Path};

pub struct Case {
    pub route: String,
    pub state: String,
    pub action: String,
    pub key: Vec<u8>,
    pub input: Vec<u8>,
    pub expected: Vec<u8>,
}
impl Case {
    pub fn read(path: &Path) -> Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if bytes.len() > 4096 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("fixture_encoding"))?;
        let f: Vec<_> = text.split_terminator('\n').collect();
        if f.len() != 6
            || !matches!(f[0], "wrap" | "unwrap" | "derive")
            || !matches!(f[1], "IDLE" | "CONSUMED" | "REFUSED_TERMINAL" | "RETIRED")
            || !matches!(f[2], "init" | "take" | "logout" | "close")
            || (f[2] == "take" && f[1] != "CONSUMED")
        {
            return Err(Failure::Input("direct_material_fields"));
        }
        let key = hex(f[3], 32).map_err(Failure::Input)?;
        let input = hex(f[4], 1024).map_err(Failure::Input)?;
        let expected = hex(f[5], 1024).map_err(Failure::Input)?;
        let valid = match f[0] {
            "wrap" => {
                input.len() >= 16 && input.len() % 8 == 0 && expected.len() == input.len() + 8
            }
            "unwrap" => {
                expected.len() >= 16 && expected.len() % 8 == 0 && input.len() == expected.len() + 8
            }
            "derive" => !input.is_empty() && input.len() % 16 == 0 && expected.len() == input.len(),
            _ => false,
        };
        if !matches!(key.len(), 16 | 24 | 32) || !valid {
            return Err(Failure::Input("direct_material_dimensions"));
        }
        Ok(Self {
            route: f[0].into(),
            state: f[1].into(),
            action: f[2].into(),
            key,
            input,
            expected,
        })
    }
    pub fn function(&self) -> &'static str {
        match self.route.as_str() {
            "wrap" => "C_WrapKey",
            "unwrap" => "C_UnwrapKey",
            _ => "C_DeriveKey",
        }
    }
    pub fn refusal_code(&self) -> u64 {
        if self.route == "wrap" {
            fe11_sys::CKR_KEY_FUNCTION_NOT_PERMITTED as u64
        } else {
            fe11_sys::CKR_TEMPLATE_INCOMPLETE as u64
        }
    }
}
