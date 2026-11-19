// SPDX-License-Identifier: Apache-2.0
//! Minimal complete AES and P-256 templates, with one required-field negative.
use super::{
    generation_fixture::{Field, Fixture, Generator, Value},
    outcome::Failure,
};
use fe11::*;
use std::{fs::File, io::Read, path::Path};

pub struct Case {
    pub pair: bool,
    pub state: String,
    pub action: String,
}
impl Case {
    pub fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(513)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if bytes.len() > 512 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("fixture_encoding"))?;
        let f: Vec<_> = text.split_terminator('\n').collect();
        if f.len() != 3
            || !matches!(f[0], "single" | "pair")
            || !matches!(f[1], "IDLE" | "CONSUMED" | "REFUSED_TERMINAL" | "RETIRED")
            || !matches!(f[2], "init" | "take" | "logout" | "close")
        {
            return Err(Failure::Input("direct_generation_fields"));
        }
        Ok(Self {
            pair: f[0] == "pair",
            state: f[1].into(),
            action: f[2].into(),
        })
    }
    pub fn template(&self, label: &str, invalid: bool) -> Fixture {
        let uint = |attribute, value| Field {
            attribute,
            value: Value::Unsigned(value),
        };
        let boolean = |attribute, value| Field {
            attribute,
            value: Value::Boolean(value),
        };
        let bytes = |attribute, value| Field {
            attribute,
            value: Value::Bytes(value),
        };
        let mut public = vec![
            uint(
                StandardAttribute::CLASS,
                if self.pair {
                    fe11_sys::CKO_PUBLIC_KEY
                } else {
                    fe11_sys::CKO_SECRET_KEY
                } as u64,
            ),
            uint(
                StandardAttribute::KEY_TYPE,
                if self.pair {
                    fe11_sys::CKK_EC
                } else {
                    fe11_sys::CKK_AES
                } as u64,
            ),
            boolean(StandardAttribute::PRIVATE, false),
            boolean(StandardAttribute::TOKEN, false),
            bytes(StandardAttribute::LABEL, label.as_bytes().to_vec()),
        ];
        let mut private = Vec::new();
        if self.pair {
            public.push(boolean(StandardAttribute::VERIFY, true));
            if !invalid {
                public.push(bytes(
                    StandardAttribute::EC_PARAMS,
                    vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
                ));
            }
            private = vec![
                uint(StandardAttribute::CLASS, fe11_sys::CKO_PRIVATE_KEY as u64),
                uint(StandardAttribute::KEY_TYPE, fe11_sys::CKK_EC as u64),
                boolean(StandardAttribute::PRIVATE, false),
                boolean(StandardAttribute::TOKEN, false),
                boolean(StandardAttribute::SIGN, true),
                bytes(StandardAttribute::LABEL, label.as_bytes().to_vec()),
            ];
        } else {
            public.push(boolean(StandardAttribute::ENCRYPT, true));
            public.push(boolean(StandardAttribute::DECRYPT, true));
            if !invalid {
                public.push(uint(StandardAttribute::VALUE_LEN, 16));
            }
        }
        Fixture {
            generator: if self.pair {
                Generator::Pair(KeyPairGenerator::EC_KEY_PAIR_GEN)
            } else {
                Generator::Single(KeyGenerator::AES_KEY_GEN)
            },
            public,
            private,
            pqc_witness: None,
            rsa_witness: false,
            domain_witness: false,
            secret_witness: false,
            disabled_use: None,
            protection_matrix: false,
            lifetime: false,
        }
    }
    pub fn function(&self) -> &'static str {
        if self.pair {
            "C_GenerateKeyPair"
        } else {
            "C_GenerateKey"
        }
    }
    pub fn count(&self) -> usize {
        if self.pair {
            2
        } else {
            1
        }
    }
}
