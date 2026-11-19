// SPDX-License-Identifier: Apache-2.0
//! Public prerequisites for absent-mechanism checks, separate from their oracles.
use super::{arguments::hex, object_owner::Owner, outcome::Failure};
use fe11::*;
use std::{fs::File, io::Read, path::Path};

pub struct Case {
    pub family: String,
    pub operation: String,
    pub compatible: bool,
    pub input: Vec<u8>,
    pub signature: Vec<u8>,
    gost_value: Vec<u8>,
    rsa: Vec<Vec<u8>>,
}

pub const DIGEST_OID: &[u8] = &[6, 7, 42, 133, 3, 2, 2, 30, 1];
pub const CURVE_OID: &[u8] = &[6, 7, 42, 133, 3, 2, 2, 35, 1];

impl Case {
    pub fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut data = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(8193)
            .read_to_end(&mut data)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if data.len() > 8192 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&data).map_err(|_| Failure::Input("fixture_encoding"))?;
        let f: Vec<_> = text.split_terminator('\n').collect();
        if f.len() != 14
            || !matches!(f[0], "digest" | "mac" | "pair" | "raw" | "combined")
            || !matches!(f[1], "digest" | "sign" | "verify" | "generate_pair")
            || !matches!(f[2], "compatible" | "rsa")
        {
            return Err(Failure::Input("absent_mechanism_fields"));
        }
        let case = Self {
            family: f[0].into(),
            operation: f[1].into(),
            compatible: f[2] == "compatible",
            input: hex(f[3], 64).map_err(Failure::Input)?,
            signature: hex(f[4], 256).map_err(Failure::Input)?,
            gost_value: hex(f[5], 64).map_err(Failure::Input)?,
            rsa: f[6..14]
                .iter()
                .map(|v| hex(v, 256).map_err(Failure::Input))
                .collect::<std::result::Result<_, _>>()?,
        };
        if !matches!(
            (case.family.as_str(), case.operation.as_str()),
            ("digest", "digest")
                | ("pair", "generate_pair")
                | ("mac" | "raw" | "combined", "sign" | "verify")
        ) || (case.family == "raw" && case.input.len() != 32)
            || (case.family == "mac" && case.signature.len() != 32)
            || (case.signature_key()
                && case.compatible
                && case.gost_value.len() != if case.sign() { 32 } else { 64 })
            || (case.signature_key()
                && !case.compatible
                && (case.rsa[0].len() != 256 || case.rsa.iter().any(Vec::is_empty)))
        {
            return Err(Failure::Input("absent_mechanism_dimensions"));
        }
        Ok(case)
    }
    pub fn sign(&self) -> bool {
        self.operation == "sign"
    }
    pub fn signature_key(&self) -> bool {
        matches!(self.family.as_str(), "raw" | "combined")
    }
    pub fn mechanism(&self) -> u64 {
        match self.family.as_str() {
            "digest" => fe11_sys::CKM_GOSTR3411 as u64,
            "mac" => fe11_sys::CKM_GOSTR3411_HMAC as u64,
            "pair" => fe11_sys::CKM_GOSTR3410_KEY_PAIR_GEN as u64,
            "raw" => fe11_sys::CKM_GOSTR3410 as u64,
            _ => fe11_sys::CKM_GOSTR3410_WITH_GOSTR3411 as u64,
        }
    }
    pub fn parameters(&self) -> NativeSignatureParameters<'_> {
        if self.family == "raw" {
            NativeSignatureParameters::Parameterless(NativeSignatureAlgorithm::GOSTR3410)
        } else if self.compatible {
            // This single-condition Init explicitly requests the parameterless form.
            NativeSignatureParameters::GostWithDigest { oid: None }
        } else {
            NativeSignatureParameters::GostWithDigest {
                oid: Some(DIGEST_OID),
            }
        }
    }
    pub fn import(&self, owner: &Owner) -> Result<Option<NativeObjectRef>> {
        if self.family == "mac" {
            let value: Vec<_> = (0u8..32).collect();
            return owner
                .import_secret(
                    &value,
                    fe11_sys::CKK_GENERIC_SECRET,
                    [StandardAttribute::SIGN, StandardAttribute::VERIFY],
                )
                .map(Some);
        }
        if !self.signature_key() {
            return Ok(None);
        }
        if !self.compatible {
            return if self.sign() {
                owner.import_rsa_private(&self.rsa, StandardAttribute::SIGN)
            } else {
                owner.import_rsa_public(&self.rsa[0], &self.rsa[1])
            }
            .map(Some);
        }
        let attr = |attribute: StandardAttribute, value| AttributeInput {
            attribute: attribute.into(),
            value,
        };
        let mut attributes = vec![
            attr(
                StandardAttribute::CLASS,
                AttributeInputValue::Unsigned(if self.sign() {
                    fe11_sys::CKO_PRIVATE_KEY
                } else {
                    fe11_sys::CKO_PUBLIC_KEY
                } as u64),
            ),
            attr(
                StandardAttribute::KEY_TYPE,
                AttributeInputValue::Unsigned(fe11_sys::CKK_GOSTR3410 as u64),
            ),
            attr(
                StandardAttribute::TOKEN,
                AttributeInputValue::Boolean(false),
            ),
            attr(
                StandardAttribute::PRIVATE,
                AttributeInputValue::Boolean(self.sign()),
            ),
            attr(
                StandardAttribute::GOSTR3410_PARAMS,
                AttributeInputValue::Bytes(CURVE_OID),
            ),
            attr(
                StandardAttribute::GOSTR3411_PARAMS,
                AttributeInputValue::Bytes(DIGEST_OID),
            ),
            attr(
                StandardAttribute::VALUE,
                AttributeInputValue::Bytes(&self.gost_value),
            ),
            attr(
                if self.sign() {
                    StandardAttribute::SIGN
                } else {
                    StandardAttribute::VERIFY
                },
                AttributeInputValue::Boolean(true),
            ),
        ];
        if self.sign() {
            attributes.push(attr(
                StandardAttribute::SENSITIVE,
                AttributeInputValue::Boolean(false),
            ));
            attributes.push(attr(
                StandardAttribute::EXTRACTABLE,
                AttributeInputValue::Boolean(true),
            ));
        }
        owner
            .create(
                &attributes,
                AttributeTemplateLimits {
                    maximum_depth: 0,
                    maximum_attributes: attributes.len(),
                    maximum_value_bytes: self.gost_value.len() + if self.sign() { 39 } else { 37 },
                },
            )
            .map(Some)
    }
}
