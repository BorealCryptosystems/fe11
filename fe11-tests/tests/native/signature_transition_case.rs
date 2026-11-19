// SPDX-License-Identifier: Apache-2.0
//! Exact inputs and independent deterministic outputs for signature continuations.
use super::{arguments::hex, object_owner::Owner, outcome::Failure};
use fe11::*;
use std::{fs::File, io::Read, path::Path};

enum Material {
    Hmac(Vec<u8>),
    Rsa(Vec<Vec<u8>>),
    RsaSingle(Vec<Vec<u8>>),
    Pqc(super::signature_transition_pqc::Material),
    Edwards(super::signature_transition_edwards::Material),
    Ecdsa(super::signature_transition_ecdsa::Material),
}

pub struct Case {
    pub state: String,
    pub action: String,
    pub sign: bool,
    pub input: Vec<u8>,
    pub width: usize,
    material: Material,
    expected: [Vec<u8>; 3],
    other_key: Option<Vec<Vec<u8>>>,
}

impl Case {
    pub fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if bytes.len() > 65536 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("fixture_encoding"))?;
        let f: Vec<_> = text.split_terminator('\n').collect();
        if !matches!(f.len(), 8 | 9 | 16 | 24)
            || !matches!(f[2], "sign" | "verify")
            || !matches!(
                f[0],
                "IDLE"
                    | "INITIALIZED"
                    | "MULTIPART_ACTIVE"
                    | "OUTPUT_REQUIRED"
                    | "OUTPUT_STORAGE_SELECTED"
                    | "CONSUMED"
                    | "RETIRED"
                    | "REFUSED_TERMINAL"
                    | "TICKET_DROPPED"
            )
            || !matches!(
                f[1],
                "init"
                    | "init_other_key"
                    | "update"
                    | "final"
                    | "provide_capacity"
                    | "provide_0"
                    | "provide_31"
                    | "provide_32"
                    | "provide_33"
                    | "provide_255"
                    | "provide_256"
                    | "provide_257"
                    | "poll"
                    | "logout"
                    | "close"
                    | "capture"
                    | "cancel"
                    | "drop_ticket"
            )
        {
            return Err(Failure::Input("signature_transition_fields"));
        }
        let (material, input, width, outputs) = if f.len() == 8 {
            let key = hex(f[3], 131).map_err(Failure::Input)?;
            let input = hex(f[4], 54).map_err(Failure::Input)?;
            if key.len() != 131 || input.len() != 54 {
                return Err(Failure::Input("mac_transition_dimensions"));
            }
            (Material::Hmac(key), input, 32, [f[5], f[6], f[7]])
        } else if f.len() == 9 && matches!(f[3], "ECDSA-P256" | "ECDSA-SHA256-P256") {
            let material = super::signature_transition_ecdsa::Material::read(&f)?;
            let raw = f[3] == "ECDSA-P256";
            let input = hex(f[7], if raw { 32 } else { 4096 }).map_err(Failure::Input)?;
            if f[0] == "MULTIPART_ACTIVE" || (raw && input.len() != 32) {
                return Err(Failure::Input("ecdsa_single_digest_width"));
            }
            (Material::Ecdsa(material), input, 64, [f[8]; 3])
        } else if f.len() == 9 && f[3] == "ED-25519" {
            let material = super::signature_transition_edwards::Material::read(&f)?;
            let input = hex(f[7], 4096).map_err(Failure::Input)?;
            if f[0] == "MULTIPART_ACTIVE" {
                return Err(Failure::Input("single_signature_state"));
            }
            (Material::Edwards(material), input, 64, [f[8]; 3])
        } else if f.len() == 9 {
            let material = super::signature_transition_pqc::Material::read(&f)?;
            let input = hex(f[7], 4096).map_err(Failure::Input)?;
            if f[0] == "MULTIPART_ACTIVE" {
                return Err(Failure::Input("single_signature_state"));
            }
            let width = material.parameters.signature_bytes;
            (Material::Pqc(material), input, width, [f[8]; 3])
        } else {
            if !matches!(f[3], "rsa-sha256-pkcs" | "rsa-sha256-pkcs-single") {
                return Err(Failure::Input("signature_transition_profile"));
            }
            let key = f[4..12]
                .iter()
                .map(|v| hex(v, 256).map_err(Failure::Input))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let input = hex(f[12], 3).map_err(Failure::Input)?;
            if key[0].len() != 256 || key.iter().any(Vec::is_empty) || input != b"abc" {
                return Err(Failure::Input("rsa_transition_dimensions"));
            }
            let material = if f[3] == "rsa-sha256-pkcs-single" {
                Material::RsaSingle(key)
            } else {
                Material::Rsa(key)
            };
            (material, input, 256, [f[13], f[14], f[15]])
        };
        let expected = [
            hex(outputs[0], width).map_err(Failure::Input)?,
            hex(outputs[1], width).map_err(Failure::Input)?,
            hex(outputs[2], width).map_err(Failure::Input)?,
        ];
        if expected.iter().any(|v| v.len() != width)
            || (f[1].starts_with("provide_")
                && f[1] != "provide_capacity"
                && !f[1]
                    .strip_prefix("provide_")
                    .and_then(|v| v.parse::<usize>().ok())
                    .is_some_and(|v| [0, width - 1, width, width + 1].contains(&v)))
            || (f[2] == "verify" && matches!(f[0], "OUTPUT_REQUIRED" | "OUTPUT_STORAGE_SELECTED"))
        {
            return Err(Failure::Input("signature_transition_dimensions"));
        }
        let other_key = if f.len() == 24 {
            if f[1] != "init_other_key" || f[0] != "INITIALIZED" || f[2] != "sign" {
                return Err(Failure::Input("rsa_other_key_context"));
            }
            let values = f[16..24]
                .iter()
                .map(|v| hex(v, 256).map_err(Failure::Input))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if values[0].len() != 256 || values.iter().any(Vec::is_empty) || f[16] == f[4] {
                return Err(Failure::Input("rsa_other_key_dimensions"));
            }
            Some(values)
        } else {
            if f[1] == "init_other_key" {
                return Err(Failure::Input("rsa_other_key_missing"));
            }
            None
        };
        Ok(Self {
            state: f[0].into(),
            action: f[1].into(),
            sign: f[2] == "sign",
            input,
            width,
            material,
            expected,
            other_key,
        })
    }
    pub fn expected(&self, submitted: u64) -> std::result::Result<&[u8], Failure> {
        if self.single() && submitted != 1 {
            return Err(Failure::Input("single_signature_submission_count"));
        }
        self.expected
            .get(submitted as usize)
            .map(Vec::as_slice)
            .ok_or(Failure::Input("signature_submission_count"))
    }
    pub fn import(&self, owner: &Owner, allowed: bool) -> Result<NativeObjectRef> {
        match &self.material {
            Material::Ecdsa(material) => material.import(owner, self.sign, allowed),
            Material::Edwards(material) => material.import(owner, self.sign, allowed),
            Material::Pqc(material) => material.import(owner, self.sign, allowed),
            Material::Hmac(key) => owner.import_secret_usages(
                key,
                fe11_sys::CKK_GENERIC_SECRET,
                [
                    (StandardAttribute::SIGN, allowed),
                    (StandardAttribute::VERIFY, allowed),
                ],
            ),
            Material::Rsa(key) | Material::RsaSingle(key) if self.sign => {
                owner.import_rsa_private_usage(key, StandardAttribute::SIGN, allowed)
            }
            Material::Rsa(key) | Material::RsaSingle(key) => owner.import_rsa_public_usage_enabled(
                &key[0],
                &key[1],
                StandardAttribute::VERIFY,
                allowed,
            ),
        }
    }
    pub fn import_other(&self, owner: &Owner) -> Result<Option<NativeObjectRef>> {
        self.other_key
            .as_ref()
            .map(|key| owner.import_rsa_private_usage(key, StandardAttribute::SIGN, true))
            .transpose()
    }
    pub fn begin(
        &self,
        session: &AdvancedSession,
        key: &NativeObjectRef,
        capacity: usize,
    ) -> Result<OperationTicket> {
        let output = SignatureOutputPlan::Buffer { capacity };
        match &self.material {
            Material::Ecdsa(material) if self.sign => {
                session.begin_native_sign_single(key, material.mechanism(), output, 2 * self.width)
            }
            Material::Ecdsa(material) => {
                session.begin_native_verify_single(key, material.mechanism())
            }
            Material::Edwards(material) if self.sign => {
                session.begin_native_sign_single(key, material.mechanism(), output, 2 * self.width)
            }
            Material::Edwards(material) => {
                session.begin_native_verify_single(key, material.mechanism())
            }
            Material::RsaSingle(_) if self.sign => session.begin_native_sign_single(
                key,
                NativeSignatureParameters::Parameterless(NativeSignatureAlgorithm::SHA256_RSA_PKCS),
                output,
                2 * self.width,
            ),
            Material::RsaSingle(_) => session.begin_native_verify_single(
                key,
                NativeSignatureParameters::Parameterless(NativeSignatureAlgorithm::SHA256_RSA_PKCS),
            ),
            Material::Pqc(material) if self.sign => {
                session.begin_native_sign_single(key, material.mechanism(), output, 2 * self.width)
            }
            Material::Pqc(material) => {
                session.begin_native_verify_single(key, material.mechanism())
            }
            Material::Hmac(_) if self.sign => session.begin_native_mac_stream(
                key,
                NativeMacParameters::Full(NativeMacAlgorithm::SHA256_HMAC),
                output,
                2 * self.width,
            ),
            Material::Hmac(_) => session.begin_native_mac_verify_stream(
                key,
                NativeMacParameters::Full(NativeMacAlgorithm::SHA256_HMAC),
            ),
            Material::Rsa(_) if self.sign => session.begin_native_sign_stream(
                key,
                NativeSignatureParameters::Parameterless(NativeSignatureAlgorithm::SHA256_RSA_PKCS),
                output,
                2 * self.width,
            ),
            Material::Rsa(_) => session.begin_native_verify_stream(
                key,
                NativeSignatureParameters::Parameterless(NativeSignatureAlgorithm::SHA256_RSA_PKCS),
            ),
        }
    }
    pub fn single(&self) -> bool {
        matches!(
            self.material,
            Material::Pqc(_) | Material::Edwards(_) | Material::Ecdsa(_) | Material::RsaSingle(_)
        )
    }
    pub fn external_signature_reference(&self) -> bool {
        self.sign && matches!(self.material, Material::Ecdsa(_))
    }
}
