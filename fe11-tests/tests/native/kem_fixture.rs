// SPDX-License-Identifier: Apache-2.0
//! Published ML-KEM decapsulation vectors, including implicit-rejection secrets.
use super::{arguments::hex, object_owner::Owner, outcome::Failure};
use fe11::*;
use std::{fs::File, io::Read, path::Path};

pub struct Vector {
    pub advanced: bool,
    set: u64,
    private: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub expected: Vec<u8>,
    pub length_negative: bool,
}
impl Vector {
    pub fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("vector_open"))?
            .take(16385)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("vector_read"))?;
        if bytes.len() > 16384 {
            return Err(Failure::Input("vector_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("vector_encoding"))?;
        let f: Vec<_> = text.split_terminator('\n').collect();
        if !matches!(f.len(), 5 | 6) || !matches!(f[0], "session" | "advanced") {
            return Err(Failure::Input("kem_fields"));
        }
        let (set, private_bytes, ciphertext_bytes) = match f[1] {
            "ML-KEM-512" => (fe11_sys::CKP_ML_KEM_512, 1632, 768),
            "ML-KEM-768" => (fe11_sys::CKP_ML_KEM_768, 2400, 1088),
            "ML-KEM-1024" => (fe11_sys::CKP_ML_KEM_1024, 3168, 1568),
            _ => return Err(Failure::Input("kem_parameter_set")),
        };
        let mut v = Self {
            advanced: f[0] == "advanced",
            set: set as u64,
            private: hex(f[2], 3168).map_err(Failure::Input)?,
            ciphertext: hex(f[3], 1568).map_err(Failure::Input)?,
            expected: hex(f[4], 32).map_err(Failure::Input)?,
            length_negative: f.len() == 6,
        };
        if v.private.len() != private_bytes
            || v.ciphertext.len() != ciphertext_bytes
            || v.expected.len() != 32
        {
            return Err(Failure::Input("kem_dimensions"));
        }
        // Validate the published tuple before applying exactly one mutation.
        // Existing five-field KATs retain their exact-width requirement.
        if v.length_negative {
            match f[5] {
                "empty" => v.ciphertext.clear(),
                "short" => {
                    v.ciphertext.pop();
                }
                "long" => v.ciphertext.push(0),
                _ => return Err(Failure::Input("kem_length_mutation")),
            }
        }
        Ok(v)
    }
    pub fn import(&self, owner: &Owner) -> Result<NativeObjectRef> {
        let attr = |attribute: StandardAttribute, value| AttributeInput {
            attribute: attribute.into(),
            value,
        };
        // These are public ACVP test keys. Session-local, non-private objects
        // avoid introducing authentication or persistent state into the KAT.
        let attributes = [
            attr(
                StandardAttribute::CLASS,
                AttributeInputValue::Unsigned(fe11_sys::CKO_PRIVATE_KEY as u64),
            ),
            attr(
                StandardAttribute::KEY_TYPE,
                AttributeInputValue::Unsigned(fe11_sys::CKK_ML_KEM as u64),
            ),
            attr(
                StandardAttribute::PARAMETER_SET,
                AttributeInputValue::Unsigned(self.set),
            ),
            attr(
                StandardAttribute::TOKEN,
                AttributeInputValue::Boolean(false),
            ),
            attr(
                StandardAttribute::PRIVATE,
                AttributeInputValue::Boolean(false),
            ),
            attr(
                StandardAttribute::DECAPSULATE,
                AttributeInputValue::Boolean(true),
            ),
            attr(
                StandardAttribute::VALUE,
                AttributeInputValue::Bytes(&self.private),
            ),
        ];
        owner.create(
            &attributes,
            AttributeTemplateLimits {
                maximum_depth: 0,
                maximum_attributes: attributes.len(),
                maximum_value_bytes: self.private.len() + 27,
            },
        )
    }
    pub fn check(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        retained: &mut Option<CreatedObjectSet>,
        observed_refusal: &mut Option<Error>,
    ) -> std::result::Result<(), Failure> {
        let attr = |attribute: StandardAttribute, value| AttributeInput {
            attribute: attribute.into(),
            value,
        };
        let attributes = [
            attr(
                StandardAttribute::CLASS,
                AttributeInputValue::Unsigned(fe11_sys::CKO_SECRET_KEY as u64),
            ),
            attr(
                StandardAttribute::KEY_TYPE,
                AttributeInputValue::Unsigned(fe11_sys::CKK_GENERIC_SECRET as u64),
            ),
            attr(
                StandardAttribute::TOKEN,
                AttributeInputValue::Boolean(false),
            ),
            attr(
                StandardAttribute::PRIVATE,
                AttributeInputValue::Boolean(false),
            ),
            attr(
                StandardAttribute::SENSITIVE,
                AttributeInputValue::Boolean(false),
            ),
            attr(
                StandardAttribute::EXTRACTABLE,
                AttributeInputValue::Boolean(true),
            ),
            attr(
                StandardAttribute::VALUE_LEN,
                AttributeInputValue::Unsigned(32),
            ),
        ];
        let output = GenerationTemplate {
            attributes: &attributes,
            limits: AttributeTemplateLimits {
                maximum_depth: 0,
                maximum_attributes: attributes.len(),
                maximum_value_bytes: 28,
            },
            observation: None,
            destination: DestinationPlan {
                search: DestinationSearchPlan::NotRequested,
                user: DestinationUserObservation::NotRequested,
            },
        };
        let result = match owner {
            Owner::Session(s) => s.decapsulate_native(
                Some(key),
                NativeKemParameters::MlKem,
                &self.ciphertext,
                output,
            ),
            Owner::Advanced(s) => s.decapsulate_native(
                Some(key),
                NativeKemParameters::MlKem,
                &self.ciphertext,
                output,
            ),
        };
        let created = match result {
            Err(error) if self.length_negative && length_refusal(&error) => {
                *observed_refusal = Some(error);
                return Ok(());
            }
            Err(error) => return Err(error.into()),
            Ok(created) => created,
        };
        // Retain creation ownership before any observation can fail; cleanup
        // destroys every returned object even if the expected bytes disagree.
        *retained = Some(created.objects);
        if self.length_negative {
            return Err(Failure::Oracle("kem_invalid_ciphertext_length_accepted"));
        }
        if created.remainder.is_some() {
            return Err(Failure::Oracle("kem_unexpected_remainder"));
        }
        let view = created.observation?;
        if view.ciphertext().is_some() {
            return Err(Failure::Oracle("decapsulation_returned_ciphertext"));
        }
        let objects = retained
            .as_ref()
            .ok_or(Failure::Input("kem_created_owner"))?
            .as_slice();
        if objects.len() != 1 {
            return Err(Failure::Oracle("kem_created_object_count"));
        }
        let plan = FlatAttributeReadPlan::Buffer { capacity: 32 };
        let observed = match owner {
            Owner::Session(s) => s.read_flat_attribute(&objects[0], StandardAttribute::VALUE, plan),
            Owner::Advanced(s) => {
                s.read_flat_attribute(&objects[0], StandardAttribute::VALUE, plan)
            }
        }?;
        if observed.calls != (AttributeReadCalls::Direct { code: 0 }) {
            return Err(Failure::Oracle("kem_shared_native_status"));
        }
        match observed.value {
            FlatAttributeValue::Available(value) if value.as_bytes() == self.expected => Ok(()),
            _ => Err(Failure::Oracle("kem_published_shared_secret")),
        }
    }
}

fn length_refusal(error: &Error) -> bool {
    match error {
        Error::ObjectsMayRemain(cause) => length_refusal(cause),
        Error::Native {
            function: "C_DecapsulateKey",
            code,
            ..
        } => {
            // PKCS#11 permits GENERAL_ERROR without proving non-creation.
            // Keep ObjectsMayRemain and may_have_effect in the recorded error;
            // this oracle only asserts that no shared secret was published.
            *code == fe11_sys::CKR_WRAPPED_KEY_LEN_RANGE as u64
                || *code == fe11_sys::CKR_GENERAL_ERROR as u64
        }
        _ => false,
    }
}
