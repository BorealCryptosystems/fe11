// SPDX-License-Identifier: Apache-2.0
//! Generated ML-KEM owners and retained native results for lifecycle checks.
use super::{
    configuration::{select_token, Configuration},
    credentials::Credentials,
    outcome::Failure,
};
use fe11::*;

fn attr(
    attribute: StandardAttribute,
    value: AttributeInputValue<'static>,
) -> AttributeInput<'static> {
    AttributeInput {
        attribute: attribute.into(),
        value,
    }
}
fn boolean(attribute: StandardAttribute, value: bool) -> AttributeInput<'static> {
    attr(attribute, AttributeInputValue::Boolean(value))
}
fn unsigned(attribute: StandardAttribute, value: u64) -> AttributeInput<'static> {
    attr(attribute, AttributeInputValue::Unsigned(value))
}
fn template<'a>(attributes: &'a [AttributeInput<'a>]) -> GenerationTemplate<'a> {
    GenerationTemplate {
        attributes,
        limits: AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: attributes.len(),
            maximum_value_bytes: 128,
        },
        observation: None,
        destination: DestinationPlan {
            search: DestinationSearchPlan::NotRequested,
            user: DestinationUserObservation::NotRequested,
        },
    }
}

pub struct Fixture {
    pub session: Session,
    pub pair: Option<NativeKeyPair>,
    denied: Option<NativeObjectRef>,
    imported_public: Option<NativeObjectRef>,
    pub objects: Vec<CreatedObjectSet>,
    pub results: Vec<NativeKemResult>,
    pub values: Vec<SecretBytes>,
    pub closed: bool,
    pub logged: bool,
    ciphertext_bytes: usize,
}
impl Fixture {
    pub fn open(module: &Module, config: &Configuration) -> std::result::Result<Self, Failure> {
        let token = select_token(module, &config.label).ok_or(Failure::Input("kem_token"))?;
        Ok(Self {
            session: module.select(&token)?.open_session(true)?,
            pair: None,
            denied: None,
            imported_public: None,
            objects: vec![],
            results: vec![],
            values: vec![],
            closed: false,
            logged: false,
            ciphertext_bytes: 768,
        })
    }
    pub fn prepare(
        &mut self,
        pins: &Credentials,
        explicit_set: Option<u64>,
    ) -> std::result::Result<(), Failure> {
        let set = explicit_set.unwrap_or(fe11_sys::CKP_ML_KEM_512 as u64);
        let public_bytes = if set == fe11_sys::CKP_ML_KEM_512 as u64 {
            self.ciphertext_bytes = 768;
            800
        } else if set == fe11_sys::CKP_ML_KEM_768 as u64 {
            self.ciphertext_bytes = 1088;
            1184
        } else if set == fe11_sys::CKP_ML_KEM_1024 as u64 {
            self.ciphertext_bytes = 1568;
            1568
        } else {
            return Err(Failure::Input("kem_parameter_set"));
        };
        self.session
            .login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        self.logged = true;
        let public = [
            unsigned(StandardAttribute::CLASS, fe11_sys::CKO_PUBLIC_KEY as u64),
            unsigned(StandardAttribute::KEY_TYPE, fe11_sys::CKK_ML_KEM as u64),
            unsigned(StandardAttribute::PARAMETER_SET, set),
            boolean(StandardAttribute::TOKEN, false),
            boolean(StandardAttribute::PRIVATE, false),
            boolean(StandardAttribute::ENCAPSULATE, true),
        ];
        let private = [
            unsigned(StandardAttribute::CLASS, fe11_sys::CKO_PRIVATE_KEY as u64),
            unsigned(StandardAttribute::KEY_TYPE, fe11_sys::CKK_ML_KEM as u64),
            boolean(StandardAttribute::TOKEN, false),
            boolean(StandardAttribute::PRIVATE, true),
            boolean(StandardAttribute::SENSITIVE, true),
            boolean(StandardAttribute::EXTRACTABLE, false),
            boolean(StandardAttribute::DECAPSULATE, true),
        ];
        let created = self.session.generate_native_key_pair(
            KeyPairGenerator::ML_KEM_KEY_PAIR_GEN,
            template(&public),
            template(&private),
        )?;
        self.objects.push(created.objects);
        if created.remainder.is_some() || self.objects.last().map_or(0, |x| x.as_slice().len()) != 2
        {
            return Err(Failure::Oracle("kem_pair_ownership"));
        }
        self.pair = Some(created.observation?);
        if explicit_set.is_some() {
            let pair = self.pair.as_ref().ok_or(Failure::Input("kem_pair"))?;
            // Parameter identity belongs to both objects. Private key bytes
            // stay non-extractable; only the public encoding length is read.
            for object in [pair.public.native(), pair.private.native()] {
                let value = self.session.read_flat_attribute(
                    object,
                    StandardAttribute::PARAMETER_SET,
                    FlatAttributeReadPlan::Buffer { capacity: 8 },
                )?;
                if value.calls != (AttributeReadCalls::Direct { code: 0 })
                    || value.unsigned()? != set
                {
                    return Err(Failure::Oracle("kem_generated_parameter_identity"));
                }
            }
            let public = self.session.read_flat_attribute(
                pair.public.native(),
                StandardAttribute::VALUE,
                FlatAttributeReadPlan::Buffer {
                    capacity: public_bytes,
                },
            )?;
            if public.calls != (AttributeReadCalls::Direct { code: 0 }) {
                return Err(Failure::Oracle("kem_generated_public_status"));
            }
            match public.value {
                FlatAttributeValue::Available(bytes) if bytes.as_bytes().len() == public_bytes => {
                    ()
                }
                _ => return Err(Failure::Oracle("kem_generated_public_width")),
            }
        }
        Ok(())
    }
    /// Re-import the generated public encoding. The private half stays with
    /// the module and serves as the independent peer for decapsulation.
    pub fn import_public(&mut self, set: u64, width: usize) -> std::result::Result<(), Failure> {
        let pair = self.pair.as_ref().ok_or(Failure::Input("kem_pair"))?;
        let read = |key: &NativeObjectRef, attribute, capacity| {
            self.session.read_flat_attribute(key, attribute, FlatAttributeReadPlan::Buffer { capacity })
        };
        let original = read(pair.public.native(), StandardAttribute::VALUE, width)?;
        let FlatAttributeValue::Available(bytes) = original.value else {
            return Err(Failure::Oracle("kem_public_encoding_absent"));
        };
        if original.calls != (AttributeReadCalls::Direct { code: 0 }) || bytes.as_bytes().len() != width {
            return Err(Failure::Oracle("kem_public_encoding_width"));
        }
        let class = fe11_sys::CKO_PUBLIC_KEY as u64;
        let key_type = fe11_sys::CKK_ML_KEM as u64;
        let attributes = [
            unsigned(StandardAttribute::CLASS, class),
            unsigned(StandardAttribute::KEY_TYPE, key_type),
            unsigned(StandardAttribute::PARAMETER_SET, set),
            boolean(StandardAttribute::TOKEN, false),
            boolean(StandardAttribute::PRIVATE, false),
            boolean(StandardAttribute::ENCAPSULATE, true),
            AttributeInput {
                attribute: StandardAttribute::VALUE.into(),
                value: AttributeInputValue::Bytes(bytes.as_bytes()),
            },
        ];
        let imported = self.session.create_native_object(&attributes, AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: attributes.len(),
            maximum_value_bytes: width + 3 * std::mem::size_of::<fe11_sys::CK_ULONG>() + 3,
        })?;
        self.imported_public = Some(imported);
        let key = self.imported_public.as_ref().ok_or(Failure::Oracle("kem_import_owner"))?;
        for (attribute, expected) in [(StandardAttribute::CLASS, class),
            (StandardAttribute::KEY_TYPE, key_type), (StandardAttribute::PARAMETER_SET, set)] {
            let value = read(key, attribute, std::mem::size_of::<fe11_sys::CK_ULONG>())?;
            if value.calls != (AttributeReadCalls::Direct { code: 0 }) || value.unsigned()? != expected {
                return Err(Failure::Oracle("kem_import_identity"));
            }
        }
        let reread = read(key, StandardAttribute::VALUE, width)?;
        if reread.calls != (AttributeReadCalls::Direct { code: 0 })
            || !matches!(reread.value, FlatAttributeValue::Available(value) if value.as_bytes() == bytes.as_bytes()) {
            return Err(Failure::Oracle("kem_import_encoding_changed"));
        }
        Ok(())
    }
    pub fn call(
        &mut self,
        encapsulate: bool,
        ciphertext: &[u8],
        incomplete: bool,
    ) -> std::result::Result<usize, Failure> {
        let pair = self.pair.as_ref().ok_or(Failure::Input("kem_pair"))?;
        let mut attributes = vec![
            unsigned(StandardAttribute::CLASS, fe11_sys::CKO_SECRET_KEY as u64),
            unsigned(
                StandardAttribute::KEY_TYPE,
                fe11_sys::CKK_GENERIC_SECRET as u64,
            ),
            unsigned(StandardAttribute::VALUE_LEN, 32),
            boolean(StandardAttribute::TOKEN, false),
            boolean(StandardAttribute::PRIVATE, false),
            boolean(StandardAttribute::SENSITIVE, false),
            boolean(StandardAttribute::EXTRACTABLE, true),
        ];
        if incomplete {
            attributes.remove(0);
        }
        let created = if encapsulate {
            self.session.encapsulate_native(
                Some(self.denied.as_ref().or(self.imported_public.as_ref()).unwrap_or(pair.public.native())),
                NativeKemParameters::MlKem,
                self.ciphertext_bytes,
                template(&attributes),
            )
        } else {
            self.session.decapsulate_native(
                Some(self.denied.as_ref().unwrap_or(pair.private.native())),
                NativeKemParameters::MlKem,
                ciphertext,
                template(&attributes),
            )
        }?;
        self.objects.push(created.objects);
        if created.remainder.is_some() || self.objects.last().map_or(0, |x| x.as_slice().len()) != 1
        {
            return Err(Failure::Oracle("kem_result_ownership"));
        }
        self.results.push(created.observation?);
        let index = self.results.len() - 1;
        let result = &self.results[index];
        if if encapsulate {
            result
                .ciphertext()
                .map_or(true, |v| v.len() != self.ciphertext_bytes)
        } else {
            result.ciphertext().is_some()
        } {
            return Err(Failure::Oracle("kem_ciphertext_shape"));
        }
        let read = self.session.read_flat_attribute(
            result.object.native(),
            StandardAttribute::VALUE,
            FlatAttributeReadPlan::Buffer { capacity: 32 },
        )?;
        if read.calls != (AttributeReadCalls::Direct { code: 0 }) {
            return Err(Failure::Oracle("kem_value_status"));
        }
        let FlatAttributeValue::Available(value) = read.value else {
            return Err(Failure::Oracle("kem_value_missing"));
        };
        if value.as_bytes().len() != 32 {
            return Err(Failure::Oracle("kem_value_length"));
        }
        let mut secret = SecretBytes::new(32)?;
        secret.as_mut_slice().copy_from_slice(value.as_bytes());
        self.values.push(secret);
        Ok(index)
    }
    pub fn matching_pair(&mut self) -> std::result::Result<(usize, usize), Failure> {
        let sender = self.call(true, &[], false)?;
        let ciphertext = self.results[sender]
            .ciphertext()
            .ok_or(Failure::Oracle("kem_ciphertext_missing"))?
            .to_vec();
        let receiver = self.call(false, &ciphertext, false)?;
        if self.values[sender].as_slice() != self.values[receiver].as_slice() {
            return Err(Failure::Oracle("kem_shared_secrets_differ"));
        }
        Ok((sender, receiver))
    }
    pub fn deny_usage(&mut self, encapsulate: bool) -> std::result::Result<(), Failure> {
        let pair = self.pair.as_ref().ok_or(Failure::Input("kem_pair"))?;
        let key = if encapsulate {
            pair.public.native()
        } else {
            pair.private.native()
        };
        let attributes = [boolean(
            if encapsulate {
                StandardAttribute::ENCAPSULATE
            } else {
                StandardAttribute::DECAPSULATE
            },
            false,
        )];
        // Copy the actual successful key, changing exactly one usage attribute.
        // Retain the returned object before any subsequent assertion can fail.
        self.denied = Some(self.session.copy_native_object(
            key,
            &attributes,
            AttributeTemplateLimits {
                maximum_depth: 0,
                maximum_attributes: 1,
                maximum_value_bytes: 1,
            },
        )?);
        Ok(())
    }
    pub fn close(&mut self) -> std::result::Result<(), Failure> {
        self.session.close()?;
        self.closed = true;
        Ok(())
    }
    pub fn cleanup(&mut self) -> Vec<Failure> {
        let mut failures = Vec::new();
        if !self.closed {
            // Session objects survive assertion failures in these retained sets.
            // Destroy each published object before logout can hide private keys.
            if self.logged {
                for key in self.denied.iter().chain(self.imported_public.iter()) {
                    if let Err(error) = self.session.destroy_native_object(key) {
                        failures.push(error.into());
                    }
                }
                for set in &self.objects {
                    for object in set.as_slice() {
                        if let Err(error) = self.session.destroy_native_object(object) {
                            failures.push(error.into());
                        }
                    }
                }
            }
            if self.logged {
                if let Err(error) = self.session.logout() {
                    failures.push(error.into());
                }
            }
            if let Err(error) = self.close() {
                failures.push(error);
            }
        }
        failures
    }
}
