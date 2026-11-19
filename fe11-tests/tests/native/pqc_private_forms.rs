// SPDX-License-Identifier: Apache-2.0
//! Import each public private-key representation without converting its input.
//! The paired public key comes from a published key-generation vector. A native
//! use checks correspondence; successful metadata reads alone do not prove it.
use super::*;

pub(super) struct Case {
    algorithm: PqcPrivateKeyAlgorithm,
    form: String,
    seed: SecretBytes,
    value: SecretBytes,
    public: Vec<u8>,
}

fn secret(bytes: Vec<u8>) -> Result<SecretBytes> {
    // All inputs are public test-vector material. Copies are confined to the
    // fixture; no private data is included in assertion messages or reports.
    let mut result = SecretBytes::new(bytes.len())?;
    result.as_mut_slice().copy_from_slice(&bytes);
    Ok(result)
}

impl Case {
    pub(super) fn read(fields: &[&str]) -> std::result::Result<Self, Failure> {
        if fields.len() != 6 || !matches!(fields[2], "seed" | "value" | "both") {
            return Err(Failure::Input("pqc_private_form_fields"));
        }
        let algorithm = match fields[1] {
            "ML-DSA-44" => PqcPrivateKeyAlgorithm::MlDsa(MlDsaParameterSet::MlDsa44),
            "ML-DSA-65" => PqcPrivateKeyAlgorithm::MlDsa(MlDsaParameterSet::MlDsa65),
            "ML-DSA-87" => PqcPrivateKeyAlgorithm::MlDsa(MlDsaParameterSet::MlDsa87),
            "ML-KEM-512" => PqcPrivateKeyAlgorithm::MlKem(MlKemParameterSet::MlKem512),
            "ML-KEM-768" => PqcPrivateKeyAlgorithm::MlKem(MlKemParameterSet::MlKem768),
            "ML-KEM-1024" => PqcPrivateKeyAlgorithm::MlKem(MlKemParameterSet::MlKem1024),
            _ => return Err(Failure::Input("pqc_private_form_algorithm")),
        };
        let seed = secret(hex(fields[3], 64).map_err(Failure::Input)?)?;
        let value = secret(hex(fields[4], 4896).map_err(Failure::Input)?)?;
        let public = hex(fields[5], 2592).map_err(Failure::Input)?;
        let public_length = match algorithm {
            PqcPrivateKeyAlgorithm::MlDsa(MlDsaParameterSet::MlDsa44) => 1312,
            PqcPrivateKeyAlgorithm::MlDsa(MlDsaParameterSet::MlDsa65) => 1952,
            PqcPrivateKeyAlgorithm::MlDsa(MlDsaParameterSet::MlDsa87) => 2592,
            PqcPrivateKeyAlgorithm::MlKem(set) => set.public_key_length(),
        };
        if seed.len() != algorithm.seed_length()
            || value.len() != algorithm.value_length()
            || public.len() != public_length
        {
            return Err(Failure::Input("pqc_private_form_width"));
        }
        Ok(Self {
            algorithm,
            form: fields[2].into(),
            seed,
            value,
            public,
        })
    }
}

pub(super) fn check(
    session: &Session,
    case: Case,
    label: &str,
    retained: &mut Option<CreatedObjectSet>,
    additional: &mut Vec<NativeObjectRef>,
) -> std::result::Result<(), Failure> {
    let Case {
        algorithm,
        form,
        seed,
        value,
        public,
    } = case;
    let is_signing = matches!(algorithm, PqcPrivateKeyAlgorithm::MlDsa(_));
    let mut admission = object_fixture::public_key_options(label.as_bytes()).admission;
    admission.observation.verify = false;
    admission.observation.sign = is_signing;
    admission.observation.decapsulate = !is_signing;
    let spec = PqcPrivateImportSpec {
        history_observation: generation_transition_spec::history(),
        admission,
        id: label.as_bytes().to_vec(),
        label: label.into(),
        persistent: false,
        protection: CurrentKeyProtection {
            sensitive: true,
            extractable: false,
        },
        usages: KeyUsageRequest {
            sign: is_signing.then_some(true),
            decapsulate: (!is_signing).then_some(true),
            ..KeyUsageRequest::omitted()
        },
        visibility: ObjectVisibility::Public,
    };
    let input = match form.as_str() {
        "seed" => PqcPrivateInput::Seed { algorithm, seed },
        "value" => PqcPrivateInput::Value { algorithm, value },
        "both" => PqcPrivateInput::SeedAndValue {
            algorithm,
            seed,
            value,
        },
        _ => return Err(Failure::Input("pqc_private_form_selector")),
    };
    if input.algorithm() != algorithm {
        return Err(Failure::Oracle("pqc_private_input_identity"));
    }
    let created = session.import_pqc_private_key(
        spec,
        input,
        &public,
        MechanismAttributes {
            request: MechanismRequest::Omitted,
            admission: MechanismObservationPlan::NotRequested,
        },
    )?;
    // Retain ownership before any fallible observation. Every object returned
    // by this test is cleaned even when native import/use or an oracle fails.
    *retained = Some(created.objects);
    if created.remainder.is_some() {
        return Err(Failure::Oracle("pqc_private_import_remainder"));
    }
    let imported = created.observation?;
    if imported.algorithm() != algorithm || imported.input_public_key() != public {
        return Err(Failure::Oracle("pqc_private_import_identity"));
    }
    let private = imported.managed().native_object();
    let (kind, set, capacity) = match algorithm {
        PqcPrivateKeyAlgorithm::MlDsa(MlDsaParameterSet::MlDsa44) => {
            (fe11_sys::CKK_ML_DSA, fe11_sys::CKP_ML_DSA_44, 2420)
        }
        PqcPrivateKeyAlgorithm::MlDsa(MlDsaParameterSet::MlDsa65) => {
            (fe11_sys::CKK_ML_DSA, fe11_sys::CKP_ML_DSA_65, 3309)
        }
        PqcPrivateKeyAlgorithm::MlDsa(MlDsaParameterSet::MlDsa87) => {
            (fe11_sys::CKK_ML_DSA, fe11_sys::CKP_ML_DSA_87, 4627)
        }
        PqcPrivateKeyAlgorithm::MlKem(MlKemParameterSet::MlKem512) => {
            (fe11_sys::CKK_ML_KEM, fe11_sys::CKP_ML_KEM_512, 768)
        }
        PqcPrivateKeyAlgorithm::MlKem(MlKemParameterSet::MlKem768) => {
            (fe11_sys::CKK_ML_KEM, fe11_sys::CKP_ML_KEM_768, 1088)
        }
        PqcPrivateKeyAlgorithm::MlKem(MlKemParameterSet::MlKem1024) => {
            (fe11_sys::CKK_ML_KEM, fe11_sys::CKP_ML_KEM_1024, 1568)
        }
    };
    let attr = |attribute: StandardAttribute, value| AttributeInput {
        attribute: attribute.into(),
        value,
    };
    let template = [
        attr(
            StandardAttribute::CLASS,
            AttributeInputValue::Unsigned(fe11_sys::CKO_PUBLIC_KEY as u64),
        ),
        attr(
            StandardAttribute::KEY_TYPE,
            AttributeInputValue::Unsigned(kind as u64),
        ),
        attr(
            StandardAttribute::PARAMETER_SET,
            AttributeInputValue::Unsigned(set as u64),
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
            if is_signing {
                StandardAttribute::VERIFY
            } else {
                StandardAttribute::ENCAPSULATE
            },
            AttributeInputValue::Boolean(true),
        ),
        attr(
            StandardAttribute::VALUE,
            AttributeInputValue::Bytes(&public),
        ),
    ];
    let key = session.create_native_object(
        &template,
        AttributeTemplateLimits {
            maximum_depth: 0,
            maximum_attributes: template.len(),
            maximum_value_bytes: public.len() + 27,
        },
    )?;
    additional.push(key.clone());
    if is_signing {
        let parameters = || NativeSignatureParameters::PqcPure {
            family: NativePqcFamily::MlDsa,
            parameters: Some(NativePqcContext {
                hedging: PqcHedging::DeterministicRequired,
                context: Some(&[]),
            }),
        };
        let limits = || InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: 3,
        };
        let signature = session.sign_native(
            &private,
            parameters(),
            MessageRoute::Single,
            &[b"abc"],
            limits(),
            capacity,
            None,
        )?;
        if signature.as_bytes().len() != capacity {
            return Err(Failure::Oracle("pqc_private_signature_width"));
        }
        session.verify_native(
            &key,
            parameters(),
            MessageRoute::Single,
            &[b"abc"],
            signature.as_bytes(),
            limits(),
            None,
        )?;
    } else {
        kem_use(session, &private, &key, capacity, additional)?;
    }
    Ok(())
}

fn kem_use(
    session: &Session,
    private: &NativeObjectRef,
    public: &NativeObjectRef,
    capacity: usize,
    retained: &mut Vec<NativeObjectRef>,
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
    let output = || GenerationTemplate {
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
    let enc =
        session.encapsulate_native(Some(public), NativeKemParameters::MlKem, capacity, output())?;
    retained.extend_from_slice(enc.objects.as_slice());
    if enc.objects.as_slice().len() != 1 || enc.remainder.is_some() {
        return Err(Failure::Oracle("pqc_encapsulation_ownership"));
    }
    let view = enc.observation?;
    let ciphertext = view
        .ciphertext()
        .ok_or(Failure::Oracle("pqc_ciphertext_absent"))?;
    if ciphertext.len() != capacity {
        return Err(Failure::Oracle("pqc_ciphertext_width"));
    }
    let dec = session.decapsulate_native(
        Some(private),
        NativeKemParameters::MlKem,
        ciphertext,
        output(),
    )?;
    retained.extend_from_slice(dec.objects.as_slice());
    if dec.objects.as_slice().len() != 1
        || dec.remainder.is_some()
        || dec.observation?.ciphertext().is_some()
    {
        return Err(Failure::Oracle("pqc_decapsulation_ownership"));
    }
    let read = |object| -> std::result::Result<AttributeBytes, Failure> {
        let value = session.read_flat_attribute(
            object,
            StandardAttribute::VALUE,
            FlatAttributeReadPlan::Buffer { capacity: 32 },
        )?;
        if value.calls != (AttributeReadCalls::Direct { code: 0 }) {
            return Err(Failure::Oracle("pqc_shared_read_status"));
        }
        match value.value {
            FlatAttributeValue::Available(bytes) if bytes.as_bytes().len() == 32 => Ok(bytes),
            _ => Err(Failure::Oracle("pqc_shared_read_width")),
        }
    };
    let encapsulated = read(&enc.objects.as_slice()[0])?;
    let decapsulated = read(&dec.objects.as_slice()[0])?;
    if encapsulated.as_bytes() != decapsulated.as_bytes() {
        return Err(Failure::Oracle("pqc_private_public_correspondence"));
    }
    Ok(())
}
