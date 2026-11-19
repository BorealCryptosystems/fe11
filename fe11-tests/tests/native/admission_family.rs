// SPDX-License-Identifier: Apache-2.0
//! Incompatible admission families must fail before native observation of a live object.
use super::{
    arguments::hex,
    configuration::Configuration,
    generation_transition_spec::history,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
    selection_symmetric,
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

struct Case {
    kind: String,
    private: Option<SecretBytes>,
    public: Vec<u8>,
}
impl Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("family_fixture_open"))?
            .take(8193)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("family_fixture_read"))?;
        if bytes.len() > 8192 {
            return Err(Failure::Input("family_fixture_size"));
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| Failure::Input("family_fixture_encoding"))?;
        let f: Vec<_> = text.split_terminator('\n').collect();
        if f == ["data"] || f == ["data_aead"] {
            return Ok(Self {
                kind: f[0].into(),
                private: None,
                public: vec![],
            });
        }
        if f.len() != 3 || !matches!(f[0], "dsa" | "kem" | "kem_legacy") {
            return Err(Failure::Input("family_fixture_fields"));
        }
        let raw = hex(f[1], 2560).map_err(Failure::Input)?;
        let public = hex(f[2], 1312).map_err(Failure::Input)?;
        let expected = if f[0] == "dsa" {
            (2560, 1312)
        } else {
            (1632, 800)
        };
        if (raw.len(), public.len()) != expected {
            return Err(Failure::Input("family_fixture_dimensions"));
        }
        // Public ACVP fixture material only; the native private representation
        // still uses the API's owned secret buffer rather than ordinary bytes.
        let mut private = SecretBytes::new(raw.len())?;
        private.as_mut_slice().copy_from_slice(&raw);
        Ok(Self {
            kind: f[0].into(),
            private: Some(private),
            public,
        })
    }
}

enum Subject {
    Data(ManagedObjectRef),
    Pqc(PqcImportedPrivateKey),
}

fn retain<T>(
    created: CreatedObjects<T>,
    owned: &mut Option<CreatedObjectSet>,
) -> std::result::Result<T, Failure> {
    let count = created.objects.as_slice().len();
    *owned = Some(created.objects);
    if count != 1 || created.remainder.is_some() {
        return Err(Failure::Oracle("family_creation_count"));
    }
    Ok(created.observation?)
}

fn prepare(
    session: &Session,
    case: Case,
    owned: &mut Option<CreatedObjectSet>,
) -> std::result::Result<Subject, Failure> {
    let mut admission = selection_symmetric::key(false).admission;
    if matches!(case.kind.as_str(), "data" | "data_aead") {
        admission.public_attributes = std::sync::Arc::new(vec![Attribute::Class]);
        let spec = DataSpec {
            modifiable: false,
            copyable: false,
            destroyable: true,
            persistent: false,
            private: false,
            label: "history-family-data".into(),
            application: "family-observation".into(),
            object_type: vec![6, 3, 42, 3, 4],
            admission,
            content: ContentObservation::NotRequested,
            destination: DestinationPlan {
                search: DestinationSearchPlan::NotRequested,
                user: DestinationUserObservation::NotRequested,
            },
        };
        let mut value = SecretBytes::new(3)?;
        value.as_mut_slice().copy_from_slice(b"abc");
        return Ok(Subject::Data(retain(
            session.create_data(spec, value)?,
            owned,
        )?));
    }
    let dsa = case.kind == "dsa";
    let algorithm = if dsa {
        PqcPrivateKeyAlgorithm::MlDsa(MlDsaParameterSet::MlDsa44)
    } else {
        PqcPrivateKeyAlgorithm::MlKem(MlKemParameterSet::MlKem512)
    };
    let spec = PqcPrivateImportSpec {
        history_observation: history(),
        admission,
        id: selection_symmetric::ID.to_vec(),
        label: selection_symmetric::LABEL.into(),
        persistent: false,
        protection: CurrentKeyProtection {
            sensitive: false,
            extractable: true,
        },
        usages: if dsa {
            KeyUsageRequest {
                sign: Some(true),
                ..KeyUsageRequest::omitted()
            }
        } else {
            KeyUsageRequest {
                decapsulate: Some(true),
                ..KeyUsageRequest::omitted()
            }
        },
        visibility: ObjectVisibility::Public,
    };
    let input = PqcPrivateInput::Value {
        algorithm,
        value: case.private.ok_or(Failure::Input("family_value"))?,
    };
    let key = retain(
        session.import_pqc_private_key(
            spec,
            input,
            &case.public,
            MechanismAttributes {
                request: MechanismRequest::Omitted,
                admission: MechanismObservationPlan::NotRequested,
            },
        )?,
        owned,
    )?;
    if key.algorithm() != algorithm
        || key.input_public_key() != case.public
        || key.managed().class() != ManagedClass::PrivateKey
    {
        return Err(Failure::Oracle("family_import_identity"));
    }
    let expected_kind = if dsa {
        fe11_sys::CKK_ML_DSA
    } else {
        fe11_sys::CKK_ML_KEM
    }
    .to_ne_bytes();
    match key
        .managed()
        .object_observations()
        .attribute_observation(Attribute::KeyType)
    {
        AttributeValue::Available(value) if value.as_slice() == expected_kind => (),
        _ => return Err(Failure::Oracle("family_native_key_type")),
    }
    Ok(Subject::Pqc(key))
}

fn rejected<T>(result: Result<T>, expected: RejectionReason) -> std::result::Result<(), Failure> {
    match result {
        Err(Error::Rejected(reason)) if reason == expected => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err(Failure::Oracle("family_guard_missing")),
    }
}

fn check(
    module: &Module,
    session: &Session,
    subject: &Subject,
    kind: &str,
) -> std::result::Result<(), Failure> {
    let before = module.call_counts()?;
    let admission = || selection_symmetric::key(false).admission;
    match subject {
        Subject::Data(key) if kind == "data_aead" => rejected(
            session.encrypt_stream_aead(
                key,
                StreamAeadParameters {
                    nonce: StreamAeadNonce::ChaCha20Ietf([0; 12]),
                    aad: &[],
                },
                &[b"abc"],
                MessageRoute::Single,
                InputLimits {
                    maximum_parts: 1,
                    maximum_total_bytes: 3,
                },
            ),
            RejectionReason::SymmetricParameters(
                SymmetricParametersRejection::AeadRequiresAnAdmittedSecretKey,
            ),
        )?,
        Subject::Data(key) => rejected(
            session.key_history(
                key,
                HistoryObservationPlan {
                    sensitive: false,
                    extractable: false,
                    always_sensitive: false,
                    never_extractable: false,
                    local: false,
                    generation: false,
                    maximum_bytes: 0,
                },
            ),
            RejectionReason::KeyDerivation(KeyDerivationRejection::KeyHistoryClass),
        )?,
        Subject::Pqc(key) if kind == "kem_legacy" => rejected(
            session.admit_imported_kem_decapsulation_key(
                key,
                MechanismObservationPlan::NotRequested,
                admission(),
            ),
            RejectionReason::KeyEncapsulation(
                KeyEncapsulationRejection::MlKemRequiresSelected32Interface,
            ),
        )?,
        Subject::Pqc(key) => match key.algorithm() {
            PqcPrivateKeyAlgorithm::MlDsa(_) => rejected(
                session.admit_imported_kem_decapsulation_key(
                    key,
                    MechanismObservationPlan::NotRequested,
                    admission(),
                ),
                RejectionReason::KeyEncapsulation(
                    KeyEncapsulationRejection::MlKemImportedKeyFamily,
                ),
            )?,
            PqcPrivateKeyAlgorithm::MlKem(_) => rejected(
                session.admit_imported_pqc_signing_key(
                    key,
                    MechanismObservationPlan::NotRequested,
                    admission(),
                ),
                RejectionReason::PostQuantumKeys(PostQuantumKeysRejection::MlDsaImportedKeyFamily),
            )?,
        },
    }
    if module.call_counts()? != before {
        return Err(Failure::Oracle("family_guard_dispatched"));
    }
    Ok(())
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut owned = None;
    let mut subject = None;
    let mut kind = String::new();
    let setup = (|| -> std::result::Result<(), Failure> {
        let case = Case::read(path)?;
        kind = case.kind.clone();
        owner = Some(Owner::open(&module, config, false)?);
        let Some(Owner::Session(session)) = &owner else {
            return Err(Failure::Input("family_owner"));
        };
        subject = Some(prepare(session, case, &mut owned)?);
        Ok(())
    })();
    let started = setup.is_ok();
    let body = match (&owner, &subject) {
        (Some(Owner::Session(session)), Some(subject)) => check(&module, session, subject, &kind),
        _ => Ok(()),
    };
    drop(subject);
    let mut cleanup = Vec::new();
    if let (Some(Owner::Session(session)), Some(owned)) = (&owner, &owned) {
        for key in owned.as_slice() {
            if let Err(error) = session.destroy_native_object(key) {
                cleanup.push(error.into());
            }
        }
    }
    drop(owned);
    if let Some(owner) = &owner {
        cleanup.extend(owner.close(None));
    }
    drop(owner);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    if let Err(error) = &setup {
        outcome::record(&mut report, Phase::Setup, error)?;
    }
    if let Err(error) = &body {
        outcome::record(&mut report, Phase::Body, error)?;
    }
    for error in &cleanup {
        outcome::record(&mut report, Phase::Cleanup, error)?;
    }
    if started {
        report.observation(
            Phase::Body,
            "live_object_family_refusal_without_dispatch",
            Producer::TestOracle,
            Observation::Boolean(body.is_ok()),
        )?;
    }
    report.finish(
        if started {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if !started {
            PhaseResult::NotExecuted
        } else if body.is_ok() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if cleanup.is_empty() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
    )
}
