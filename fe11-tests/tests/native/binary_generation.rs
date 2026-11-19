// SPDX-License-Identifier: Apache-2.0
//! Characterize optional named curves; successful creation requires usable keys.
use super::{
    binary_curve::Curve,
    configuration::Configuration,
    credentials::Credentials,
    derived_value,
    generation_fixture::{Field, Fixture, Generator, Value},
    generation_vector,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
use std::{
    io::{self, Write},
    path::Path,
};

fn fixture(curve: &Curve, label: &str) -> Fixture {
    let unsigned = |attribute, value| Field {
        attribute,
        value: Value::Unsigned(value),
    };
    let boolean = |attribute, value| Field {
        attribute,
        value: Value::Boolean(value),
    };
    let mut public = vec![
        unsigned(StandardAttribute::CLASS, fe11_sys::CKO_PUBLIC_KEY as u64),
        unsigned(StandardAttribute::KEY_TYPE, fe11_sys::CKK_EC as u64),
        Field {
            attribute: StandardAttribute::EC_PARAMS,
            value: Value::Bytes(curve.oid.clone()),
        },
        boolean(StandardAttribute::VERIFY, true),
        boolean(StandardAttribute::DERIVE, true),
        boolean(StandardAttribute::TOKEN, false),
        boolean(StandardAttribute::PRIVATE, false),
    ];
    let mut private = vec![
        unsigned(StandardAttribute::CLASS, fe11_sys::CKO_PRIVATE_KEY as u64),
        unsigned(StandardAttribute::KEY_TYPE, fe11_sys::CKK_EC as u64),
        boolean(StandardAttribute::SIGN, true),
        boolean(StandardAttribute::DERIVE, true),
        boolean(StandardAttribute::TOKEN, false),
        boolean(StandardAttribute::PRIVATE, true),
        boolean(StandardAttribute::SENSITIVE, false),
        boolean(StandardAttribute::EXTRACTABLE, true),
    ];
    for fields in [&mut public, &mut private] {
        fields.push(Field {
            attribute: StandardAttribute::LABEL,
            value: Value::Bytes(label.as_bytes().to_vec()),
        });
    }
    Fixture {
        generator: Generator::Pair(KeyPairGenerator::EC_KEY_PAIR_GEN),
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

fn characterization_code(code: u64) -> bool {
    [
        fe11_sys::CKR_CURVE_NOT_SUPPORTED,
        fe11_sys::CKR_DOMAIN_PARAMS_INVALID,
        fe11_sys::CKR_KEY_SIZE_RANGE,
        fe11_sys::CKR_ATTRIBUTE_VALUE_INVALID,
        fe11_sys::CKR_FUNCTION_FAILED,
        fe11_sys::CKR_GENERAL_ERROR,
    ]
    .iter()
    .any(|&allowed| code == allowed as u64)
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut logged = false;
    let mut generated = None;
    let mut derived = None;
    let mut supported = None;
    let setup = (|| -> std::result::Result<Curve, Failure> {
        let curve = Curve::read(path)?;
        owner = Some(Owner::open(&module, config, false)?);
        let Some(Owner::Session(session)) = &owner else {
            return Err(Failure::Input("binary_generation_owner"));
        };
        session.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        logged = true;
        Ok(curve)
    })();
    let body = match &setup {
        Err(_) => Ok(()),
        Ok(curve) => (|| -> std::result::Result<(), Failure> {
            let Some(o @ Owner::Session(session)) = &owner else {
                return Err(Failure::Input("binary_generation_owner"));
            };
            match generation_vector::generate(
                session,
                &fixture(curve, &config.label),
                &mut generated,
            ) {
                Ok(()) => (),
                Err(Failure::Product(
                    error @ Error::Native {
                        function: "C_GenerateKeyPair",
                        code,
                        ..
                    },
                )) if characterization_code(code) => {
                    // A bounded native refusal characterizes this optional curve;
                    // it does not establish curve support or successful generation.
                    if generated.is_some() {
                        return Err(Failure::Oracle("refused_generation_has_owners"));
                    }
                    outcome::record(&mut report, Phase::Body, &Failure::Product(error))
                        .map_err(|_| Failure::Input("report_write"))?;
                    supported = Some(false);
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
            let objects = generated
                .as_ref()
                .ok_or(Failure::Input("binary_generation_objects"))?
                .as_slice();
            if objects.len() != 2 {
                return Err(Failure::Oracle("binary_generation_object_count"));
            }
            let point = session.read_flat_attribute(
                &objects[0],
                StandardAttribute::EC_POINT,
                FlatAttributeReadPlan::Buffer { capacity: 160 },
            )?;
            if point.calls != (AttributeReadCalls::Direct { code: 0 }) {
                return Err(Failure::Oracle("binary_public_point_code"));
            }
            let FlatAttributeValue::Available(bytes) = point.value else {
                return Err(Failure::Oracle("binary_public_point_absent"));
            };
            let expected = curve.check_der_point(bytes.as_bytes())?;
            // For the generator G and generated private d, ECDH(d,G) has exactly
            // x(dG), already checked as the generated public point. No private
            // scalar is exported, and equality alone cannot hide an invalid point.
            derived_value::check(
                o,
                &objects[1],
                NativeKeyDerivation::Ecdh {
                    kdf: fe11_sys::CKD_NULL as u64,
                    cofactor: false,
                    peer_public: &curve.generator,
                    shared_data: None,
                },
                expected,
                &mut derived,
            )?;
            supported = Some(true);
            Ok(())
        })(),
    };
    let mut cleanup = Vec::new();
    if let Some(Owner::Session(session)) = &owner {
        for objects in derived.iter().chain(generated.iter()) {
            for object in objects.as_slice() {
                if let Err(error) = session.destroy_native_object(object) {
                    cleanup.push(error.into());
                }
            }
        }
        if logged {
            if let Err(error) = session.logout() {
                cleanup.push(error.into());
            }
        }
    }
    drop(derived);
    drop(generated);
    if let Some(owner) = &owner {
        cleanup.extend(owner.close(None));
    }
    drop(owner);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    if let Some(value) = supported {
        report.observation(
            Phase::Body,
            "binary_curve_supported",
            Producer::Native,
            Observation::Boolean(value),
        )?;
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
    report.finish(
        if setup.is_ok() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if setup.is_err() {
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
