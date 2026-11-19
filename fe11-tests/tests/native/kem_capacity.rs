// SPDX-License-Identifier: Apache-2.0
//! Fresh-session encapsulation capacities and ownership after observation failure.
use super::super::{
    derived_value,
    kem_lifecycle_fixture::Fixture,
    object_fixture,
    outcome::{self, Failure},
    report::{Observation, Phase, Producer, Report},
};
use fe11::*;
use std::io::Write;

pub fn check<W: Write>(
    fixture: &mut Fixture,
    action: &str,
    parameter_set: u64,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let length = match parameter_set {
        n if n == fe11_sys::CKP_ML_KEM_512 as u64 => 768,
        n if n == fe11_sys::CKP_ML_KEM_768 as u64 => 1088,
        n if n == fe11_sys::CKP_ML_KEM_1024 as u64 => 1568,
        _ => return Err(Failure::Input("kem_capacity_parameter_set")),
    };
    let capacity = match action {
        "zero" => 0,
        "short" => length - 1,
        "large" => length + 1,
        "observation" => length,
        _ => return Err(Failure::Input("kem_capacity_action")),
    };
    let attributes = derived_value::template_attributes(32);
    let observation = if action == "observation" {
        let mut admission = object_fixture::public_key_options(&[]).admission;
        admission.observation.verify = false;
        admission.observation.maximum_bytes = 2;
        Some(CreationObservation {
            admission,
            content: ContentObservation::Observe(ContentReadPlan::Value { maximum_bytes: 1 }),
        })
    } else {
        None
    };
    let pair = fixture
        .pair
        .as_ref()
        .ok_or(Failure::Input("kem_capacity_pair"))?;
    let result = fixture.session.encapsulate_native(
        Some(pair.public.native()),
        NativeKemParameters::MlKem,
        capacity,
        GenerationTemplate {
            attributes: &attributes,
            limits: AttributeTemplateLimits {
                maximum_depth: 0,
                maximum_attributes: attributes.len(),
                maximum_value_bytes: 128,
            },
            observation,
            destination: DestinationPlan {
                search: DestinationSearchPlan::NotRequested,
                user: DestinationUserObservation::NotRequested,
            },
        },
    );
    let created = match result {
        Err(error) => {
            let sizing = match &error {
                Error::ObjectsMayRemain(cause) => match &**cause {
                    Error::OutputBufferTooSmall {
                        function: "C_EncapsulateKey",
                        code,
                        required,
                        capacity: supplied,
                    } if *code == fe11_sys::CKR_BUFFER_TOO_SMALL as u64 => {
                        Some((*required, *supplied))
                    }
                    _ => None,
                },
                _ => None,
            };
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("kem_capacity_report"))?;
            if let Some((required, supplied)) = sizing {
                report
                    .observation(
                        Phase::Body,
                        "kem_required_ciphertext_bytes",
                        Producer::TestOracle,
                        Observation::Number(required as u64),
                    )
                    .map_err(|_| Failure::Input("kem_capacity_report"))?;
                if capacity < length && supplied == capacity && required == length {
                    return Ok(());
                }
            }
            return Err(Failure::Oracle("kem_native_size_and_capacity"));
        }
        Ok(created) => created,
    };
    // Retain native owners before examining descriptive results. Every exit is
    // cleaned by the enclosing lifecycle, including a native success that
    // violates the capacity or metadata oracle.
    fixture.objects.push(created.objects);
    if fixture.objects.last().map_or(0, |x| x.as_slice().len()) != 1 || capacity < length {
        return Err(Failure::Oracle("kem_capacity_created_object"));
    }
    let ciphertext = if action == "observation" {
        let expected = matches!(&created.observation,
            Err(Error::OperationCompleted { function: "C_EncapsulateKey", cause })
                if matches!(&**cause, Error::Rejected(RejectionReason::InputBounds(InputBoundsRejection::LengthBound))));
        if let Err(error) = created.observation {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("kem_capacity_report"))?;
        }
        if !expected {
            return Err(Failure::Oracle("kem_content_observation_failure"));
        }
        created
            .remainder
            .as_ref()
            .and_then(CreationRemainder::ciphertext)
            .ok_or(Failure::Oracle("kem_observation_ciphertext_retained"))?
            .to_vec()
    } else {
        if created.remainder.is_some() {
            return Err(Failure::Oracle("kem_capacity_unexpected_remainder"));
        }
        let value = created.observation?;
        let ciphertext = value
            .ciphertext()
            .ok_or(Failure::Oracle("kem_capacity_ciphertext_missing"))?
            .to_vec();
        // The result's object owner is already retained above. Keep this
        // ciphertext separately: Fixture's results/values vectors are paired
        // exclusively by Fixture::call and must not be offset here.
        ciphertext
    };
    if ciphertext.len() != length {
        return Err(Failure::Oracle("kem_capacity_exact_ciphertext_length"));
    }
    let object = &fixture
        .objects
        .last()
        .ok_or(Failure::Input("kem_capacity_object"))?
        .as_slice()[0];
    let secret = fixture.session.read_flat_attribute(
        object,
        StandardAttribute::VALUE,
        FlatAttributeReadPlan::Buffer { capacity: 32 },
    )?;
    if secret.calls != (AttributeReadCalls::Direct { code: 0 }) {
        return Err(Failure::Oracle("kem_capacity_secret_status"));
    }
    let FlatAttributeValue::Available(secret) = secret.value else {
        return Err(Failure::Oracle("kem_capacity_secret_unavailable"));
    };
    let receiver = fixture.call(false, &ciphertext, false)?;
    if secret.as_bytes().len() != 32 || fixture.values[receiver].as_slice() != secret.as_bytes() {
        return Err(Failure::Oracle("kem_capacity_shared_secret"));
    }
    report
        .observation(
            Phase::Body,
            "kem_capacity_output_and_ownership",
            Producer::TestOracle,
            Observation::Boolean(true),
        )
        .map_err(|_| Failure::Input("kem_capacity_report"))?;
    Ok(())
}
