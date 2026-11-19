// SPDX-License-Identifier: Apache-2.0
//! Single-fault derive requests reuse their complete, published positive tuple.
use super::{
    configuration::Configuration,
    derived_value,
    derived_value_case::DerivedValueCase,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, PhaseResult, Report},
};
use fe11::*;
use std::{
    io::{self, Write},
    path::Path,
};

/// Complete positive fixture whose sole negative mutation is its DERIVE flag.
pub trait DerivationFixture: DerivedValueCase {
    fn import_usage(&self, owner: &Owner, allowed: bool) -> Result<NativeObjectRef>;
}
impl DerivationFixture for super::encrypt_data_fixture::Vector {
    fn import_usage(&self, owner: &Owner, allowed: bool) -> Result<NativeObjectRef> {
        super::encrypt_data_fixture::Vector::import_usage(self, owner, allowed)
    }
}
impl DerivationFixture for super::dh_fixture::Vector {
    fn import_usage(&self, owner: &Owner, allowed: bool) -> Result<NativeObjectRef> {
        super::dh_fixture::Vector::import_usage(self, owner, allowed)
    }
}
impl DerivationFixture for super::ecdh_fixture::Vector {
    fn import_usage(&self, owner: &Owner, allowed: bool) -> Result<NativeObjectRef> {
        super::ecdh_fixture::Vector::import_usage(self, owner, allowed)
    }
}

pub fn execute<V: DerivationFixture, W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    usage: bool,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut key = None;
    let mut created = None;
    let setup = (|| -> std::result::Result<V, Failure> {
        let vector = V::read(path)?;
        if vector.advanced() {
            return Err(Failure::Input("negative_derive_receiver"));
        }
        owner = Some(Owner::open(&module, config, false)?);
        key = Some(
            vector.import_usage(
                owner
                    .as_ref()
                    .ok_or(Failure::Input("negative_derive_owner"))?,
                !usage,
            )?,
        );
        Ok(vector)
    })();
    let body = match &setup {
        Err(_) => Ok(()),
        Ok(vector) => (|| -> std::result::Result<(), Failure> {
            let Some(Owner::Session(session)) = owner.as_ref() else {
                return Err(Failure::Input("negative_derive_owner"));
            };
            let key = key.as_ref().ok_or(Failure::Input("negative_derive_base"))?;
            let mut attributes =
                Vec::from(derived_value::template_attributes(vector.expected().len()));
            if !usage {
                // The complete template begins with CLASS. No other input is
                // altered; notably the key type and requested value length stay valid.
                if attributes[0].attribute != StandardAttribute::CLASS {
                    return Err(Failure::Input("negative_derive_class_position"));
                }
                attributes.remove(0);
            }
            let request = GenerationTemplate {
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
            let code = if usage {
                fe11_sys::CKR_KEY_FUNCTION_NOT_PERMITTED
            } else {
                fe11_sys::CKR_TEMPLATE_INCOMPLETE
            };
            match session.derive_native_key(key, vector.parameters(), request) {
                Err(
                    error @ Error::Native {
                        function: "C_DeriveKey",
                        code: actual,
                        ..
                    },
                ) if actual == code as u64 => {
                    // Preserve the actual effect-uncertainty flag; a native
                    // refusal is not converted into an invented non-creation proof.
                    outcome::record(&mut report, Phase::Body, &Failure::Product(error))
                        .map_err(|_| Failure::Input("report_write"))?;
                    Ok(())
                }
                Err(error) => Err(error.into()),
                Ok(result) => {
                    // Keep every returned creation capability before any
                    // observation/assertion can fail, then destroy it in cleanup.
                    created = Some(result.objects);
                    Err(Failure::Oracle("invalid_derive_request_accepted"))
                }
            }
        })(),
    };
    let mut cleanup = Vec::new();
    if let (Some(Owner::Session(session)), Some(objects)) = (&owner, &created) {
        for object in objects.as_slice() {
            if let Err(error) = session.destroy_native_object(object) {
                cleanup.push(Failure::from(error));
            }
        }
    }
    drop(created);
    if let Some(owner) = &owner {
        cleanup.extend(owner.close(key.as_ref()));
    }
    drop(key);
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
