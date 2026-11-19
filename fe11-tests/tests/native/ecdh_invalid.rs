// SPDX-License-Identifier: Apache-2.0
//! Invalid SEC1 peer bytes are forwarded unchanged with an otherwise valid key.
use super::{
    arguments::hex,
    configuration::Configuration,
    derived_value, ecdh_fixture,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

struct InvalidPeer {
    vector: ecdh_fixture::Vector,
    width: usize,
    created: Option<CreatedObjectSet>,
}
impl InvalidPeer {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("ecdh_invalid_open"))?
            .take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("ecdh_invalid_read"))?;
        if bytes.len() > 4096 {
            return Err(Failure::Input("ecdh_invalid_size"));
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| Failure::Input("ecdh_invalid_encoding"))?;
        let f: Vec<_> = text.split_terminator('\n').collect();
        if f.len() != 5 || !matches!(f[0], "session" | "advanced") {
            return Err(Failure::Input("ecdh_invalid_fields"));
        }
        let width = f[4]
            .parse()
            .map_err(|_| Failure::Input("ecdh_invalid_width"))?;
        if !matches!(width, 28 | 32 | 48 | 66) {
            return Err(Failure::Input("ecdh_invalid_width"));
        }
        let vector = ecdh_fixture::Vector {
            advanced: f[0] == "advanced",
            parameters: hex(f[1], 64).map_err(Failure::Input)?,
            private: hex(f[2], 128).map_err(Failure::Input)?,
            peer: hex(f[3], 256).map_err(Failure::Input)?,
            // No shared secret is supplied or invented for an invalid point.
            expected: Vec::new(),
        };
        if vector.parameters.is_empty() || vector.private.is_empty() {
            return Err(Failure::Input("ecdh_invalid_key"));
        }
        Ok(Self {
            vector,
            width,
            created: None,
        })
    }
    fn advanced(&self) -> bool {
        self.vector.advanced
    }
    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        Ok(self.vector.import(owner)?)
    }
    fn check<W: Write>(
        &mut self,
        owner: &Owner,
        key: &NativeObjectRef,
        report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        let parameters = NativeKeyDerivation::Ecdh {
            kdf: fe11_sys::CKD_NULL as u64,
            cofactor: false,
            peer_public: &self.vector.peer,
            shared_data: None,
        };
        let attributes = derived_value::template_attributes(self.width);
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
        let result = match owner {
            Owner::Session(s) => s.derive_native_key(key, parameters, request),
            Owner::Advanced(s) => s.derive_native_key(key, parameters, request),
        };
        match result {
            Err(
                error @ Error::Native {
                    function: "C_DeriveKey",
                    code,
                    ..
                },
            ) if code == fe11_sys::CKR_MECHANISM_PARAM_INVALID as u64
                || code == fe11_sys::CKR_ARGUMENTS_BAD as u64 =>
            {
                outcome::record(report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("report_write"))?;
                Ok(())
            }
            Err(e) => Err(e.into()),
            Ok(result) => {
                // Retain the complete returned set even on unexpected success;
                // never replace the refusal oracle with a derived-value check.
                self.created = Some(result.objects);
                if let Err(e) = result.observation {
                    outcome::record(report, Phase::Body, &Failure::Product(e))
                        .map_err(|_| Failure::Input("report_write"))?;
                }
                Err(Failure::Oracle("invalid_ecdh_peer_accepted"))
            }
        }
    }
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut key = None;
    let mut setup = (|| {
        let vector = InvalidPeer::read(path)?;
        owner = Some(Owner::open(&module, config, vector.advanced())?);
        key = Some(vector.import(owner.as_ref().ok_or(Failure::Input("ecdh_invalid_owner"))?)?);
        Ok::<_, Failure>(vector)
    })();
    let body = match (&mut setup, &owner, &key) {
        (Ok(vector), Some(owner), Some(key)) => vector.check(owner, key, &mut report),
        (Err(_), _, _) => Ok(()),
        _ => Err(Failure::Input("ecdh_invalid_fixture_incomplete")),
    };
    let mut cleanup = Vec::new();
    if let (Ok(vector), Some(owner)) = (&setup, &owner) {
        if let Some(objects) = &vector.created {
            for object in objects.as_slice() {
                let result = match owner {
                    Owner::Session(s) => s.destroy_native_object(object),
                    Owner::Advanced(s) => s.destroy_native_object(object),
                };
                if let Err(e) = result {
                    cleanup.push(Failure::from(e));
                }
            }
        }
    }
    if let Ok(vector) = &mut setup {
        vector.created.take();
    }
    if let Some(owner) = &owner {
        cleanup.extend(owner.close(key.as_ref()));
    }
    drop(key);
    drop(owner);
    if let Err(e) = module.close() {
        cleanup.push(e.into());
    }
    if let Err(e) = &setup {
        outcome::record(&mut report, Phase::Setup, e)?;
    }
    if let Err(e) = &body {
        outcome::record(&mut report, Phase::Body, e)?;
    }
    for e in &cleanup {
        outcome::record(&mut report, Phase::Cleanup, e)?;
    }
    if setup.is_ok() {
        report.observation(
            Phase::Body,
            "invalid_ecdh_peer_exact_native_refusal",
            Producer::TestOracle,
            Observation::Boolean(body.is_ok()),
        )?;
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
