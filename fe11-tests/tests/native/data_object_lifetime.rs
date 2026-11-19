// SPDX-License-Identifier: Apache-2.0
//! Data-object visibility and two independently searched aliases.
use super::{select_token, Configuration, Credentials, Failure, Phase, PhaseResult, Report};
use crate::{object_transition_fixture::find, outcome};
use fe11::*;
use std::io::{self, Write};

pub(super) struct Case {
    token: bool,
    private: bool,
    aliases: bool,
}

impl Case {
    pub(super) fn read(fields: &[&str]) -> std::result::Result<Self, Failure> {
        if fields.len() != 4
            || fields[0] != "data-lifetime"
            || !matches!(fields[1], "false" | "true")
            || !matches!(fields[2], "false" | "true")
            || !matches!(fields[3], "visibility" | "aliases")
        {
            return Err(Failure::Input("data_lifetime_fields"));
        }
        Ok(Self {
            token: fields[1] == "true",
            private: fields[2] == "true",
            aliases: fields[3] == "aliases",
        })
    }
}

const VALUE: &[u8] = b"data\0\xff";
const APPLICATION: &[u8] = b"application\0\xc3\xa9";

fn check(
    session: &Session,
    object: &NativeObjectRef,
    case: &Case,
) -> std::result::Result<(), Failure> {
    let requests = [
        (
            StandardAttribute::CLASS,
            std::mem::size_of::<fe11_sys::CK_ULONG>(),
        ),
        (StandardAttribute::TOKEN, 1),
        (StandardAttribute::PRIVATE, 1),
        (StandardAttribute::APPLICATION, APPLICATION.len()),
        (StandardAttribute::VALUE, VALUE.len()),
    ]
    .map(|(attribute, capacity)| FlatAttributeRequest {
        attribute: attribute.into(),
        plan: FlatAttributeReadPlan::Buffer { capacity },
    });
    let values = session.read_flat_attributes(object, &requests, 64)?;
    if values.calls()
        != AttributeBatchCalls::One(AttributeBatchCall {
            code: 0,
            attribute_count: 5,
        })
        || values.len() != 5
    {
        return Err(Failure::Oracle("data_lifetime_attribute_status"));
    }
    let fields: Vec<_> = values.iter().collect();
    if fields[0].unsigned()? != fe11_sys::CKO_DATA as u64
        || fields[1].boolean()? != case.token
        || fields[2].boolean()? != case.private
    {
        return Err(Failure::Oracle("data_lifetime_class_flags"));
    }
    for (field, expected) in [(fields[3], APPLICATION), (fields[4], VALUE)] {
        match &field.value {
            FlatAttributeValue::Available(value) if value.as_bytes() == expected => (),
            _ => return Err(Failure::Oracle("data_lifetime_bytes")),
        }
    }
    Ok(())
}

fn population(
    session: &Session,
    label: &[u8],
    present: bool,
) -> std::result::Result<Vec<NativeObjectRef>, Failure> {
    let found = find(session, label)?;
    if found.len() != usize::from(present) {
        return Err(Failure::Oracle("data_lifetime_population"));
    }
    Ok(found)
}

pub(super) fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    pins: &Credentials,
    case: Case,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut creator = None;
    let mut peer = None;
    let mut original = None;
    let mut logged = false;
    let mut creator_closed = false;
    let label = config.label.as_bytes();
    let setup = (|| -> std::result::Result<(), Failure> {
        let token =
            select_token(&module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        creator = Some(module.select(&token)?.open_session(true)?);
        peer = Some(module.select(&token)?.open_session(true)?);
        peer.as_ref()
            .ok_or(Failure::Input("data_peer"))?
            .login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        logged = true;
        let fields = [
            (
                StandardAttribute::CLASS,
                AttributeInputValue::Unsigned(fe11_sys::CKO_DATA as u64),
            ),
            (
                StandardAttribute::TOKEN,
                AttributeInputValue::Boolean(case.token),
            ),
            (
                StandardAttribute::PRIVATE,
                AttributeInputValue::Boolean(case.private),
            ),
            (StandardAttribute::LABEL, AttributeInputValue::Bytes(label)),
            (
                StandardAttribute::APPLICATION,
                AttributeInputValue::Bytes(APPLICATION),
            ),
            (StandardAttribute::VALUE, AttributeInputValue::Bytes(VALUE)),
        ]
        .map(|(attribute, value)| AttributeInput {
            attribute: attribute.into(),
            value,
        });
        original = Some(
            creator
                .as_ref()
                .ok_or(Failure::Input("data_creator"))?
                .create_native_object(
                    &fields,
                    AttributeTemplateLimits {
                        maximum_depth: 0,
                        maximum_attributes: fields.len(),
                        maximum_value_bytes: 256,
                    },
                )?,
        );
        Ok(())
    })();
    let body = if setup.is_ok() {
        (|| -> std::result::Result<(), Failure> {
            let creator = creator.as_ref().ok_or(Failure::Input("data_creator"))?;
            let peer = peer.as_ref().ok_or(Failure::Input("data_peer"))?;
            check(
                creator,
                original.as_ref().ok_or(Failure::Input("data_original"))?,
                &case,
            )?;
            // Separate searches must produce aliases of the same owned object.
            // Neither alias may extend the creator's native session lifetime.
            let first = population(peer, label, true)?;
            let second = population(peer, label, true)?;
            check(peer, &first[0], &case)?;
            check(peer, &second[0], &case)?;
            if case.aliases {
                // Flat reads retain bytes but do not upgrade creator provenance.
                // Establish the lifetime contract of each independently searched
                // alias explicitly before closing the original creator.
                for alias in [&first[0], &second[0]] {
                    let mut admission = crate::object_fixture::public_key_options(label).admission;
                    admission.observation.verify = false;
                    admission.observation.maximum_bytes = 2;
                    let _view = peer.observe_native_object(
                        alias,
                        ManagedClass::Data,
                        admission,
                        ContentObservation::NotRequested,
                    )?;
                    let provenance = if case.token {
                        ObjectCreatorProvenance::TokenObject
                    } else {
                        ObjectCreatorProvenance::KnownCreationSession
                    };
                    if alias.creator_provenance() != provenance
                        || alias.visibility_observation() != Observation::Observed(case.private)
                    {
                        return Err(Failure::Oracle("data_alias_observation_prerequisite"));
                    }
                }
                creator.close()?;
                creator_closed = true;
                for alias in [&first[0], &second[0]] {
                    if case.token {
                        check(peer, alias, &case)?;
                    } else {
                        let before = module.call_counts()?;
                        match check(peer, alias, &case) {
                            Err(Failure::Product(Error::Rejected(
                                RejectionReason::ObjectCreation(
                                    ObjectCreationRejection::CreatingSessionClosed,
                                ),
                            ))) => (),
                            Err(error) => return Err(error),
                            Ok(()) => return Err(Failure::Oracle("data_alias_survived_creator")),
                        }
                        if module.call_counts()? != before {
                            return Err(Failure::Oracle("data_closed_creator_dispatched"));
                        }
                    }
                }
                population(peer, label, case.token)?;
            } else {
                peer.logout()?;
                logged = false;
                for object in population(peer, label, !case.private)? {
                    check(peer, &object, &case)?;
                }
                peer.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
                logged = true;
                // Logout destroys private session objects; private token objects
                // become visible again after a fresh login and fresh search.
                for object in population(peer, label, !case.private || case.token)? {
                    check(peer, &object, &case)?;
                }
            }
            Ok(())
        })()
    } else {
        Ok(())
    };
    let mut cleanup = Vec::new();
    if let Some(peer) = &peer {
        if !logged {
            match peer.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec())) {
                Ok(()) => logged = true,
                Err(error) => cleanup.push(error.into()),
            }
        }
        // This label belongs only to the single object created in this isolated
        // token. Refresh after Logout; never destroy through an invalid alias.
        match find(peer, label) {
            Ok(objects) => {
                for object in objects {
                    if let Err(error) = peer.destroy_native_object(&object) {
                        cleanup.push(error.into());
                    }
                }
            }
            Err(error) => cleanup.push(error),
        }
    }
    if !creator_closed {
        if let Some(creator) = &creator {
            if let Err(error) = creator.close() {
                cleanup.push(error.into());
            }
        }
    }
    if let Some(peer) = &peer {
        if logged {
            if let Err(error) = peer.logout() {
                cleanup.push(error.into());
            }
        }
        if let Err(error) = peer.close() {
            cleanup.push(error.into());
        }
    }
    drop(original);
    drop(creator);
    drop(peer);
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
