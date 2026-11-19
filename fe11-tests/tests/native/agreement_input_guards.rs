// SPDX-License-Identifier: Apache-2.0
//! Peer-domain and coordinate-width checks use exact public inputs.
use super::{
    arguments::hex, configuration::Configuration, credentials::Credentials,
    generation_transition_spec::history, module_controls, object_owner::Owner, outcome::Failure,
    report::Report, selection_asymmetric,
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

#[path = "agreement_kdf.rs"]
mod kdf;

fn read(path: &Path) -> std::result::Result<(String, Vec<u8>), Failure> {
    let mut input = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("agreement_guard_open"))?
        .take(1025)
        .read_to_end(&mut input)
        .map_err(|_| Failure::Input("agreement_guard_read"))?;
    if input.len() > 1024 {
        return Err(Failure::Input("agreement_guard_size"));
    }
    let text =
        std::str::from_utf8(&input).map_err(|_| Failure::Input("agreement_guard_encoding"))?;
    let fields: Vec<_> = text.split_terminator('\n').collect();
    if fields.len() != 2
        || !matches!(
            fields[0],
            "curve" | "width" | "kdf-x963" | "kdf-concat" | "kdf-native"
        )
    {
        return Err(Failure::Input("agreement_guard_fields"));
    }
    Ok((
        fields[0].into(),
        hex(fields[1], 512).map_err(Failure::Input)?,
    ))
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut objects = Vec::new();
    let mut pair = None;
    let setup = (|| -> std::result::Result<(String, Vec<u8>), Failure> {
        let case = read(path)?;
        owner = Some(Owner::open(&module, config, false)?);
        let Some(Owner::Session(session)) = &owner else {
            return Err(Failure::Input("agreement_guard_owner"));
        };
        if case.0 != "width" {
            session.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
            let mut spec = selection_asymmetric::agreement();
            spec.label = config.label.clone();
            spec.id = config.label.as_bytes().to_vec();
            let created = session.generate_agreement_key(
                spec,
                CurrentKeyProtection {
                    sensitive: true,
                    extractable: false,
                },
                history(),
            )?;
            objects.push(created.objects);
            if objects[0].as_slice().len() != 2 || created.remainder.is_some() {
                return Err(Failure::Oracle("agreement_guard_generation"));
            }
            pair = Some(created.observation?);
        }
        Ok(case)
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        let Ok((action, bytes)) = &setup else {
            return Ok(());
        };
        let Some(Owner::Session(session)) = &owner else {
            return Err(Failure::Input("agreement_guard_owner"));
        };
        if action.starts_with("kdf-") {
            let key = &pair
                .as_ref()
                .ok_or(Failure::Input("agreement_kdf_pair"))?
                .private;
            kdf::refused(session, key, bytes, action, &mut objects, &mut report)?;
        } else {
            let before = module.call_counts()?;
            let (result, expected) = if action == "width" {
                (
                    MontgomeryPublicKey::from_native(MontgomeryDomain::X25519, bytes).map(|_| ()),
                    KeyDerivationRejection::MontgomeryPublicCoordinateWidth,
                )
            } else {
                let key = &pair
                    .as_ref()
                    .ok_or(Failure::Input("agreement_guard_pair"))?
                    .private;
                let peer = AgreementPeer::from_spki(AgreementCurve::P384, bytes)?;
                let target = kdf::target();
                let result = session
                    .derive_ecdh(
                        key,
                        &peer,
                        EcdhKdf::Null,
                        &[],
                        target,
                        DerivationObservationPlan {
                            parent: history(),
                            child: history(),
                        },
                    )
                    .map(|created| {
                        objects.push(created.objects);
                    });
                (result, KeyDerivationRejection::AgreementCurveMismatch)
            };
            match result {
                Err(Error::Rejected(RejectionReason::KeyDerivation(actual)))
                    if actual == expected =>
                {
                    ()
                }
                Err(error) => return Err(error.into()),
                Ok(()) => return Err(Failure::Oracle("agreement_guard_accepted")),
            }
            if module.call_counts()? != before {
                return Err(Failure::Oracle("agreement_guard_dispatched"));
            }
        }
        let digest = session.digest(
            HashAlgorithm::Sha256,
            b"abc",
            InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: 3,
            },
        )?;
        let expected = hex(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            32,
        )
        .map_err(Failure::Input)?;
        if digest.as_bytes() != expected {
            return Err(Failure::Oracle("agreement_guard_idle_control"));
        }
        Ok(())
    })();
    drop(pair);
    let mut cleanup = Vec::new();
    if let Some(current) = &owner {
        if let Owner::Session(session) = current {
            for set in &objects {
                for object in set.as_slice() {
                    if let Err(error) = session.destroy_native_object(object) {
                        cleanup.push(error.into());
                    }
                }
            }
        }
        drop(objects);
        cleanup.extend(current.close(None));
    }
    drop(owner);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
