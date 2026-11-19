// SPDX-License-Identifier: Apache-2.0
//! An external prehash cannot be split into a native multipart signature.
use super::{
    arguments::hex, configuration::Configuration, credentials::Credentials, module_controls,
    object_owner::Owner, outcome::Failure, report::Report, selection_asymmetric,
};
use fe11::*;
use std::io::{self, Write};

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    pins: &Credentials,
    report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut objects = None;
    let setup = (|| -> std::result::Result<PqcKeyPair, Failure> {
        owner = Some(Owner::open(&module, config, false)?);
        let Some(Owner::Session(session)) = &owner else {
            return Err(Failure::Input("pqc_signing_guard_owner"));
        };
        session.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        let mut spec = selection_asymmetric::pqc();
        spec.id = config.label.as_bytes().to_vec();
        spec.label = config.label.clone();
        let policy = || MechanismAttributes {
            request: MechanismRequest::Omitted,
            admission: MechanismObservationPlan::NotRequested,
        };
        let created = session.generate_pqc_key_pair(
            spec,
            policy(),
            policy(),
            CurrentKeyProtection {
                sensitive: true,
                extractable: false,
            },
            ObjectVisibility::Public,
        )?;
        objects = Some(created.objects);
        if created.remainder.is_some()
            || objects.as_ref().map_or(0, |set| set.as_slice().len()) != 2
        {
            return Err(Failure::Oracle("pqc_signing_guard_generation"));
        }
        Ok(created.observation?)
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        let Ok(pair) = &setup else { return Ok(()) };
        let Some(Owner::Session(session)) = &owner else {
            return Err(Failure::Input("pqc_signing_guard_owner"));
        };
        let parameters = PqcSignatureParameters::new(
            PqcSignatureMode::Prehashed(PqcHash::Sha256),
            &[],
            PqcHedging::Preferred,
        )?;
        let input = [0u8; 32];
        let fingerprint = pair.private.fingerprint();
        let before = module.call_counts()?;
        match session.sign_pqc_multipart(
            &pair.private,
            &parameters,
            &[&input],
            InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: 32,
            },
        ) {
            Err(Error::Unsupported(UnsupportedReason::PostQuantumKeys(
                PostQuantumKeysUnsupported::Pkcs11PqcExternalPrehashIsSinglePartOnly,
            ))) => (),
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(Failure::Oracle("pqc_signing_guard_accepted")),
        }
        if module.call_counts()? != before || pair.private.fingerprint() != fingerprint {
            return Err(Failure::Oracle("pqc_signing_guard_changed_state"));
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
            return Err(Failure::Oracle("pqc_signing_guard_idle_control"));
        }
        Ok(())
    })();
    let setup = setup.map(|_| ());
    let mut cleanup = Vec::new();
    if let Some(o) = &owner {
        if let (Owner::Session(session), Some(set)) = (o, &objects) {
            for object in set.as_slice() {
                if let Err(error) = session.destroy_native_object(object) {
                    cleanup.push(error.into());
                }
            }
        }
        drop(objects);
        cleanup.extend(o.close(None));
    }
    drop(owner);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    module_controls::finish(report, setup, body, cleanup)
}
