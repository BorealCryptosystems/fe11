// SPDX-License-Identifier: Apache-2.0
//! Synchronous ownership conversion retains generated references and native work.
use super::{
    arguments::hex, configuration::Configuration, credentials::Credentials, module_controls,
    object_owner::Owner, outcome::Failure, report::Report, selection_rsa,
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

fn action(path: &Path) -> std::result::Result<bool, Failure> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("session_case_open"))?
        .take(33)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Input("session_case_read"))?;
    match bytes.as_slice() {
        b"digest32_profile\n" => Ok(false),
        b"into_advanced\n" => Ok(true),
        _ => Err(Failure::Input("session_case_action")),
    }
}

fn key_spec(label: &str) -> KeySpec {
    let source = selection_rsa::classical();
    KeySpec {
        public_visibility: source.public_visibility,
        private_visibility: source.private_visibility,
        private_protection: source.private_protection,
        public_usages: source.public_usages,
        private_usages: source.private_usages,
        public_admission: source.public_admission,
        private_admission: source.private_admission,
        bits: 2048,
        exponent: 65537,
        id: label.as_bytes().to_vec(),
        label: label.into(),
        persistent: false,
    }
}

fn signature_parameters() -> NativeSignatureParameters<'static> {
    NativeSignatureParameters::Parameterless(NativeSignatureAlgorithm::SHA256_RSA_PKCS)
}

fn converted(owner: &AdvancedSession, pair: &KeyPair) -> std::result::Result<(), Failure> {
    if owner.mode() != AdvancedSessionMode::Synchronous {
        return Err(Failure::Oracle("session_conversion_mode"));
    }
    let limits = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: 3,
    };
    // These are the exact generated references, not objects re-found by label.
    // Their successful use exercises the preserved owner/session bindings.
    let private = pair.private.native_object();
    let public = pair.public.native_object();
    let signature = owner.sign_native(
        &private,
        signature_parameters(),
        MessageRoute::Single,
        &[b"abc"],
        limits,
        256,
        None,
    )?;
    if signature.as_bytes().len() != 256 {
        return Err(Failure::Oracle("conversion_signature_width"));
    }
    owner.verify_native(
        &public,
        signature_parameters(),
        MessageRoute::Single,
        &[b"abc"],
        signature.as_bytes(),
        limits,
        None,
    )?;
    let mut ticket = owner.digest_native(NativeDigestAlgorithm::Sha256, &[b"abc"], limits)?;
    // Synchronous eager work has three native digest steps and publication.
    // This bounds protocol steps, not elapsed time or module performance.
    for _ in 0..8 {
        match owner.poll(&mut ticket)? {
            OperationProgress::Ready => (),
            OperationProgress::NativeDigest(value) => {
                let expected = hex(
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                    32,
                )
                .map_err(Failure::Input)?;
                return if value.as_bytes() == expected {
                    Ok(())
                } else {
                    Err(Failure::Oracle("conversion_digest_value"))
                };
            }
            _ => return Err(Failure::Oracle("conversion_digest_result_kind")),
        }
    }
    Err(Failure::Oracle("conversion_digest_not_completed"))
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut objects = None;
    let setup = (|| -> std::result::Result<(bool, KeyPair), Failure> {
        let conversion = action(path)?;
        owner = Some(Owner::open(&module, config, false)?);
        let Some(Owner::Session(session)) = &owner else {
            return Err(Failure::Input("session_owner"));
        };
        session.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        let created = session.generate_rsa_signing_key_pair(key_spec(&config.label))?;
        objects = Some(created.objects);
        if created.remainder.is_some() {
            return Err(Failure::Oracle("session_pair_remainder"));
        }
        Ok((conversion, created.observation?))
    })();
    let body = match &setup {
        Err(_) => Ok(()),
        Ok((conversion, pair)) => (|| -> std::result::Result<(), Failure> {
            let before = module.call_counts()?;
            if *conversion {
                let Some(Owner::Session(session)) = owner.take() else {
                    return Err(Failure::Input("session_owner"));
                };
                owner = Some(Owner::Advanced(session.into_advanced()?));
                if module.call_counts()? != before {
                    return Err(Failure::Oracle("conversion_dispatched"));
                }
                let Some(Owner::Advanced(session)) = &owner else {
                    return Err(Failure::Input("converted_owner"));
                };
                converted(session, pair)
            } else {
                let Some(Owner::Session(session)) = &owner else {
                    return Err(Failure::Input("session_owner"));
                };
                let result = session.verify_pss(
                    &pair.public,
                    Digest32::from_bytes(&[0; 32])?,
                    PssParams {
                        hash: fe11_sys::CKM_SHA384 as u64,
                        mgf: fe11_sys::CKG_MGF1_SHA256 as u64,
                        salt_length: 32,
                    },
                    &[0; 256],
                );
                match result {
                    Err(Error::Rejected(RejectionReason::SessionLifecycle(
                        SessionLifecycleRejection::Digest32RequiresSha256,
                    ))) => (),
                    Err(error) => return Err(error.into()),
                    Ok(_) => return Err(Failure::Oracle("digest32_wrong_hash_accepted")),
                }
                if module.call_counts()? != before {
                    return Err(Failure::Oracle("digest32_guard_dispatched"));
                }
                Ok(())
            }
        })(),
    };
    let setup = setup.map(|_| ());
    let mut cleanup = Vec::new();
    if let Some(o) = &owner {
        if let Some(set) = &objects {
            for object in set.as_slice() {
                if let Err(error) = super::key_wrap_fixture::destroy(o, object) {
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
