// SPDX-License-Identifier: Apache-2.0
//! Typed signature guards retain real generated keys and exact native results.
use super::{
    configuration::Configuration, credentials::Credentials, module_controls, object_owner::Owner,
    outcome::Failure, report::Report, selection_rsa,
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

fn read(path: &Path) -> std::result::Result<String, Failure> {
    let mut data = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("sign_guard_open"))?
        .take(65)
        .read_to_end(&mut data)
        .map_err(|_| Failure::Input("sign_guard_read"))?;
    if data.len() > 64 {
        return Err(Failure::Input("sign_guard_size"));
    }
    let text = std::str::from_utf8(&data).map_err(|_| Failure::Input("sign_guard_encoding"))?;
    let action = text
        .strip_suffix('\n')
        .ok_or(Failure::Input("sign_guard_fields"))?;
    if !matches!(
        action,
        "no_der"
            | "rsa_digest_profile"
            | "ecdsa_digest_permission"
            | "message_signing"
            | "message_verification"
    ) {
        return Err(Failure::Input("sign_guard_action"));
    }
    Ok(action.into())
}
fn limits() -> InputLimits {
    InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: 3,
    }
}
fn refused<T>(result: Result<T>, expected: RejectionReason) -> std::result::Result<(), Failure> {
    match result {
        Err(Error::Rejected(actual)) if actual == expected => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => Err(Failure::Oracle("signature_guard_accepted")),
    }
}
fn classical(reason: ClassicalSignaturesRejection) -> RejectionReason {
    RejectionReason::ClassicalSignatures(reason)
}

fn check(
    module: &Module,
    owner: &mut Option<Owner>,
    pair: &ClassicalKeyPair,
    action: &str,
) -> std::result::Result<(), Failure> {
    if action.starts_with("message_") {
        let Some(Owner::Session(session)) = owner.take() else {
            return Err(Failure::Input("message_guard_owner"));
        };
        *owner = Some(Owner::Advanced(session.into_advanced()?));
        let Some(Owner::Advanced(session)) = owner.as_ref() else {
            return Err(Failure::Input("message_guard_conversion"));
        };
        let parts: [&[u8]; 1] = [b"abc"];
        let messages = [SignatureMessage { parts: &parts }];
        let parameters = RsaPssParameters {
            hash: HashAlgorithm::Sha256,
            mgf_hash: HashAlgorithm::Sha256,
            salt_length: 32,
        };
        let before = module.call_counts()?;
        if action == "message_signing" {
            refused(
                session.sign_pss_messages(
                    &pair.private,
                    parameters,
                    &messages,
                    MessageRoute::Single,
                    limits(),
                ),
                classical(ClassicalSignaturesRejection::MessageRsaSigningKeyRequired),
            )?;
        } else {
            refused(
                session.verify_pss_messages(
                    &pair.public,
                    parameters,
                    &messages,
                    &[&[0u8; 256]],
                    MessageRoute::Single,
                    limits(),
                ),
                RejectionReason::PublicVerification(
                    PublicVerificationRejection::MessageRsaVerificationKeyRequired,
                ),
            )?;
        }
        if before != module.call_counts()? {
            return Err(Failure::Oracle("message_key_guard_dispatched"));
        }
        return Ok(());
    }
    let Some(Owner::Session(session)) = owner.as_ref() else {
        return Err(Failure::Input("sign_guard_owner"));
    };
    if action == "no_der" {
        let signature = session.sign_classical(
            &pair.private,
            SigningRequest::RsaPkcs1 {
                hash: HashAlgorithm::Sha256,
                execution: HashExecution::Pkcs11Combined,
            },
            b"abc",
            limits(),
        )?;
        if signature.as_bytes().len() != 256
            || signature.profile() != SignatureProfile::RsaPkcs1(HashAlgorithm::Sha256)
        {
            return Err(Failure::Oracle("signature_guard_profile"));
        }
        let original = signature.as_bytes().to_vec();
        let before = module.call_counts()?;
        refused(
            signature.to_der(),
            classical(ClassicalSignaturesRejection::SignatureHasNoDerConversion),
        )?;
        if signature.as_bytes() != original || before != module.call_counts()? {
            return Err(Failure::Oracle("signature_guard_changed_result"));
        }
        let verified = session.verify_rsa_pkcs1(
            &pair.public,
            HashAlgorithm::Sha256,
            HashExecution::Pkcs11Combined,
            b"abc",
            signature.as_bytes(),
            limits(),
        )?;
        if verified.validity != Verification::Valid
            || verified.key_fingerprint != pair.public.fingerprint()
        {
            return Err(Failure::Oracle("signature_guard_not_verifiable"));
        }
        return Ok(());
    }
    let digest = session.digest(HashAlgorithm::Sha256, b"abc", limits())?;
    let expected = super::arguments::hex(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        32,
    )
    .map_err(Failure::Input)?;
    if digest.as_bytes() != expected {
        return Err(Failure::Oracle("signature_guard_digest"));
    }
    let before = module.call_counts()?;
    let (hash, reason) = if action == "rsa_digest_profile" {
        (
            HashAlgorithm::Sha384,
            ClassicalSignaturesRejection::RsaPreparedDigestProfile,
        )
    } else {
        (
            HashAlgorithm::Sha256,
            ClassicalSignaturesRejection::RsaPreparedSigningPermission,
        )
    };
    refused(
        session.sign_rsa_digest(&pair.private, RsaSignatureProfile::Pkcs1(hash), &digest),
        classical(reason),
    )?;
    if before != module.call_counts()? || digest.as_bytes() != expected {
        return Err(Failure::Oracle("prepared_guard_changed_input"));
    }
    Ok(())
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
    let setup = (|| -> std::result::Result<(String, ClassicalKeyPair), Failure> {
        let action = read(path)?;
        owner = Some(Owner::open(&module, config, false)?);
        let Some(Owner::Session(session)) = &owner else {
            return Err(Failure::Input("sign_guard_owner"));
        };
        session.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        let mut spec = selection_rsa::classical();
        spec.label = config.label.clone();
        if matches!(
            action.as_str(),
            "ecdsa_digest_permission" | "message_signing" | "message_verification"
        ) {
            spec.algorithm = ClassicalKeyAlgorithm::Ecdsa(EcCurve::P256);
            spec.rsa_public_exponent = None;
            spec.profiles = vec![SignatureProfile::Ecdsa(HashAlgorithm::Sha256)];
        }
        let result =
            session.generate_classical_key_pair(spec, MechanismObservationPlan::NotRequested)?;
        objects = Some(result.objects);
        if result.remainder.is_some() || objects.as_ref().map_or(0, |x| x.as_slice().len()) != 2 {
            return Err(Failure::Oracle("sign_guard_generation_count"));
        }
        Ok((action, result.observation?))
    })();
    let body = match &setup {
        Ok((action, pair)) => check(&module, &mut owner, pair, action),
        Err(_) => Ok(()),
    };
    let mut cleanup = Vec::new();
    if let (Some(o), Some(objects)) = (&owner, &objects) {
        for object in objects.as_slice() {
            if let Err(e) = super::key_wrap_fixture::destroy(o, object) {
                cleanup.push(e.into());
            }
        }
    }
    drop(objects);
    let setup = setup.map(|_| ());
    // Closing the last real session ends its login state; no independent
    // administrative session or fabricated logout capability is introduced.
    if let Some(o) = &owner {
        cleanup.extend(o.close(None));
    }
    drop(owner);
    if let Err(e) = module.close() {
        cleanup.push(e.into());
    }
    module_controls::finish(report, setup, body, cleanup)
}
