// SPDX-License-Identifier: Apache-2.0
//! Encoding and prepared-digest guards on actual imported public key objects.
use super::{
    arguments::hex,
    configuration::Configuration,
    object_fixture::{self, Fixture},
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

struct Case {
    action: String,
    spki: Vec<u8>,
    input: Vec<u8>,
    fingerprint: Vec<u8>,
}
impl Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(8193)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if bytes.len() > 8192 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("fixture_utf8"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if fields.len() != 4
            || !matches!(
                fields[0],
                "dsa_scalar"
                    | "dsa_der"
                    | "dsa_width"
                    | "not_dsa_from"
                    | "not_dsa_to"
                    | "not_ecdsa_from"
                    | "not_ecdsa_to"
                    | "historical_digest"
                    | "pss_digest"
                    | "not_rsa"
                    | "not_edwards"
                    | "edwards_curve"
            )
        {
            return Err(Failure::Input("verification_guard_fields"));
        }
        let fingerprint = hex(fields[3], 32).map_err(Failure::Input)?;
        if fingerprint.len() != 32 {
            return Err(Failure::Input("fingerprint_width"));
        }
        Ok(Self {
            action: fields[0].into(),
            spki: hex(fields[1], 2048).map_err(Failure::Input)?,
            input: hex(fields[2], 128).map_err(Failure::Input)?,
            fingerprint,
        })
    }
}

fn dsa_control(key: &VerificationKey, width: usize) -> std::result::Result<(), Failure> {
    // Width comes from the selected public fixture, not from untrusted input.
    let mut raw = vec![0u8; width * 2];
    raw[width - 1] = 1;
    raw[width * 2 - 1] = 2;
    let der = [0x30, 6, 2, 1, 1, 2, 1, 2];
    if key.dsa_signature_to_der(&raw)? != der || key.dsa_signature_from_der(&der)? != raw {
        return Err(Failure::Oracle("dsa_scalar_control"));
    }
    Ok(())
}

fn check(
    session: &Session,
    key: &VerificationKey,
    case: &Case,
    module: &Module,
) -> std::result::Result<(), Failure> {
    let digest = session.digest(
        HashAlgorithm::Sha256,
        b"abc",
        InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: 3,
        },
    )?;
    let known = hex(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        32,
    )
    .map_err(Failure::Input)?;
    if digest.as_bytes() != known || key.fingerprint().as_slice() != case.fingerprint {
        return Err(Failure::Oracle("verification_guard_producer"));
    }
    let before = module.call_counts()?;
    if case.action == "edwards_curve" {
        match session.verify_eddsa(
            key,
            EdDsaParameters::new(EdDsaVariant::Ed448, &[])?,
            b"abc",
            &case.input,
            InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: 3,
            },
        ) {
            Err(Error::Rejected(RejectionReason::PublicVerification(
                PublicVerificationRejection::EddsaInstanceAndKeyCurveDiffer,
            ))) => (),
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(Failure::Oracle("edwards_curve_mismatch_accepted")),
        }
        if key.fingerprint().as_slice() != case.fingerprint || module.call_counts()? != before {
            return Err(Failure::Oracle(
                "edwards_curve_guard_changed_owner_or_dispatched",
            ));
        }
        return Ok(());
    }
    if case.action == "not_edwards" {
        match session.verify_pure_eddsa(
            key,
            b"abc",
            &case.input,
            InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: 3,
            },
        ) {
            Err(Error::Rejected(RejectionReason::PublicVerification(
                PublicVerificationRejection::NotAnEdwardsReference,
            ))) => (),
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(Failure::Oracle("rsa_key_accepted_as_edwards")),
        }
        if module.call_counts()? != before {
            return Err(Failure::Oracle("edwards_family_guard_dispatched"));
        }
        return Ok(());
    }
    let dsa = matches!(case.action.as_str(), "dsa_scalar" | "dsa_width" | "dsa_der");
    if dsa {
        dsa_control(key, if case.action == "dsa_der" { 20 } else { 32 })?;
    }
    let (actual, expected) = match case.action.as_str() {
        "dsa_der" => (
            key.dsa_signature_from_der(&case.input).map(|_| ()),
            ClassicalSignaturesRejection::DsaSignatureDer,
        ),
        "dsa_scalar" => (
            key.dsa_signature_from_der(&case.input).map(|_| ()),
            ClassicalSignaturesRejection::DsaScalarWidth,
        ),
        "dsa_width" => (
            key.dsa_signature_to_der(&case.input).map(|_| ()),
            ClassicalSignaturesRejection::DsaSignatureWidth,
        ),
        "not_dsa_from" => (
            key.dsa_signature_from_der(&case.input).map(|_| ()),
            ClassicalSignaturesRejection::NotADsaReference,
        ),
        "not_dsa_to" => (
            key.dsa_signature_to_der(&case.input).map(|_| ()),
            ClassicalSignaturesRejection::NotADsaReference,
        ),
        "not_ecdsa_from" => (
            key.ecdsa_signature_from_der(&case.input).map(|_| ()),
            ClassicalSignaturesRejection::NotAnEcdsaReference,
        ),
        "not_ecdsa_to" => (
            key.ecdsa_signature_to_der(&case.input).map(|_| ()),
            ClassicalSignaturesRejection::NotAnEcdsaReference,
        ),
        "historical_digest" => {
            let historical = HistoricalDigest::from_bytes(HistoricalHash::Md5, &[0; 16])?;
            (
                session
                    .verify_historical_digest(
                        key,
                        HistoricalProfile::RsaPkcs1(HistoricalHash::Sha1),
                        &historical,
                        &case.input,
                    )
                    .map(|_| ()),
                ClassicalSignaturesRejection::HistoricalDigestProfile,
            )
        }
        "pss_digest" => (
            session
                .verify_rsa_pss_digest(
                    key,
                    RsaPssParameters {
                        hash: HashAlgorithm::Sha384,
                        mgf_hash: HashAlgorithm::Sha384,
                        salt_length: 48,
                    },
                    &digest,
                    &case.input,
                )
                .map(|_| ()),
            ClassicalSignaturesRejection::PssDigestAlgorithm,
        ),
        "not_rsa" => (
            session
                .verify_rsa_pss_digest(
                    key,
                    RsaPssParameters {
                        hash: HashAlgorithm::Sha256,
                        mgf_hash: HashAlgorithm::Sha256,
                        salt_length: 32,
                    },
                    &digest,
                    &case.input,
                )
                .map(|_| ()),
            ClassicalSignaturesRejection::NotAnRsaReference,
        ),
        _ => return Err(Failure::Input("verification_guard_action")),
    };
    match actual {
        Err(Error::Rejected(RejectionReason::ClassicalSignatures(reason)))
            if reason == expected =>
        {
            ()
        }
        Err(error) => return Err(error.into()),
        Ok(()) => return Err(Failure::Oracle("verification_guard_refusal_missing")),
    }
    if dsa {
        dsa_control(key, if case.action == "dsa_der" { 20 } else { 32 })?;
    }
    if key.fingerprint().as_slice() != case.fingerprint
        || digest.as_bytes() != known
        || module.call_counts()? != before
    {
        return Err(Failure::Oracle(
            "verification_guard_changed_owner_or_dispatched",
        ));
    }
    Ok(())
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut fixture = None;
    let setup = (|| -> std::result::Result<(Case, VerificationKey), Failure> {
        let case = Case::read(path)?;
        fixture = Some(Fixture::open(&module, config)?);
        let owner = fixture.as_mut().ok_or(Failure::Input("public_key_owner"))?;
        let created = owner.session.create_verification_key(
            &case.spki,
            &[],
            MechanismObservationPlan::NotRequested,
            object_fixture::public_key_options(config.label.as_bytes()),
        )?;
        Ok((case, owner.retain_public_key(created)?))
    })();
    let started = setup.is_ok();
    let body = match &setup {
        Ok((case, key)) => match &fixture {
            Some(owner) => check(&owner.session, key, case, &module),
            None => Err(Failure::Input("public_key_owner")),
        },
        Err(_) => Ok(()),
    };
    if let Err(error) = &setup {
        outcome::record(&mut report, Phase::Setup, error)?;
    }
    if let Err(error) = &body {
        outcome::record(&mut report, Phase::Body, error)?;
    }
    drop(setup);
    let mut cleanup = fixture.as_mut().map_or_else(Vec::new, Fixture::close);
    drop(fixture);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    for error in &cleanup {
        outcome::record(&mut report, Phase::Cleanup, error)?;
    }
    if started {
        report.observation(
            Phase::Body,
            "public_key_and_digest_retained_without_native_verify",
            Producer::Fe11Local,
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
