// SPDX-License-Identifier: Apache-2.0
//! Malformed key encodings must fail before creation and preserve session use.
//! Fixtures contain only published test keys and explicit structural mutations.
use super::{
    arguments::hex,
    configuration::{select_token, Configuration},
    credentials::Credentials,
    object_fixture::public_key_options,
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
    wrapping: bool,
    algorithm: ClassicalKeyAlgorithm,
    cause: KeyEncodingRejection,
    input: Vec<u8>,
    spki: Vec<u8>,
}
impl Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(131073)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if bytes.len() > 131072 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("fixture_encoding"))?;
        let f: Vec<_> = text.split_terminator('\n').collect();
        if f.len() != 5 || !matches!(f[0], "wrapping" | "signing") {
            return Err(Failure::Input("import_encoding_fields"));
        }
        let algorithm = match f[1] {
            "Rsa2048" => ClassicalKeyAlgorithm::Rsa { bits: 2048 },
            "EcdsaP256" => ClassicalKeyAlgorithm::Ecdsa(EcCurve::P256),
            "Ed25519" => ClassicalKeyAlgorithm::Ed25519,
            _ => return Err(Failure::Input("import_encoding_algorithm")),
        };
        let cause = match f[2] {
            "RsaNullParametersRequired" => KeyEncodingRejection::RsaNullParametersRequired,
            "RsaParameters" => KeyEncodingRejection::RsaParameters,
            "RsaPublicDer" => KeyEncodingRejection::RsaPublicDer,
            "RsaSpkiAlgorithm" => KeyEncodingRejection::RsaSpkiAlgorithm,
            "RsaSpkiDer" => KeyEncodingRejection::RsaSpkiDer,
            "RsaUnusedBits" => KeyEncodingRejection::RsaUnusedBits,
            "MultiPrimeRsaUnsupported" => KeyEncodingRejection::MultiPrimeRsaUnsupported,
            "PrivateEcAlgorithm" => KeyEncodingRejection::PrivateEcAlgorithm,
            "PrivateEcDer" => KeyEncodingRejection::PrivateEcDer,
            "PrivateEcNamedCurveAbsent" => KeyEncodingRejection::PrivateEcNamedCurveAbsent,
            "PrivateEcParameters" => KeyEncodingRejection::PrivateEcParameters,
            "PrivateEcVersion" => KeyEncodingRejection::PrivateEcVersion,
            "PrivateEdwardsAlgorithm" => KeyEncodingRejection::PrivateEdwardsAlgorithm,
            "PrivateEdwardsNestedOctetString" => {
                KeyEncodingRejection::PrivateEdwardsNestedOctetString
            }
            "PrivateEdwardsParameters" => KeyEncodingRejection::PrivateEdwardsParameters,
            "PrivateEdwardsSeedLength" => KeyEncodingRejection::PrivateEdwardsSeedLength,
            "PrivatePkcs8Der" => KeyEncodingRejection::PrivatePkcs8Der,
            "PrivatePkcs8Size" => KeyEncodingRejection::PrivatePkcs8Size,
            "PrivatePkcs8Version" => KeyEncodingRejection::PrivatePkcs8Version,
            "PrivateRsaDer" => KeyEncodingRejection::PrivateRsaDer,
            "PrivateRsaParameters" => KeyEncodingRejection::PrivateRsaParameters,
            "PrivateRsaParametersAbsent" => KeyEncodingRejection::PrivateRsaParametersAbsent,
            "PrivateRsaProfile" => KeyEncodingRejection::PrivateRsaProfile,
            _ => return Err(Failure::Input("import_encoding_cause")),
        };
        Ok(Self {
            wrapping: f[0] == "wrapping",
            algorithm,
            cause,
            input: hex(f[3], 32768).map_err(Failure::Input)?,
            spki: hex(f[4], 4096).map_err(Failure::Input)?,
        })
    }
}

fn history() -> HistoryObservationPlan {
    HistoryObservationPlan {
        sensitive: false,
        extractable: false,
        always_sensitive: false,
        never_extractable: false,
        local: false,
        generation: false,
        maximum_bytes: 64,
    }
}

fn signing_spec(algorithm: ClassicalKeyAlgorithm) -> SigningIntroductionSpec {
    SigningIntroductionSpec {
        history_observation: history(),
        key: ClassicalKeySpec {
            rsa_public_exponent: None,
            public_usages: KeyUsageRequest {
                verify: Some(true),
                ..KeyUsageRequest::omitted()
            },
            private_usages: KeyUsageRequest {
                sign: Some(true),
                ..KeyUsageRequest::omitted()
            },
            public_visibility: ObjectVisibility::Public,
            private_visibility: ObjectVisibility::Private,
            private_protection: CurrentKeyProtection {
                sensitive: true,
                extractable: false,
            },
            public_admission: public_key_options(b"encoding-public").admission,
            private_admission: public_key_options(b"encoding-private").admission,
            mechanisms: MechanismObservationPlan::NotRequested,
            algorithm,
            id: b"encoding-key".to_vec(),
            label: "encoding-key".into(),
            persistent: false,
            profiles: Vec::new(),
        },
    }
}
fn wrapping_spec() -> RsaKeyEncryptionSpec {
    RsaKeyEncryptionSpec {
        public_exponent: None,
        native_protection: CurrentKeyProtection {
            sensitive: true,
            extractable: false,
        },
        public_visibility: ObjectVisibility::Public,
        private_visibility: ObjectVisibility::Private,
        public_usages: KeyUsageRequest {
            wrap: Some(true),
            ..KeyUsageRequest::omitted()
        },
        private_usages: KeyUsageRequest::omitted(),
        history_observation: history(),
        public_admission: public_key_options(b"encoding-public").admission,
        private_admission: public_key_options(b"encoding-private").admission,
        bits: 2048,
        id: b"encoding-key".to_vec(),
        label: "encoding-key".into(),
        persistent: false,
    }
}

fn expect_refusal<T, W: Write>(
    result: Result<CreatedObjects<T>>,
    expected: KeyEncodingRejection,
    objects: &mut Vec<CreatedObjectSet>,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    match result {
        Err(Error::Rejected(RejectionReason::KeyEncoding(cause))) if cause == expected => {
            report
                .observation(
                    Phase::Body,
                    "exact_import_encoding_refusal",
                    Producer::Fe11Local,
                    Observation::Rejected(RejectionReason::KeyEncoding(cause)),
                )
                .map_err(|_| Failure::Input("report_write"))?;
            Ok(())
        }
        Err(error) => Err(error.into()),
        Ok(created) => {
            // Retain even an unexpected creation before failing the assertion.
            // Cleanup destroys those exact objects, never a search-selected key.
            objects.push(created.objects);
            Err(Failure::Oracle("malformed_key_import_accepted"))
        }
    }
}

fn check<W: Write>(
    case: &Case,
    session: &Session,
    objects: &mut Vec<CreatedObjectSet>,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    if case.wrapping {
        expect_refusal(
            session.import_rsa_wrapping_key(
                wrapping_spec(),
                &case.input,
                MechanismObservationPlan::NotRequested,
            ),
            case.cause,
            objects,
            report,
        )?;
    } else {
        let mut secret = SecretBytes::new(case.input.len())?;
        secret.as_mut_slice().copy_from_slice(&case.input);
        expect_refusal(
            session.import_signing_key(signing_spec(case.algorithm), secret, &case.spki),
            case.cause,
            objects,
            report,
        )?;
    }
    // This success proves session usability after the exact local refusal.
    // Its independently known answer is separate from any key-import claim.
    let digest = session.digest_native_single(
        NativeDigestAlgorithm::Sha256,
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
    if digest.as_bytes() != expected || digest.algorithm() != NativeDigestAlgorithm::Sha256 {
        return Err(Failure::Oracle("session_usable_after_encoding_refusal"));
    }
    Ok(())
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut session = None;
    let mut objects = Vec::new();
    let mut logged = false;
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = Case::read(path)?;
        let token =
            select_token(&module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        session = Some(module.select(&token)?.open_session(true)?);
        session
            .as_ref()
            .ok_or(Failure::Input("encoding_session"))?
            .login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        logged = true;
        Ok(case)
    })();
    let started = setup.is_ok();
    let (setup_result, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(case) => (
            Ok(()),
            match session.as_ref() {
                Some(session) => check(&case, session, &mut objects, &mut report),
                None => Err(Failure::Input("encoding_session")),
            },
        ),
    };
    let mut cleanup = Vec::new();
    if let Some(session) = session.as_ref() {
        for set in &objects {
            for object in set.as_slice() {
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
        if let Err(error) = session.close() {
            cleanup.push(error.into());
        }
    }
    drop(objects);
    drop(session);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    if let Err(error) = &setup_result {
        outcome::record(&mut report, Phase::Setup, error)?;
    }
    if let Err(error) = &body {
        outcome::record(&mut report, Phase::Body, error)?;
    }
    for error in &cleanup {
        outcome::record(&mut report, Phase::Cleanup, error)?;
    }
    report.finish(
        if setup_result.is_ok() {
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
