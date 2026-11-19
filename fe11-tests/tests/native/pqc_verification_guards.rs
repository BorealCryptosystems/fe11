// SPDX-License-Identifier: Apache-2.0
//! Typed PQC verification refusals retain real imported public keys.
use super::{
    arguments::hex, configuration::Configuration, module_controls, object_fixture,
    object_owner::Owner, outcome::Failure, report::Report,
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

struct Case {
    action: String,
    public: PqcPublicKey,
    signature: PqcSignature,
}

impl Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("pqc_guard_open"))?
            .take(16385)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("pqc_guard_read"))?;
        if bytes.len() > 16384 {
            return Err(Failure::Input("pqc_guard_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("pqc_guard_encoding"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if fields.len() != 3
            || !matches!(
                fields[0],
                "algorithm"
                    | "multipart_algorithm"
                    | "message_ceiling"
                    | "prehash_length"
                    | "multipart_prehash"
                    | "multipart_pure"
            )
        {
            return Err(Failure::Input("pqc_guard_fields"));
        }
        let public = PqcPublicKey::from_raw(
            PqcAlgorithm::MlDsa(MlDsaParameterSet::MlDsa44),
            &hex(fields[1], 1312).map_err(Failure::Input)?,
        )?;
        let variant = if fields[0].ends_with("algorithm") {
            MlDsaParameterSet::MlDsa65
        } else {
            MlDsaParameterSet::MlDsa44
        };
        let signature = PqcSignature::from_bytes(
            PqcAlgorithm::MlDsa(variant),
            &hex(fields[2], 3309).map_err(Failure::Input)?,
        )?;
        Ok(Self {
            action: fields[0].into(),
            public,
            signature,
        })
    }
}

fn check(
    module: &Module,
    session: &Session,
    key: &PqcVerificationKey,
    case: &Case,
) -> std::result::Result<(), Failure> {
    let fingerprint = key.fingerprint();
    let original = case.signature.as_bytes().to_vec();
    let prehash = [0u8; 32];
    let message: &[u8] = match case.action.as_str() {
        "prehash_length" => &prehash[..31],
        "multipart_prehash" => &prehash,
        _ => b"abc",
    };
    let mode = match case.action.as_str() {
        "prehash_length" | "multipart_prehash" => PqcSignatureMode::Prehashed(PqcHash::Sha256),
        "multipart_algorithm" => PqcSignatureMode::HashMessage(PqcHash::Sha256),
        _ => PqcSignatureMode::Pure,
    };
    let parameters = PqcSignatureParameters::new(mode, &[], PqcHedging::Preferred)?;
    let limits = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: if case.action == "message_ceiling" {
            2
        } else {
            message.len()
        },
    };
    let before = module.call_counts()?;
    let result = if case.action.starts_with("multipart_") {
        session.verify_pqc_multipart(key, &parameters, &[message], &case.signature, limits)
    } else {
        session.verify_pqc(key, &parameters, message, &case.signature, limits)
    };
    let expected = match case.action.as_str() {
        "multipart_prehash" => Error::Unsupported(UnsupportedReason::PostQuantumKeys(
            PostQuantumKeysUnsupported::Pkcs11PqcExternalPrehashIsSinglePartOnly,
        )),
        "multipart_pure" => Error::Unsupported(UnsupportedReason::PostQuantumKeys(
            PostQuantumKeysUnsupported::PurePqcMultipartVerificationRequiresVerifysignature,
        )),
        action => Error::Rejected(RejectionReason::PostQuantumKeys(match action {
            "algorithm" | "multipart_algorithm" => {
                PostQuantumKeysRejection::PqcSignatureAlgorithmMismatch
            }
            "message_ceiling" => PostQuantumKeysRejection::PqcMessageCeiling,
            "prehash_length" => PostQuantumKeysRejection::PqcPrehashLength,
            _ => return Err(Failure::Input("pqc_guard_action")),
        })),
    };
    match result {
        Err(actual) if actual == expected => (),
        Err(actual) => return Err(actual.into()),
        Ok(_) => return Err(Failure::Oracle("pqc_guard_missing")),
    }
    if module.call_counts()? != before
        || key.fingerprint() != fingerprint
        || case.signature.as_bytes() != original
    {
        return Err(Failure::Oracle("pqc_guard_changed_state"));
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
        return Err(Failure::Oracle("pqc_guard_session_control"));
    }
    Ok(())
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut objects = None;
    let setup = (|| -> std::result::Result<(Case, PqcVerificationKey), Failure> {
        let case = Case::read(path)?;
        owner = Some(Owner::open(&module, config, false)?);
        let Some(Owner::Session(session)) = &owner else {
            return Err(Failure::Input("pqc_guard_owner"));
        };
        let spki = case.public.to_spki()?;
        let created = session.import_pqc_verification_key(
            &spki,
            MechanismAttributes {
                request: MechanismRequest::Omitted,
                admission: MechanismObservationPlan::NotRequested,
            },
            object_fixture::public_key_options(config.label.as_bytes()),
        )?;
        objects = Some(created.objects);
        if created.remainder.is_some() {
            return Err(Failure::Oracle("pqc_guard_unexpected_remainder"));
        }
        Ok((case, created.observation?))
    })();
    let body = match (&setup, &owner) {
        (Ok((case, key)), Some(Owner::Session(session))) => check(&module, session, key, case),
        (Err(_), _) => Ok(()),
        _ => Err(Failure::Input("pqc_guard_owner")),
    };
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
