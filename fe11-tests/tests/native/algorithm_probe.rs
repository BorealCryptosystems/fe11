// SPDX-License-Identifier: Apache-2.0
//! One real algorithm-availability witness per isolated preparation process.
//! A round trip is a prerequisite witness, not a published-vector test oracle.
use super::{
    configuration::Configuration,
    outcome::Failure,
    probe_kem,
    probe_session::ProbeSession,
    probe_signatures::{self, SignatureFamily},
};
use crate::credentials::Credentials;

enum Selection {
    Signature(SignatureFamily),
    Kem(fe11_sys::CK_ULONG),
    Agreement(bool),
    Symmetric(String),
    Digest(String),
}

fn selection(name: &str) -> Result<Selection, Failure> {
    let signature = match name {
        "rsa" => SignatureFamily::Rsa,
        "dsa" => SignatureFamily::Dsa,
        "dh" => return Ok(Selection::Agreement(false)),
        "ecdh" => return Ok(Selection::Agreement(true)),
        "aes" | "des" | "des2" | "des3" | "hmac" | "cmac" => {
            return Ok(Selection::Symmetric(name.to_owned()))
        }
        "digest-md5" | "digest-sha-1" | "digest-sha224" | "digest-sha256" | "digest-sha384"
        | "digest-sha512" | "digest-sha3-224" | "digest-sha3-256" | "digest-sha3-384"
        | "digest-sha3-512" => return Ok(Selection::Digest(name.to_owned())),
        "ecdsa" => SignatureFamily::Ecdsa,
        "ed25519" => SignatureFamily::Edwards25519,
        "ed448" => SignatureFamily::Edwards448,
        _ => {
            let (family, parameter) = name
                .rsplit_once('-')
                .ok_or(Failure::Input("probe_algorithm"))?;
            let parameter = parameter
                .parse()
                .map_err(|_| Failure::Input("probe_parameter"))?;
            return match family {
                "ml-dsa" if (1..=3).contains(&parameter) => {
                    Ok(Selection::Signature(SignatureFamily::MlDsa(parameter)))
                }
                "slh-dsa" if (1..=12).contains(&parameter) => {
                    Ok(Selection::Signature(SignatureFamily::SlhDsa(parameter)))
                }
                "ml-kem" if (1..=3).contains(&parameter) => Ok(Selection::Kem(parameter)),
                _ => Err(Failure::Input("probe_algorithm_parameter")),
            };
        }
    };
    Ok(Selection::Signature(signature))
}

pub(super) struct Outcome {
    pub body: Result<(), Failure>,
    pub cleanup: Vec<Failure>,
}

pub(super) fn run(config: &Configuration, pins: &mut Credentials, name: &str) -> Outcome {
    let mut owner = ProbeSession::new();
    let body = (|| {
        let selected = selection(name)?;
        owner.open(config, &mut pins.user)?;
        match selected {
            Selection::Signature(family) => probe_signatures::run(&mut owner, family),
            Selection::Kem(parameter) => probe_kem::run(&mut owner, parameter),
            Selection::Agreement(elliptic) => super::probe_agreement::run(&mut owner, elliptic),
            Selection::Symmetric(name) => super::probe_symmetric::run(&mut owner, &name),
            Selection::Digest(name) => super::probe_digests::run(&mut owner, &name),
        }
    })();
    let cleanup = owner.close();
    Outcome { body, cleanup }
}
