// SPDX-License-Identifier: Apache-2.0
//! Two initializers on one session, with the first operation still owned.
use super::super::{
    arguments::hex,
    configuration::Configuration,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Observation, Phase, Producer, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    num::NonZeroUsize,
    path::Path,
};

#[derive(Clone, Copy)]
enum Family {
    Digest,
    Cipher,
    Sign,
    Verify,
    Search,
}

impl Family {
    fn parse(name: &str) -> std::result::Result<Self, Failure> {
        match name {
            "digest" => Ok(Self::Digest),
            "cipher" => Ok(Self::Cipher),
            "sign" => Ok(Self::Sign),
            "verify" => Ok(Self::Verify),
            "search" => Ok(Self::Search),
            _ => Err(Failure::Input("operation_family")),
        }
    }

    fn function(self) -> &'static str {
        match self {
            Self::Digest => "C_DigestInit",
            Self::Cipher => "C_EncryptInit",
            Self::Sign => "C_SignInit",
            Self::Verify => "C_VerifyInit",
            Self::Search => "C_FindObjectsInit",
        }
    }
}

struct Case {
    first: Family,
    second: Family,
    modulus: Vec<u8>,
    exponent: Vec<u8>,
}

impl Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut data = String::new();
        File::open(path)
            .map_err(|_| Failure::Input("pair_fixture"))?
            .take(641)
            .read_to_string(&mut data)
            .map_err(|_| Failure::Input("pair_encoding"))?;
        if data.len() > 640 {
            return Err(Failure::Input("pair_limit"));
        }
        let lines: Vec<_> = data.lines().collect();
        let [a, b, n, e] = lines.as_slice() else {
            return Err(Failure::Input("pair_fields"));
        };
        let modulus = hex(n, 256).map_err(Failure::Input)?;
        let exponent = hex(e, 3).map_err(Failure::Input)?;
        if modulus.len() != 256 || exponent != [1, 0, 1] {
            return Err(Failure::Input("pair_rsa"));
        }
        Ok(Self {
            first: Family::parse(a)?,
            second: Family::parse(b)?,
            modulus,
            exponent,
        })
    }
}

enum Active<'a> {
    Crypto(OperationTicket),
    Search(NativeObjectIterator<'a>),
}

impl Active<'_> {
    fn finish_search(self) -> Result<()> {
        match self {
            Self::Search(mut cursor) => cursor.finish(),
            // The session close releases the retained native crypto operation.
            Self::Crypto(ticket) => {
                drop(ticket);
                Ok(())
            }
        }
    }
}

/// Complete the exact predecessor after the other Init returned. This is an
/// independent check of the ticket, not a replacement operation on the session.
fn finish_original(
    session: &Session,
    first: Family,
    modulus: &[u8],
    mut ticket: OperationTicket,
) -> std::result::Result<(), Failure> {
    let limits = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: 3,
    };
    let valid = match first {
        Family::Cipher => matches!(session.poll_cipher(&mut ticket)?,
            OperationProgress::ExtensionEncrypted(output) if output.as_bytes().len() == modulus.len()
                && output.as_bytes().iter().any(|&octet| octet != 0) && output.as_bytes() < modulus),
        Family::Digest => {
            let expected = hex(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                32,
            )
            .map_err(Failure::Input)?;
            session.finish_native_digest(&mut ticket)?.as_bytes() == expected
        }
        Family::Sign | Family::Verify => {
            // HMAC-SHA256(key = 32 bytes of 0x37, data = "abc").
            let expected = hex(
                "c1940eae71b7ae73588d111db11fea5ff2f0ef4eaaaef17ee208747b915f68bb",
                32,
            )
            .map_err(Failure::Input)?;
            let signature = matches!(first, Family::Verify).then_some(expected.as_slice());
            match session.finish_signature_single(&mut ticket, b"abc", signature, limits)? {
                OperationProgress::NativeSignature(result) => {
                    matches!(first, Family::Sign) && result.as_bytes() == expected
                }
                OperationProgress::NativeVerification(_) => matches!(first, Family::Verify),
                _ => false,
            }
        }
        Family::Search => return Err(Failure::Input("expected_crypto_predecessor")),
    };
    if valid {
        Ok(())
    } else {
        Err(Failure::Oracle("original_operation_completion"))
    }
}

fn start<'a>(
    session: &'a Session,
    family: Family,
    rsa: &NativeObjectRef,
    mac: &NativeObjectRef,
) -> Result<Active<'a>> {
    let mac_parameters = NativeMacParameters::Full(NativeMacAlgorithm::SHA256_HMAC);
    match family {
        Family::Digest => session
            .begin_native_digest(NativeDigestAlgorithm::Sha256)
            .map(Active::Crypto),
        Family::Cipher => session
            .begin_encrypt_native_rsa(
                rsa,
                NativeRsaCipherParameters::Pkcs1v15,
                b"abc",
                256,
                InputLimits {
                    maximum_parts: 1,
                    maximum_total_bytes: 3,
                },
            )
            .map(Active::Crypto),
        Family::Sign => session
            .begin_native_mac_single(
                mac,
                mac_parameters,
                SignatureOutputPlan::Buffer { capacity: 32 },
                32,
            )
            .map(Active::Crypto),
        Family::Verify => session
            .begin_native_mac_verify_single(mac, mac_parameters)
            .map(Active::Crypto),
        Family::Search => session
            .iter_native_objects(
                &[],
                AttributeTemplateLimits {
                    maximum_depth: 0,
                    maximum_attributes: 1,
                    maximum_value_bytes: 1,
                },
                NonZeroUsize::MIN,
            )
            .map(Active::Search),
    }
}

pub(crate) fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let setup = (|| -> std::result::Result<_, Failure> {
        let case = Case::read(path)?;
        owner = Some(Owner::open(&module, config, false)?);
        let holder = owner.as_ref().ok_or(Failure::Input("pair_owner"))?;
        let rsa = holder.import_rsa_public_usage(
            &case.modulus,
            &case.exponent,
            StandardAttribute::ENCRYPT,
        )?;
        let mac = holder.import_secret(
            &[0x37; 32],
            fe11_sys::CKK_GENERIC_SECRET,
            [StandardAttribute::SIGN, StandardAttribute::VERIFY],
        )?;
        Ok((case, rsa, mac))
    })();
    let mut cleanup = Vec::new();
    let body = (|| -> std::result::Result<(), Failure> {
        let Ok((case, rsa, mac)) = &setup else {
            return Ok(());
        };
        let Some(Owner::Session(session)) = &owner else {
            return Err(Failure::Input("pair_session"));
        };
        let original = start(session, case.first, rsa, mac)?;
        report
            .observation(
                Phase::Body,
                "first_operation_initialized",
                Producer::Fe11Local,
                Observation::Boolean(true),
            )
            .map_err(|_| Failure::Input("pair_report"))?;
        let result = match start(session, case.second, rsa, mac) {
            Err(error @ Error::Native { function, code, .. })
                if function == case.second.function()
                    && code == fe11_sys::CKR_OPERATION_ACTIVE as u64 =>
            {
                outcome::record(&mut report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("pair_report"))
            }
            Err(error) => Err(error.into()),
            Ok(other) => {
                if let Err(e) = other.finish_search() {
                    cleanup.push(e.into());
                }
                Err(Failure::Oracle(
                    "second_init_accepted_on_single_operation_recipe",
                ))
            }
        };
        if !matches!(case.first, Family::Search) && result.is_ok() {
            let Active::Crypto(ticket) = original else {
                return Err(Failure::Input("expected_crypto_predecessor"));
            };
            finish_original(session, case.first, &case.modulus, ticket)?;
            report
                .observation(
                    Phase::Body,
                    "original_operation_completed",
                    Producer::Fe11Local,
                    Observation::Boolean(true),
                )
                .map_err(|_| Failure::Input("pair_report"))?;
        } else if let Err(e) = original.finish_search() {
            cleanup.push(e.into());
        }
        result
    })();
    // All imported objects have CKA_TOKEN=false. Close their exact session even
    // if a refused Init leaves an operation active; never search for cleanup.
    let setup = setup.map(|_| ());
    if let Some(held) = owner {
        cleanup.extend(held.close(None));
    }
    if let Err(e) = module.close() {
        cleanup.push(e.into());
    }
    super::finish(report, setup, body, cleanup)
}
