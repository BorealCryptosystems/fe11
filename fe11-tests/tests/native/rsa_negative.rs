// SPDX-License-Identifier: Apache-2.0
//! Isolated RSA input faults bracketed by valid operations on the same owner.
use super::{
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Observation, Phase, Producer, Report},
    rsa_known_fixture::{NegativeKind, Vector},
    single_key_case::SingleKeyCase,
};
use fe11::*;
use std::{fs::OpenOptions, io::Write, path::Path};

pub struct Negative(Vector);

fn call(
    owner: &Owner,
    key: &NativeObjectRef,
    vector: &Vector,
    input: &[u8],
    parameters: NativeSignatureParameters<'_>,
    signature: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let parts = [input];
    let limits = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: input.len(),
    };
    if vector.action == "verify" {
        owner
            .verify_parameters(
                key,
                parameters,
                MessageRoute::Single,
                &parts,
                signature.unwrap_or(&vector.expected),
                limits,
            )
            .map(|()| Vec::new())
    } else {
        match owner {
            Owner::Session(session) => session.sign_native(
                key,
                parameters,
                MessageRoute::Single,
                &parts,
                limits,
                256,
                None,
            ),
            Owner::Advanced(session) => session.sign_native(
                key,
                parameters,
                MessageRoute::Single,
                &parts,
                limits,
                256,
                None,
            ),
        }
        .map(|signature| signature.as_bytes().to_vec())
    }
}

impl SingleKeyCase for Negative {
    const ASSERTION: &'static str = "rsa_input_refusal_and_same_owner_reuse";
    const PRODUCER: Producer = Producer::TestOracle;
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let vector = Vector::read(path)?;
        if vector.negative.is_none() || vector.expected.len() != 256 {
            return Err(Failure::Input("rsa_negative_fixture"));
        }
        Ok(Self(vector))
    }
    fn advanced(&self) -> bool {
        self.0.advanced
    }
    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        let vector = &self.0;
        Ok(if vector.action == "sign" {
            owner.import_rsa_private(&vector.key, StandardAttribute::SIGN)?
        } else {
            owner.import_rsa_public_usage(
                &vector.key[0],
                &vector.key[1],
                StandardAttribute::VERIFY,
            )?
        })
    }
    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        let vector = &self.0;
        let kind = vector.negative.ok_or(Failure::Input("rsa_negative_kind"))?;
        let mut outputs = call(owner, key, vector, &vector.input, vector.signature()?, None)?;
        let mut inputs = Vec::new();
        let expected_code = match kind {
            NegativeKind::ChangedMessage => {
                let mut changed = vector.input.clone();
                *changed
                    .first_mut()
                    .ok_or(Failure::Input("rsa_changed_message_empty"))? ^= 1;
                inputs.push(changed);
                fe11_sys::CKR_SIGNATURE_INVALID
            }
            NegativeKind::WrongKey => {
                // The negative signature is unchanged from the independently
                // validated original-key fixture. This owner imports a different
                // same-size key, with its own valid positive signature control.
                inputs.push(vector.input.clone());
                fe11_sys::CKR_SIGNATURE_INVALID
            }
            NegativeKind::PssDigestLength => {
                if vector.input.len() != 32 {
                    return Err(Failure::Input("pss_control_digest_length"));
                }
                inputs.push(vector.input[..31].to_vec());
                let mut longer = vector.input.clone();
                longer.push(0);
                inputs.push(longer);
                fe11_sys::CKR_DATA_LEN_RANGE
            }
            NegativeKind::PssHashMismatch => {
                inputs.push(vector.input.clone());
                fe11_sys::CKR_MECHANISM_PARAM_INVALID
            }
        };
        let function = match (vector.action.as_str(), kind) {
            ("sign", NegativeKind::PssHashMismatch) => "C_SignInit",
            ("verify", NegativeKind::PssHashMismatch) => "C_VerifyInit",
            ("sign", _) => "C_Sign",
            _ => "C_Verify",
        };
        let mut diagnostic_mismatch = false;
        for input in inputs {
            // Change only hashAlg. The combined selector, MGF, salt, key and
            // message remain those of the preceding valid control.
            let parameters = if matches!(kind, NegativeKind::PssHashMismatch) {
                NativeSignatureParameters::RsaPss {
                    algorithm: NativePssAlgorithm::SHA256_RSA_PKCS_PSS,
                    hash: fe11_sys::CKM_SHA384 as u64,
                    mgf: fe11_sys::CKG_MGF1_SHA256 as u64,
                    salt_bytes: 32,
                }
            } else {
                vector.signature()?
            };
            match call(
                owner,
                key,
                vector,
                &input,
                parameters,
                vector.negative_signature.as_deref(),
            ) {
                Err(
                    error @ Error::Native {
                        function: actual,
                        code,
                        ..
                    },
                ) if actual == function => {
                    // Preserve every native refusal. A diagnostic mismatch
                    // still fails the scenario, but must not hide the next
                    // input boundary or the same-owner reuse control.
                    diagnostic_mismatch |= code != expected_code as u64;
                    outcome::record(report, Phase::Body, &Failure::Product(error))
                        .map_err(|_| Failure::Input("report_write"))?;
                }
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(Failure::Oracle("rsa_invalid_input_accepted")),
            }
            // Reuse the exact owner and key after each refusal. Independent
            // verification of every positive signing output is required by the driver.
            outputs.extend(call(
                owner,
                key,
                vector,
                &vector.input,
                vector.signature()?,
                None,
            )?);
        }
        if vector.action == "sign" {
            let count = if matches!(kind, NegativeKind::PssDigestLength) {
                3
            } else {
                2
            };
            if outputs.len() != 256 * count {
                return Err(Failure::Oracle("rsa_control_output_count"));
            }
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open("public-rsa-controls.bin")
                .map_err(|_| Failure::Input("reference_output_create"))?;
            file.write_all(&outputs)
                .and_then(|()| file.flush())
                .map_err(|_| Failure::Input("reference_output_write"))?;
        }
        report
            .observation(
                Phase::Body,
                "rsa_positive_controls_complete",
                Producer::TestOracle,
                Observation::Boolean(true),
            )
            .map_err(|_| Failure::Input("report_write"))?;
        if diagnostic_mismatch {
            Err(Failure::Oracle("rsa_native_diagnostic_mismatch"))
        } else {
            Ok(())
        }
    }
}
