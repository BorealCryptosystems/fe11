// SPDX-License-Identifier: Apache-2.0
//! ABI boundary inputs for validation selectors and classic CCM's declared length.
use crate::{
    object_owner::Owner, outcome::{self, Failure}, report::{Phase, Producer, Report},
    single_key_case::SingleKeyCase,
};
use fe11::*;
use std::{fs::File, io::{Read, Write}, path::Path};

enum Probe { Flags { native: bool }, Ccm { decrypt: bool } }

pub(super) struct Case {
    advanced: bool,
    probe: Probe,
}

impl SingleKeyCase for Case {
    const ASSERTION: &'static str = "session_abi_boundary_disposition";
    const PRODUCER: Producer = Producer::TestOracle;
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut text = String::new();
        File::open(path).and_then(|f| f.take(65).read_to_string(&mut text))
            .map_err(|_| Failure::Input("session_width_fixture"))?;
        let mut fields = text.lines();
        let advanced = match fields.next() {
            Some("session") => false,
            Some("advanced") => true,
            _ => return Err(Failure::Input("width_fixture_owner")),
        };
        let probe = match fields.next() {
            Some("flags-legacy") => Probe::Flags { native: false },
            Some("flags-standard") => Probe::Flags { native: true },
            Some("ccm-encrypt") => Probe::Ccm { decrypt: false },
            Some("ccm-decrypt") => Probe::Ccm { decrypt: true },
            _ => return Err(Failure::Input("width_fixture_operation")),
        };
        if fields.next().is_some() { return Err(Failure::Input("trailing_width_fixture")); }
        Ok(Self { advanced, probe })
    }
    fn advanced(&self) -> bool { self.advanced }
    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        Ok(owner.import_secret(b"0123456789abcdef", fe11_sys::CKK_AES,
            [StandardAttribute::ENCRYPT, StandardAttribute::DECRYPT])?)
    }
    fn check<W: Write>(&self, owner: &Owner, key: &NativeObjectRef, report: &mut Report<W>)
        -> std::result::Result<(), Failure> {
        for value in [0, 1, u32::MAX as u64, u32::MAX as u64 + 1, u64::MAX] {
            let error = match self.probe {
                Probe::Flags { native } => {
                    let result = match owner {
                        Owner::Advanced(s) => s.validation_flags(value),
                        Owner::Session(s) => s.validation_flags(value),
                    };
                    match result {
                        Err(e @ Error::Native { function: "C_GetSessionValidationFlags", code: 84, .. }) if native => e,
                        Err(e @ Error::Rejected(RejectionReason::SessionLifecycle(
                            SessionLifecycleRejection::CGetSessionValidationFlagsUnavailable))) if !native => e,
                        Err(e) => return Err(e.into()),
                        Ok(_) => return Err(Failure::Oracle("unexpected_validation_flags")),
                    }
                }
                Probe::Ccm { decrypt } => {
                    // A seven-byte nonce leaves eight bytes for the CCM length.
                    // The value is metadata; no allocation uses this length.
                    let parameters = ClassicAeadParameters::Ccm { nonce: &[0; 7], aad: &[], mac_length: 16 };
                    let output = CipherOutputPlan::Buffer { capacity: 32 };
                    let result = match (owner, decrypt) {
                        (Owner::Session(s), false) => s.begin_encrypt_classic_aead_stream(key, parameters, Some(value), output),
                        (Owner::Session(s), true) => s.begin_decrypt_classic_aead_stream(key, parameters, Some(value), output),
                        (Owner::Advanced(s), false) => s.begin_encrypt_classic_aead_stream(key, parameters, Some(value), output),
                        (Owner::Advanced(s), true) => s.begin_decrypt_classic_aead_stream(key, parameters, Some(value), output),
                    };
                    match result {
                        Err(e @ Error::Native { function: "C_EncryptInit", code: 112, .. }) if !decrypt => e,
                        Err(e @ Error::Native { function: "C_DecryptInit", code: 112, .. }) if decrypt => e,
                        Err(e) => return Err(e.into()),
                        Ok(_) => return Err(Failure::Oracle("unexpected_ccm_width_acceptance")),
                    }
                }
            };
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("width_observation_write"))?;
        }
        Ok(())
    }
}
