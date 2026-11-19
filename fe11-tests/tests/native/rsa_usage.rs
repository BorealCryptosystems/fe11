// SPDX-License-Identifier: Apache-2.0
//! One-fault RSA usage refusals preserve otherwise valid known-answer inputs.
use super::{
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, Report},
    rsa_known_fixture::Vector,
    single_key_case::SingleKeyCase,
};
use fe11::*;
use std::{io::Write, path::Path};

pub struct Usage(Vector);
impl SingleKeyCase for Usage {
    const ASSERTION: &'static str = "rsa_disabled_usage_refused_at_native_init";
    const PRODUCER: super::report::Producer = super::report::Producer::TestOracle;
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        Ok(Self(Vector::read(path)?))
    }
    fn advanced(&self) -> bool {
        self.0.advanced
    }
    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        let v = &self.0;
        let usage = match v.action.as_str() {
            "sign" => StandardAttribute::SIGN,
            "verify" => StandardAttribute::VERIFY,
            "encrypt" => StandardAttribute::ENCRYPT,
            "decrypt" => StandardAttribute::DECRYPT,
            _ => return Err(Failure::Input("rsa_usage_action")),
        };
        let key = if matches!(v.action.as_str(), "sign" | "decrypt") {
            owner.import_rsa_private_usage(&v.key, usage, false)
        } else {
            owner.import_rsa_public_usage_enabled(&v.key[0], &v.key[1], usage, false)
        };
        Ok(key?)
    }
    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        let v = &self.0;
        let parts = [v.input.as_slice()];
        let limits = InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: v.input.len(),
        };
        let (result, expected_function) = match v.action.as_str() {
            "sign" => (
                match owner {
                    Owner::Session(s) => s.sign_native(
                        key,
                        v.signature()?,
                        MessageRoute::Single,
                        &parts,
                        limits,
                        256,
                        None,
                    ),
                    Owner::Advanced(s) => s.sign_native(
                        key,
                        v.signature()?,
                        MessageRoute::Single,
                        &parts,
                        limits,
                        256,
                        None,
                    ),
                }
                .map(|_| ()),
                "C_SignInit",
            ),
            "verify" => (
                owner.verify_parameters(
                    key,
                    v.signature()?,
                    MessageRoute::Single,
                    &parts,
                    &v.expected,
                    limits,
                ),
                "C_VerifyInit",
            ),
            "encrypt" => (
                match owner {
                    Owner::Session(s) => {
                        s.encrypt_native_rsa(key, v.cipher()?, &v.input, 256, limits)
                    }
                    Owner::Advanced(s) => {
                        s.encrypt_native_rsa(key, v.cipher()?, &v.input, 256, limits)
                    }
                }
                .map(|_| ()),
                "C_EncryptInit",
            ),
            "decrypt" => (
                match owner {
                    Owner::Session(s) => {
                        s.decrypt_native_rsa(key, v.cipher()?, &v.input, 256, limits, None)
                    }
                    Owner::Advanced(s) => {
                        s.decrypt_native_rsa(key, v.cipher()?, &v.input, 256, limits, None)
                    }
                }
                .map(|_| ()),
                "C_DecryptInit",
            ),
            _ => return Err(Failure::Input("rsa_usage_action")),
        };
        match result {
            Err(error @ Error::Native { function, code, .. })
                if function == expected_function
                    && code == fe11_sys::CKR_KEY_FUNCTION_NOT_PERMITTED as u64 =>
            {
                outcome::record(report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("report_write"))?;
                Ok(())
            }
            Err(error) => Err(error.into()),
            Ok(()) => Err(Failure::Oracle("disabled_rsa_usage_accepted")),
        }
    }
}
