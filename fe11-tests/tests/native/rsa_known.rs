// SPDX-License-Identifier: Apache-2.0
//! RSA KNOWN case binding to the shared one-key lifecycle.
use super::{
    object_owner::Owner, outcome::Failure, report::Report, rsa_known_fixture::Vector,
    single_key_case::SingleKeyCase,
};
use fe11::*;
use std::{io::Write, path::Path};
impl SingleKeyCase for Vector {
    const ASSERTION: &'static str = "rsa_known_native_and_exact_output_verdict";
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        Vector::read(path)
    }
    fn advanced(&self) -> bool {
        self.advanced
    }
    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        match self.action.as_str() {
            "sign" => owner.import_rsa_private(&self.key, StandardAttribute::SIGN),
            "decrypt" => owner.import_rsa_private(&self.key, StandardAttribute::DECRYPT),
            "verify" => {
                owner.import_rsa_public_usage(&self.key[0], &self.key[1], StandardAttribute::VERIFY)
            }
            "encrypt" => owner.import_rsa_public_usage(
                &self.key[0],
                &self.key[1],
                StandardAttribute::ENCRYPT,
            ),
            _ => return Err(Failure::Input("rsa_known_action")),
        }
        .map_err(Failure::from)
    }
    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        super::rsa_known_operation::check(owner, key, self, report)
    }
}
