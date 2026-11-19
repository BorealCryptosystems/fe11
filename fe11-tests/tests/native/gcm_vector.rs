// SPDX-License-Identifier: Apache-2.0
//! GCM case binding to the shared one-key lifecycle.
use super::{
    gcm_fixture::Vector,
    object_owner::Owner,
    outcome::Failure,
    report::{Producer, Report},
    single_key_case::SingleKeyCase,
};
use fe11::*;
use std::{io::Write, path::Path};
impl SingleKeyCase for Vector {
    const ASSERTION: &'static str = "gcm_native_and_exact_output_verdict";
    // The manifest distinguishes published KATs from independently calculated
    // reference values. This observation reports the comparison, not its origin.
    const PRODUCER: Producer = Producer::TestOracle;
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        Vector::read(path)
    }
    fn advanced(&self) -> bool {
        self.advanced
    }
    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        owner
            .import_secret(
                &self.key,
                fe11_sys::CKK_AES,
                [StandardAttribute::ENCRYPT, StandardAttribute::DECRYPT],
            )
            .map_err(Failure::from)
    }
    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        super::gcm_operation::check(owner, key, self, report)
    }
}
