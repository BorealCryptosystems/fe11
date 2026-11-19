// SPDX-License-Identifier: Apache-2.0
//! CLASSICAL SIGN case binding to the shared one-key lifecycle.
use super::{
    classical_sign_fixture::Vector, object_owner::Owner, outcome::Failure, report::Report,
    single_key_case::SingleKeyCase,
};
use fe11::*;
use std::{io::Write, path::Path};
impl SingleKeyCase for Vector {
    const ASSERTION: &'static str = "classical_sign_native_and_exact_output_verdict";
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        Vector::read(path)
    }
    fn advanced(&self) -> bool {
        self.advanced
    }
    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        super::classical_sign_operation::import(owner, self).map_err(Failure::from)
    }
    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        _report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        super::classical_sign_operation::check(owner, key, self)
    }
}
