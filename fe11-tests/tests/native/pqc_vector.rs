// SPDX-License-Identifier: Apache-2.0
//! PQC case binding to the shared one-key lifecycle.
use super::{
    object_owner::Owner, outcome::Failure, pqc_fixture::Vector, report::Report,
    single_key_case::SingleKeyCase,
};
use fe11::*;
use std::{io::Write, path::Path};
impl SingleKeyCase for Vector {
    const ASSERTION: &'static str = "pqc_native_and_exact_output_verdict";
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        Vector::read(path)
    }
    fn advanced(&self) -> bool {
        self.advanced
    }
    fn bind_module(&mut self, module: &Module) -> std::result::Result<(), Failure> {
        if let Some(selector) = &self.absent {
            let mechanism = selector.number(self.parameters.family);
            for slot in module.slot_ids(true)? {
                if module.mechanism_ids(slot)?.contains(&mechanism) {
                    return Err(Failure::Oracle("pqc_hash_unexpectedly_advertised"));
                }
            }
        }
        Ok(())
    }
    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        super::pqc_operation::import(owner, self).map_err(Failure::from)
    }
    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        super::pqc_operation::check(owner, key, self, report)?;
        if let Some(selector) = &self.absent {
            super::pqc_absent::check(owner, key, self, selector)?;
        }
        Ok(())
    }
}
