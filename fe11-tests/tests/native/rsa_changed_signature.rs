// SPDX-License-Identifier: Apache-2.0
//! Full-width RSA signatures with exactly their final bit changed.
use super::{
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, Report},
    rsa_known_fixture::Vector,
    single_key_case::SingleKeyCase,
};
use fe11::*;
use std::{io::Write, path::Path};

pub struct Changed(Vector);
impl SingleKeyCase for Changed {
    const ASSERTION: &'static str = "rsa_one_bit_signature_rejected";
    const PRODUCER: super::report::Producer = super::report::Producer::TestOracle;
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let vector = Vector::read(path)?;
        if vector.action != "verify" || vector.expected.len() != 256 {
            return Err(Failure::Input("rsa_changed_signature_fixture"));
        }
        Ok(Self(vector))
    }
    fn advanced(&self) -> bool {
        self.0.advanced
    }
    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        <Vector as SingleKeyCase>::import(&self.0, owner)
    }
    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        let vector = &self.0;
        let mut changed = vector.expected.clone();
        changed[255] ^= 1;
        let result = owner.verify_parameters(
            key,
            vector.signature()?,
            MessageRoute::Single,
            &[&vector.input],
            &changed,
            InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: vector.input.len(),
            },
        );
        match result {
            Err(
                error @ Error::Native {
                    function: "C_Verify",
                    code,
                    ..
                },
            ) if code == fe11_sys::CKR_SIGNATURE_INVALID as u64 => {
                outcome::record(report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("report_write"))?;
                Ok(())
            }
            Err(error) => Err(error.into()),
            Ok(()) => Err(Failure::Oracle("changed_rsa_signature_accepted")),
        }
    }
}
