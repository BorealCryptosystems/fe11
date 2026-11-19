// SPDX-License-Identifier: Apache-2.0
//! Verify the complete control, then alter exactly the signature's final bit.
use super::{
    classical_sign_fixture::Vector,
    classical_sign_operation,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, Producer, Report},
    single_key_case::SingleKeyCase,
};
use fe11::*;
use std::{io::Write, path::Path};

pub struct Changed(Vector);
impl SingleKeyCase for Changed {
    const ASSERTION: &'static str = "classical_single_bit_signature_refusal";
    const PRODUCER: Producer = Producer::TestOracle;
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        Ok(Self(Vector::read(path)?))
    }
    fn advanced(&self) -> bool {
        self.0.advanced
    }
    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        Ok(classical_sign_operation::import_usage(
            owner, &self.0, false, true,
        )?)
    }
    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        let v = &self.0;
        let input = [v.input.as_slice()];
        let limits = InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: v.input.len(),
        };
        // This control is part of the negative case, with the same imported key,
        // hash, message and signature. No unrelated positive case is replayed.
        owner.verify_parameters(
            key,
            NativeSignatureParameters::Parameterless(v.algorithm),
            MessageRoute::Single,
            &input,
            &v.signature,
            limits,
        )?;
        let mut changed = v.signature.clone();
        *changed
            .last_mut()
            .ok_or(Failure::Input("classical_signature_empty"))? ^= 1;
        match owner.verify_parameters(
            key,
            NativeSignatureParameters::Parameterless(v.algorithm),
            MessageRoute::Single,
            &input,
            &changed,
            limits,
        ) {
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
            Ok(()) => Err(Failure::Oracle("changed_classical_signature_accepted")),
        }
    }
}
