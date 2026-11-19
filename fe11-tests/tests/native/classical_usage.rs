// SPDX-License-Identifier: Apache-2.0
//! Native usage refusals retain the exact published DSA or ECDSA key and input.
use super::{
    classical_sign_fixture::Vector,
    classical_sign_operation,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, Report},
    single_key_case::SingleKeyCase,
};
use fe11::*;
use std::{io::Write, path::Path};

pub struct Usage<const SIGN: bool>(Vector);
impl<const SIGN: bool> SingleKeyCase for Usage<SIGN> {
    const ASSERTION: &'static str = "classical_disabled_usage_refused_at_native_init";
    const PRODUCER: super::report::Producer = super::report::Producer::TestOracle;

    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        Ok(Self(Vector::read(path)?))
    }
    fn advanced(&self) -> bool {
        self.0.advanced
    }
    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        Ok(classical_sign_operation::import_usage(
            owner, &self.0, SIGN, false,
        )?)
    }
    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        let vector = &self.0;
        let parts = [vector.input.as_slice()];
        let limits = InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: vector.input.len(),
        };
        let parameters = NativeSignatureParameters::Parameterless(vector.algorithm);
        let result = if SIGN {
            match owner {
                Owner::Session(session) => session.sign_native(
                    key,
                    parameters,
                    MessageRoute::Single,
                    &parts,
                    limits,
                    2 * vector.width,
                    None,
                ),
                Owner::Advanced(session) => session.sign_native(
                    key,
                    parameters,
                    MessageRoute::Single,
                    &parts,
                    limits,
                    2 * vector.width,
                    None,
                ),
            }
            .map(|_| ())
        } else {
            owner.verify_parameters(
                key,
                parameters,
                MessageRoute::Single,
                &parts,
                &vector.signature,
                limits,
            )
        };
        match result {
            Err(error @ Error::Native { function, code, .. })
                if function == if SIGN { "C_SignInit" } else { "C_VerifyInit" }
                    && code == fe11_sys::CKR_KEY_FUNCTION_NOT_PERMITTED as u64 =>
            {
                outcome::record(report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("report_write"))?;
                Ok(())
            }
            Err(error) => Err(error.into()),
            Ok(()) => Err(Failure::Oracle("disabled_classical_usage_accepted")),
        }
    }
}
