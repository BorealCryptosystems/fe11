// SPDX-License-Identifier: Apache-2.0
//! OAEP usage negatives retain an otherwise verified key and parameter tuple.
use super::{
    oaep_fixture::Vector,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, Report},
    single_key_case::SingleKeyCase,
};
use fe11::*;
use std::{io::Write, path::Path};

pub struct Usage<const ENCRYPT: bool>(Vector);
impl<const ENCRYPT: bool> SingleKeyCase for Usage<ENCRYPT> {
    const ASSERTION: &'static str = "oaep_disabled_usage_refused_at_native_init";
    const PRODUCER: super::report::Producer = super::report::Producer::TestOracle;
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let vector = Vector::read(path)?;
        if !vector.valid {
            return Err(Failure::Input("oaep_usage_requires_valid_tuple"));
        }
        Ok(Self(vector))
    }
    fn advanced(&self) -> bool {
        self.0.advanced
    }
    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        Ok(if ENCRYPT {
            owner.import_rsa_public_usage_enabled(
                &self.0.key[0],
                &self.0.key[1],
                StandardAttribute::ENCRYPT,
                false,
            )?
        } else {
            owner.import_rsa_private_usage(&self.0.key, StandardAttribute::DECRYPT, false)?
        })
    }
    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        let v = &self.0;
        let result = if ENCRYPT {
            let limits = InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: v.plaintext.len(),
            };
            match owner {
                Owner::Session(s) => {
                    s.encrypt_native_rsa(key, v.parameters(), &v.plaintext, v.key[0].len(), limits)
                }
                Owner::Advanced(s) => {
                    s.encrypt_native_rsa(key, v.parameters(), &v.plaintext, v.key[0].len(), limits)
                }
            }
        } else {
            v.decrypt(owner, key)
        };
        let expected = if ENCRYPT {
            "C_EncryptInit"
        } else {
            "C_DecryptInit"
        };
        match result {
            Err(error @ Error::Native { function, code, .. })
                if function == expected
                    && code == fe11_sys::CKR_KEY_FUNCTION_NOT_PERMITTED as u64 =>
            {
                outcome::record(report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("report_write"))?;
                Ok(())
            }
            Err(error) => Err(error.into()),
            Ok(_) => Err(Failure::Oracle("oaep_disabled_usage_accepted")),
        }
    }
}
