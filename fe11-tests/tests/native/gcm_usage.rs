// SPDX-License-Identifier: Apache-2.0
//! Disable only the requested GCM usage in a complete published valid tuple.
use super::{
    gcm_fixture::Vector,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, Producer, Report},
    single_key_case::SingleKeyCase,
};
use fe11::*;
use std::{io::Write, path::Path};

pub struct Usage(Vector);
impl SingleKeyCase for Usage {
    const ASSERTION: &'static str = "gcm_disabled_usage_refused_at_native_init";
    const PRODUCER: Producer = Producer::TestOracle;
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let v = Vector::read(path)?;
        if v.advanced || !v.valid {
            return Err(Failure::Input("gcm_usage_valid_synchronous_fixture"));
        }
        Ok(Self(v))
    }
    fn advanced(&self) -> bool {
        false
    }
    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        Ok(owner.import_secret_usages(
            &self.0.key,
            fe11_sys::CKK_AES,
            [
                (StandardAttribute::ENCRYPT, !self.0.encrypt),
                (StandardAttribute::DECRYPT, self.0.encrypt),
            ],
        )?)
    }
    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        let Owner::Session(s) = owner else {
            return Err(Failure::Input("gcm_usage_owner"));
        };
        let v = &self.0;
        let input = [v.input.as_slice()];
        let plaintext = if v.encrypt {
            v.input.len()
        } else {
            v.input
                .len()
                .checked_sub((v.tag_bits / 8) as usize)
                .ok_or(Failure::Input("gcm_usage_tag"))?
        };
        let limits = InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: plaintext
                .checked_add(v.aad.len())
                .ok_or(Failure::Input("gcm_usage_budget"))?,
        };
        let (result, function) = if v.encrypt {
            (
                s.encrypt_classic_aead(key, v.parameters(), MessageRoute::Single, &input, limits)
                    .map(|_| ()),
                "C_EncryptInit",
            )
        } else {
            (
                s.decrypt_classic_aead(key, v.parameters(), MessageRoute::Single, &input, limits)
                    .map(|_| ()),
                "C_DecryptInit",
            )
        };
        match result {
            Err(error @ Error::Native { .. }) if matches!(&error,Error::Native{function:actual,code,..}if *actual==function&&*code==fe11_sys::CKR_KEY_FUNCTION_NOT_PERMITTED as u64) => {
                outcome::record(report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("report_write"))
            }
            Err(error) => Err(error.into()),
            Ok(()) => Err(Failure::Oracle("gcm_disabled_usage_accepted")),
        }
    }
}
