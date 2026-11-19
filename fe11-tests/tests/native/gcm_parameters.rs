// SPDX-License-Identifier: Apache-2.0
//! Every classic GCM tag-bit value, compared with the public empty-message KAT.
use super::{
    arguments::hex,
    object_owner::Owner,
    outcome::Failure,
    report::{Observation, Phase, Producer, Report},
    single_key_case::SingleKeyCase,
};
use fe11::*;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

pub struct Case {
    bits: u64,
    empty_iv: bool,
}

impl SingleKeyCase for Case {
    const ASSERTION: &'static str = "gcm_tag_parameter_and_exact_output";
    const PRODUCER: Producer = Producer::TestOracle;

    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut text = String::new();
        File::open(path)
            .map_err(|_| Failure::Input("gcm_parameter_open"))?
            .take(10)
            .read_to_string(&mut text)
            .map_err(|_| Failure::Input("gcm_parameter_read"))?;
        if text == "iv-empty\n" {
            return Ok(Self {
                bits: 128,
                empty_iv: true,
            });
        }
        let value = text
            .strip_suffix('\n')
            .ok_or(Failure::Input("gcm_parameter_line"))?;
        if value.is_empty() || value.len() > 3 || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Failure::Input("gcm_parameter_number"));
        }
        let bits = value
            .parse()
            .map_err(|_| Failure::Input("gcm_parameter_number"))?;
        if bits > 129 {
            return Err(Failure::Input("gcm_parameter_partition"));
        }
        Ok(Self {
            bits,
            empty_iv: false,
        })
    }
    fn advanced(&self) -> bool {
        false
    }
    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        Ok(owner.import_secret(
            &[0; 16],
            fe11_sys::CKK_AES,
            [StandardAttribute::ENCRYPT, StandardAttribute::DECRYPT],
        )?)
    }
    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        let Owner::Session(session) = owner else {
            return Err(Failure::Input("gcm_parameter_session"));
        };
        let result = session.encrypt_classic_aead(
            key,
            ClassicAeadParameters::Gcm {
                iv: if self.empty_iv { &[] } else { &[0; 12] },
                aad: &[],
                tag_bits: self.bits,
            },
            MessageRoute::Single,
            &[&[]],
            InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: 0,
            },
        );
        if self.bits == 129 || self.empty_iv {
            let expected = if self.empty_iv {
                SymmetricParametersRejection::GcmNormativeParameterBounds
            } else {
                SymmetricParametersRejection::ClassicAeadTagLength
            };
            return match result {
                Err(Error::Rejected(RejectionReason::SymmetricParameters(actual)))
                    if actual == expected =>
                {
                    Ok(())
                }
                Err(error) => Err(error.into()),
                Ok(_) => Err(Failure::Oracle("gcm_excess_tag_bits_accepted")),
            };
        }
        // Unsupported bit granularity in a module remains an execution failure,
        // even when its rejection is predicted by the module source. A positive
        // normative oracle is never replaced with that predicted error code.
        let value = result?;
        let tag = hex("58e2fccefa7e3061367f1d57a4e7455a", 16).map_err(Failure::Input)?;
        let length =
            usize::try_from(self.bits.div_ceil(8)).map_err(|_| Failure::Input("gcm_tag_length"))?;
        if value.as_bytes().len() != length {
            return Err(Failure::Oracle("gcm_tag_byte_count"));
        }
        let bytes = value.as_bytes();
        for (index, actual) in bytes.iter().enumerate() {
            let remainder = self.bits % 8;
            let mask = if index + 1 == length && remainder != 0 {
                0xffu8 << (8 - remainder)
            } else {
                0xff
            };
            if actual & mask != tag[index] & mask {
                return Err(Failure::Oracle("gcm_tag_prefix_bits"));
            }
        }
        report
            .observation(
                Phase::Body,
                "gcm_tag_bits_checked",
                Producer::TestOracle,
                Observation::Number(self.bits),
            )
            .map_err(|_| Failure::Input("report_write"))?;
        Ok(())
    }
}
