// SPDX-License-Identifier: Apache-2.0
//! Exact concatenation and explicit length boundaries use readable public bytes.
use super::{
    derived_value,
    derived_value_case::DerivedValueCase,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, Producer, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

pub struct Case {
    advanced: bool,
    before: bool,
    data: [u8; 3],
    length: usize,
    value: [u8; 7],
}
impl DerivedValueCase for Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(65)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if bytes.len() > 64 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("fixture_encoding"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if fields.len() != 4
            || !matches!(fields[0], "session" | "advanced")
            || !matches!(fields[1], "before" | "after")
            || !matches!(fields[2], "ff00fe" | "ff00ff")
            || !matches!(fields[3], "0" | "1" | "6" | "7" | "8")
        {
            return Err(Failure::Input("concatenation_fields"));
        }
        let data = [0xff, 0, if fields[2] == "ff00fe" { 0xfe } else { 0xff }];
        let mut value = [0u8; 7];
        if fields[1] == "before" {
            value[..3].copy_from_slice(&data);
            value[3..].copy_from_slice(&[0, 1, 2, 3]);
        } else {
            value[..4].copy_from_slice(&[0, 1, 2, 3]);
            value[4..].copy_from_slice(&data);
        }
        Ok(Self {
            advanced: fields[0] == "advanced",
            before: fields[1] == "before",
            data,
            length: fields[3]
                .parse()
                .map_err(|_| Failure::Input("concatenation_length"))?,
            value,
        })
    }
    fn advanced(&self) -> bool {
        self.advanced
    }
    fn import(&self, owner: &Owner) -> Result<NativeObjectRef> {
        owner.import_secret_usages(
            &[0, 1, 2, 3],
            fe11_sys::CKK_GENERIC_SECRET,
            [
                (StandardAttribute::DERIVE, true),
                (StandardAttribute::EXTRACTABLE, true),
            ],
        )
    }
    fn parameters(&self) -> NativeKeyDerivation<'_> {
        NativeKeyDerivation::ConcatenateData {
            data: &self.data,
            placement: if self.before {
                DerivationDataPlacement::BeforeBase
            } else {
                DerivationDataPlacement::AfterBase
            },
        }
    }
    fn expected(&self) -> &[u8] {
        &self.value[..self.length.min(self.value.len())]
    }
    fn observation(&self) -> (&'static str, Producer) {
        ("concatenation_value_and_length", Producer::TestOracle)
    }
    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        retained: &mut Option<CreatedObjectSet>,
        report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        let result = derived_value::check_length(
            owner,
            key,
            self.parameters(),
            self.length,
            self.expected(),
            retained,
        );
        if self.length <= self.value.len() {
            return result;
        }
        // PKCS#11 requires an error when the requested key is longer than the
        // concatenated material. It does not prescribe one specific return code.
        // Retain any unexpectedly created object for the common cleanup path.
        match result {
            Err(
                error @ Failure::Product(Error::Native {
                    function: "C_DeriveKey",
                    ..
                }),
            ) => {
                outcome::record(report, Phase::Body, &error)
                    .map_err(|_| Failure::Input("report_write"))?;
                Ok(())
            }
            Err(error) => Err(error),
            Ok(()) => Err(Failure::Oracle("overlong_concatenation_accepted")),
        }
    }
}
