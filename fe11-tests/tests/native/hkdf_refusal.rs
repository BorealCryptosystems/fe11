// SPDX-License-Identifier: Apache-2.0
//! Native HKDF refusal after a valid generic-secret import, with owned cleanup.
use super::super::{
    arguments::hex,
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

pub(super) fn selected(path: &Path) -> bool {
    let mut prefix = [0; 12];
    File::open(path)
        .and_then(|mut file| file.read_exact(&mut prefix))
        .is_ok()
        && &prefix == b"hkdf-refuse\n"
}

pub(super) struct Case {
    advanced: bool,
    explicit: bool,
    data: bool,
    base: Vec<u8>,
}

impl DerivedValueCase for Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("hkdf_fixture_open"))?
            .take(257)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("hkdf_fixture_read"))?;
        if bytes.len() > 256 {
            return Err(Failure::Input("hkdf_fixture_bound"));
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| Failure::Input("hkdf_fixture_encoding"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if fields.len() != 5
            || fields[0] != "hkdf-refuse"
            || !matches!(fields[1], "Session" | "AdvancedSession")
            || !matches!(fields[2], "convenience" | "parameters")
            || !matches!(fields[3], "key" | "data")
        {
            return Err(Failure::Input("hkdf_fixture_fields"));
        }
        let base = hex(fields[4], 32).map_err(Failure::Input)?;
        if base.len() != 32 {
            return Err(Failure::Input("hkdf_hash_width"));
        }
        Ok(Self {
            advanced: fields[1] == "AdvancedSession",
            explicit: fields[2] == "parameters",
            data: fields[3] == "data",
            base,
        })
    }
    fn advanced(&self) -> bool {
        self.advanced
    }
    fn import(&self, owner: &Owner) -> Result<NativeObjectRef> {
        owner.import_secret(
            &self.base,
            fe11_sys::CKK_GENERIC_SECRET,
            [StandardAttribute::DERIVE, StandardAttribute::SIGN],
        )
    }
    fn parameters(&self) -> NativeKeyDerivation<'_> {
        let output = if self.data {
            NativeHkdfOutput::Data
        } else {
            NativeHkdfOutput::Key
        };
        if self.explicit {
            NativeKeyDerivation::HkdfParameters(NativeHkdfParameters {
                extract: true,
                expand: true,
                hash: fe11_sys::CKM_SHA256 as u64,
                salt: NativeHkdfSalt::Null,
                info: None,
                output,
            })
        } else {
            NativeKeyDerivation::Hkdf {
                extract: true,
                expand: true,
                hash: fe11_sys::CKM_SHA256 as u64,
                salt: NativeHkdfSalt::Null,
                info: &[0xff, 0, 0xfe],
                output,
            }
        }
    }
    fn expected(&self) -> &[u8] {
        // The overridden check never invokes the value oracle; no HKDF output
        // is claimed when the native mechanism is absent.
        &[]
    }
    fn observation(&self) -> (&'static str, Producer) {
        ("hkdf_native_mechanism_refusal", Producer::TestOracle)
    }
    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        retained: &mut Option<CreatedObjectSet>,
        report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        let mut attributes = Vec::from(derived_value::template_attributes(32));
        if self.data {
            // HKDF_DATA contributes CKO_DATA. Keep the mechanism's VALUE_LEN,
            // but exclude attributes specific to secret-key objects.
            attributes.retain(|a| {
                a.attribute == StandardAttribute::CLASS
                    || a.attribute == StandardAttribute::TOKEN
                    || a.attribute == StandardAttribute::PRIVATE
                    || a.attribute == StandardAttribute::VALUE_LEN
            });
            attributes[0].value = AttributeInputValue::Unsigned(fe11_sys::CKO_DATA as u64);
        }
        let request = GenerationTemplate {
            attributes: &attributes,
            limits: AttributeTemplateLimits {
                maximum_depth: 0,
                maximum_attributes: attributes.len(),
                maximum_value_bytes: 32,
            },
            observation: None,
            destination: DestinationPlan {
                search: DestinationSearchPlan::NotRequested,
                user: DestinationUserObservation::NotRequested,
            },
        };
        let result = match owner {
            Owner::Session(session) => session.derive_native_key(key, self.parameters(), request),
            Owner::Advanced(session) => session.derive_native_key(key, self.parameters(), request),
        };
        match result {
            Err(
                error @ Error::Native {
                    function: "C_DeriveKey",
                    code,
                    ..
                },
            ) if code == fe11_sys::CKR_MECHANISM_INVALID as u64 => {
                outcome::record(report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("report_write"))?;
                Ok(())
            }
            Err(error) => Err(error.into()),
            Ok(created) => {
                *retained = Some(created.objects);
                Err(Failure::Oracle("unexpected_hkdf_creation"))
            }
        }
    }
}
