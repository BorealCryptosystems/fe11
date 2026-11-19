// SPDX-License-Identifier: Apache-2.0
//! Characterize native ML-KEM key import without claiming FIPS key validation.
//! An accepted object is retained before observations and explicitly destroyed.
use super::{
    arguments::hex,
    configuration::{select_token, Configuration},
    credentials::Credentials,
    outcome::{self, Failure},
    report::{Observation, Phase, PhaseResult, Producer, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

struct Case {
    set: u64,
    private: bool,
    value: Vec<u8>,
}
impl Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut data = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("fixture_open"))?
            .take(8193)
            .read_to_end(&mut data)
            .map_err(|_| Failure::Input("fixture_read"))?;
        if data.len() > 8192 {
            return Err(Failure::Input("fixture_size"));
        }
        let text = std::str::from_utf8(&data).map_err(|_| Failure::Input("fixture_encoding"))?;
        let f: Vec<_> = text.split_terminator('\n').collect();
        if f.len() != 3 || !matches!(f[1], "ek" | "dk") {
            return Err(Failure::Input("kem_import_fields"));
        }
        let (set, public_bytes, private_bytes) = match f[0] {
            "ML-KEM-512" => (fe11_sys::CKP_ML_KEM_512, 800, 1632),
            "ML-KEM-768" => (fe11_sys::CKP_ML_KEM_768, 1184, 2400),
            "ML-KEM-1024" => (fe11_sys::CKP_ML_KEM_1024, 1568, 3168),
            _ => return Err(Failure::Input("kem_import_parameter_set")),
        };
        let private = f[1] == "dk";
        let value = hex(f[2], 3168).map_err(Failure::Input)?;
        if value.len() != if private { private_bytes } else { public_bytes } {
            return Err(Failure::Input("kem_import_width"));
        }
        Ok(Self {
            set: set as u64,
            private,
            value,
        })
    }
    fn class(&self) -> u64 {
        if self.private {
            fe11_sys::CKO_PRIVATE_KEY as u64
        } else {
            fe11_sys::CKO_PUBLIC_KEY as u64
        }
    }
    fn import(&self, session: &Session) -> Result<NativeObjectRef> {
        let attr = |attribute: StandardAttribute, value| AttributeInput {
            attribute: attribute.into(),
            value,
        };
        // These bytes are published ACVP test material, never operational keys.
        // Preserve the specified visibility and usage; import success does not
        // establish that the module performs FIPS203 encapsulation-key checks.
        let attributes = [
            attr(
                StandardAttribute::CLASS,
                AttributeInputValue::Unsigned(self.class()),
            ),
            attr(
                StandardAttribute::KEY_TYPE,
                AttributeInputValue::Unsigned(fe11_sys::CKK_ML_KEM as u64),
            ),
            attr(
                StandardAttribute::PARAMETER_SET,
                AttributeInputValue::Unsigned(self.set),
            ),
            attr(
                StandardAttribute::TOKEN,
                AttributeInputValue::Boolean(false),
            ),
            attr(
                StandardAttribute::PRIVATE,
                AttributeInputValue::Boolean(self.private),
            ),
            attr(
                if self.private {
                    StandardAttribute::DECAPSULATE
                } else {
                    StandardAttribute::ENCAPSULATE
                },
                AttributeInputValue::Boolean(true),
            ),
            attr(
                StandardAttribute::VALUE,
                AttributeInputValue::Bytes(&self.value),
            ),
        ];
        session.create_native_object(
            &attributes,
            AttributeTemplateLimits {
                maximum_depth: 0,
                maximum_attributes: attributes.len(),
                maximum_value_bytes: self.value.len() + 27,
            },
        )
    }
    fn observe(
        &self,
        session: &Session,
        key: &NativeObjectRef,
    ) -> std::result::Result<(), Failure> {
        for (attribute, expected) in [
            (StandardAttribute::CLASS, self.class()),
            (StandardAttribute::KEY_TYPE, fe11_sys::CKK_ML_KEM as u64),
            (StandardAttribute::PARAMETER_SET, self.set),
        ] {
            let value = session.read_flat_attribute(
                key,
                attribute,
                FlatAttributeReadPlan::Buffer {
                    capacity: std::mem::size_of::<fe11_sys::CK_ULONG>(),
                },
            )?;
            let actual = value.unsigned()?;
            if value.calls != (AttributeReadCalls::Direct { code: 0 }) || actual != expected {
                return Err(Failure::Oracle("kem_import_object_identity"));
            }
        }
        Ok(())
    }
}

fn characterize<W: Write>(
    session: &Session,
    case: &Case,
    key: &mut Option<NativeObjectRef>,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    let accepted = match case.import(session) {
        Ok(created) => {
            *key = Some(created);
            true
        }
        Err(
            error @ Error::Native {
                function: "C_CreateObject",
                code,
                ..
            },
        ) if matches!(code,
            x if x==fe11_sys::CKR_ATTRIBUTE_VALUE_INVALID as u64 || x==fe11_sys::CKR_TEMPLATE_INCONSISTENT as u64
                || x==fe11_sys::CKR_FUNCTION_FAILED as u64 || x==fe11_sys::CKR_GENERAL_ERROR as u64) =>
        {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))?;
            false
        }
        Err(error) => return Err(error.into()),
    };
    report
        .observation(
            Phase::Body,
            "kem_import_accepted",
            Producer::Native,
            Observation::Boolean(accepted),
        )
        .map_err(|_| Failure::Input("report_write"))?;
    if let Some(key) = key.as_ref() {
        case.observe(session, key)?;
    }
    Ok(())
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut session = None;
    let mut key = None;
    let mut logged = false;
    let setup = (|| -> std::result::Result<Case, Failure> {
        let case = Case::read(path)?;
        let token =
            select_token(&module, &config.label).ok_or(Failure::Input("token_not_unique"))?;
        session = Some(module.select(&token)?.open_session(true)?);
        session
            .as_ref()
            .ok_or(Failure::Input("kem_import_session"))?
            .login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        logged = true;
        Ok(case)
    })();
    let started = setup.is_ok();
    let (setup_result, body) = match setup {
        Err(error) => (Err(error), Ok(())),
        Ok(case) => (
            Ok(()),
            match session.as_ref() {
                Some(session) => characterize(session, &case, &mut key, &mut report),
                None => Err(Failure::Input("kem_import_session")),
            },
        ),
    };
    let mut cleanup = Vec::new();
    if let Some(session) = session.as_ref() {
        if let Some(key) = key.as_ref() {
            if let Err(error) = session.destroy_native_object(key) {
                cleanup.push(error.into());
            }
        }
        if logged {
            if let Err(error) = session.logout() {
                cleanup.push(error.into());
            }
        }
        if let Err(error) = session.close() {
            cleanup.push(error.into());
        }
    }
    drop(key);
    drop(session);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    if let Err(error) = &setup_result {
        outcome::record(&mut report, Phase::Setup, error)?;
    }
    if let Err(error) = &body {
        outcome::record(&mut report, Phase::Body, error)?;
    }
    for error in &cleanup {
        outcome::record(&mut report, Phase::Cleanup, error)?;
    }
    report.finish(
        if setup_result.is_ok() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if !started {
            PhaseResult::NotExecuted
        } else if body.is_ok() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
        if cleanup.is_empty() {
            PhaseResult::Passed
        } else {
            PhaseResult::Failed
        },
    )
}
