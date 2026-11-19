// SPDX-License-Identifier: Apache-2.0
//! Edwards known answers through the exact native PKCS#11 signature parameters.
use super::{
    edwards_fixture::Vector,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, Report},
    single_key_case::SingleKeyCase,
};
use fe11::*;
use std::{io::Write, path::Path};

fn rejected<W: Write>(
    result: Result<()>,
    length_error: bool,
    report: &mut Report<W>,
) -> std::result::Result<(), Failure> {
    match result {
        Err(
            error @ Error::Native {
                function: "C_Verify",
                code,
                ..
            },
        ) if code == fe11_sys::CKR_SIGNATURE_INVALID as u64
            || (length_error && code == fe11_sys::CKR_SIGNATURE_LEN_RANGE as u64) =>
        {
            outcome::record(report, Phase::Body, &Failure::Product(error))
                .map_err(|_| Failure::Input("report_write"))?;
            Ok(())
        }
        Err(error) => Err(error.into()),
        Ok(()) => Err(Failure::Oracle("invalid_edwards_signature_accepted")),
    }
}

impl SingleKeyCase for Vector {
    const ASSERTION: &'static str = "edwards_known_answer_and_context";
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        Vector::read(path)
    }
    fn advanced(&self) -> bool {
        self.advanced
    }
    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        let attr = |attribute: StandardAttribute, value| AttributeInput {
            attribute: attribute.into(),
            value,
        };
        let template = [
            attr(
                StandardAttribute::CLASS,
                AttributeInputValue::Unsigned(if self.sign {
                    fe11_sys::CKO_PRIVATE_KEY
                } else {
                    fe11_sys::CKO_PUBLIC_KEY
                } as u64),
            ),
            attr(
                StandardAttribute::KEY_TYPE,
                AttributeInputValue::Unsigned(fe11_sys::CKK_EC_EDWARDS as u64),
            ),
            attr(
                StandardAttribute::TOKEN,
                AttributeInputValue::Boolean(false),
            ),
            attr(
                StandardAttribute::PRIVATE,
                AttributeInputValue::Boolean(false),
            ),
            attr(
                if self.sign {
                    StandardAttribute::SIGN
                } else {
                    StandardAttribute::VERIFY
                },
                AttributeInputValue::Boolean(true),
            ),
            attr(
                StandardAttribute::EC_PARAMS,
                AttributeInputValue::Bytes(&self.parameters),
            ),
            // PKCS#11 Edwards points/seeds are raw RFC8032 bytes, not EC-point DER.
            attr(
                if self.sign {
                    StandardAttribute::VALUE
                } else {
                    StandardAttribute::EC_POINT
                },
                AttributeInputValue::Bytes(if self.sign {
                    &self.private
                } else {
                    &self.public
                }),
            ),
        ];
        owner
            .create(
                &template,
                AttributeTemplateLimits {
                    maximum_depth: 0,
                    maximum_attributes: template.len(),
                    maximum_value_bytes: 19 + self.parameters.len() + self.width,
                },
            )
            .map_err(Failure::from)
    }
    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        let limits = InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: self.message.len(),
        };
        let parts = [self.message.as_slice()];
        // Empty contexts exercise both a present empty slice and NULL/0. A
        // nonempty context is never dropped or replaced to obtain a success.
        let context_forms = &[true, false][..if self.context.is_empty() { 2 } else { 1 }];
        for &present in context_forms {
            if self.sign {
                let result = match owner {
                    Owner::Session(s) => s.sign_native(
                        key,
                        self.mechanism(present),
                        MessageRoute::Single,
                        &parts,
                        limits,
                        self.signature_width,
                        None,
                    ),
                    Owner::Advanced(s) => s.sign_native(
                        key,
                        self.mechanism(present),
                        MessageRoute::Single,
                        &parts,
                        limits,
                        self.signature_width,
                        None,
                    ),
                }?;
                if result.as_bytes() != self.signature {
                    return Err(Failure::Oracle("edwards_known_signature"));
                }
            } else {
                let result = owner.verify_parameters(
                    key,
                    self.mechanism(present),
                    MessageRoute::Single,
                    &parts,
                    &self.signature,
                    limits,
                );
                if self.valid {
                    result?;
                    let mut altered = self.signature.clone();
                    *altered
                        .last_mut()
                        .ok_or(Failure::Input("edwards_signature_empty"))? ^= 1;
                    rejected(
                        owner.verify_parameters(
                            key,
                            self.mechanism(present),
                            MessageRoute::Single,
                            &parts,
                            &altered,
                            limits,
                        ),
                        false,
                        report,
                    )?;
                } else {
                    rejected(result, self.signature.len() != self.signature_width, report)?;
                }
            }
        }
        Ok(())
    }
}
