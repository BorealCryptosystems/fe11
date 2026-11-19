// SPDX-License-Identifier: Apache-2.0
//! Finite-field shared secrets with explicit answer provenance and exact PKCS #3 inputs.
use super::{
    arguments::hex,
    derived_value_case::{DerivedValueCase, ExpectedOrigin},
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

pub struct Vector {
    advanced: bool,
    pub(super) prime: Vec<u8>,
    pub(super) base: Vec<u8>,
    private: Vec<u8>,
    pub(super) peer: Vec<u8>,
    expected: Vec<u8>,
    expected_origin: ExpectedOrigin,
    refusal: bool,
}

impl DerivedValueCase for Vector {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("dh_fixture_open"))?
            .take(8193)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("dh_fixture_read"))?;
        if bytes.len() > 8192 {
            return Err(Failure::Input("dh_fixture_size"));
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| Failure::Input("dh_fixture_encoding"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if !matches!(fields.len(), 6 | 7) || !matches!(fields[0], "session" | "advanced") {
            return Err(Failure::Input("dh_fixture_fields"));
        }
        // Six-field fixtures carry published answers. An independently calculated
        // answer requires an explicit marker; no unrecognized annotation is accepted.
        let expected_origin = match fields.get(6) {
            None => ExpectedOrigin::Published,
            Some(&"independently_calculated") => ExpectedOrigin::IndependentlyCalculated,
            _ => return Err(Failure::Input("dh_fixture_expected_origin")),
        };
        let number = |field| hex(field, 512).map_err(Failure::Input);
        let refusal = fields[5] == "native_general_error";
        if refusal && fields.len() != 6 {
            return Err(Failure::Input("dh_refusal_annotation"));
        }
        let value = Self {
            advanced: fields[0] == "advanced",
            prime: number(fields[1])?,
            base: number(fields[2])?,
            private: number(fields[3])?,
            peer: number(fields[4])?,
            expected: if refusal {
                Vec::new()
            } else {
                number(fields[5])?
            },
            refusal,
            expected_origin,
        };
        if value.prime.is_empty()
            || value.base.is_empty()
            || value.private.is_empty()
            || value.peer.is_empty()
            || !refusal && value.expected.len() != value.prime.len()
        {
            return Err(Failure::Input("dh_fixture_dimensions"));
        }
        Ok(value)
    }
    fn advanced(&self) -> bool {
        self.advanced
    }
    fn import(&self, owner: &Owner) -> Result<NativeObjectRef> {
        self.import_usage(owner, true)
    }
    fn parameters(&self) -> NativeKeyDerivation<'_> {
        NativeKeyDerivation::DhPkcs {
            peer_public: &self.peer,
        }
    }
    fn expected(&self) -> &[u8] {
        &self.expected
    }
    fn expected_origin(&self) -> ExpectedOrigin {
        self.expected_origin
    }
    fn observation(&self) -> (&'static str, Producer) {
        if self.refusal {
            ("invalid_dh_peer_native_refusal", Producer::Fe11Local)
        } else {
            self.expected_origin.observation()
        }
    }
    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        retained: &mut Option<CreatedObjectSet>,
        report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        if !self.refusal {
            return super::derived_value::check(
                owner,
                key,
                self.parameters(),
                &self.expected,
                retained,
            );
        }
        let attributes = super::derived_value::template_attributes(self.prime.len());
        let request = GenerationTemplate {
            attributes: &attributes,
            limits: AttributeTemplateLimits {
                maximum_depth: 0,
                maximum_attributes: attributes.len(),
                maximum_value_bytes: 28,
            },
            observation: None,
            destination: DestinationPlan {
                search: DestinationSearchPlan::NotRequested,
                user: DestinationUserObservation::NotRequested,
            },
        };
        let result = match owner {
            Owner::Session(s) => s.derive_native_key(key, self.parameters(), request),
            Owner::Advanced(s) => s.derive_native_key(key, self.parameters(), request),
        };
        match result {
            Err(
                error @ Error::Native {
                    function: "C_DeriveKey",
                    code,
                    may_have_effect: true,
                },
            ) if code == fe11_sys::CKR_GENERAL_ERROR as u64 => {
                outcome::record(report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("report_write"))?;
                Ok(())
            }
            Err(error) => Err(error.into()),
            Ok(created) => {
                // Preserve cleanup ownership even if the peer is unexpectedly
                // accepted; no synthetic expected shared secret is substituted.
                *retained = Some(created.objects);
                if let Err(error) = created.observation {
                    outcome::record(report, Phase::Body, &Failure::Product(error))
                        .map_err(|_| Failure::Input("report_write"))?;
                }
                Err(Failure::Oracle("invalid_dh_peer_accepted"))
            }
        }
    }
}

impl Vector {
    pub(super) fn import_usage(&self, owner: &Owner, allowed: bool) -> Result<NativeObjectRef> {
        let attr = |attribute: StandardAttribute, value| AttributeInput {
            attribute: attribute.into(),
            value,
        };
        let attributes = [
            attr(
                StandardAttribute::CLASS,
                AttributeInputValue::Unsigned(fe11_sys::CKO_PRIVATE_KEY as u64),
            ),
            attr(
                StandardAttribute::KEY_TYPE,
                AttributeInputValue::Unsigned(fe11_sys::CKK_DH as u64),
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
                StandardAttribute::DERIVE,
                AttributeInputValue::Boolean(allowed),
            ),
            attr(
                StandardAttribute::PRIME,
                AttributeInputValue::Bytes(&self.prime),
            ),
            attr(
                StandardAttribute::BASE,
                AttributeInputValue::Bytes(&self.base),
            ),
            attr(
                StandardAttribute::VALUE,
                AttributeInputValue::Bytes(&self.private),
            ),
        ];
        owner.create(
            &attributes,
            AttributeTemplateLimits {
                maximum_depth: 0,
                maximum_attributes: attributes.len(),
                // Each decoded integer is bounded to512 bytes; scalar attributes
                // need19 additional bytes on the tested64-bit ABI.
                maximum_value_bytes: 19 + self.prime.len() + self.base.len() + self.private.len(),
            },
        )
    }
}
