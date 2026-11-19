// SPDX-License-Identifier: Apache-2.0
//! Single-coordinate ECDH parameter and output-template contracts.
use super::super::{
    arguments::hex,
    derived_value,
    derived_value_case::DerivedValueCase,
    ecdh_fixture,
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Observation, Phase, Producer, Report},
};
use fe11::*;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

pub(super) fn selected(path: &Path) -> bool {
    let mut prefix = [0; 14];
    File::open(path)
        .and_then(|mut f| f.read_exact(&mut prefix))
        .is_ok()
        && &prefix == b"ecdh-contract\n"
}
pub(super) struct Case {
    vector: ecdh_fixture::Vector,
    action: String,
    kdf: u64,
    shared: Option<Vec<u8>>,
    output_length: usize,
    mac: Vec<u8>,
    peer_override: Option<Vec<u8>>,
}

impl DerivedValueCase for Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("ecdh_contract_open"))?
            .take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("ecdh_contract_read"))?;
        if bytes.len() > 4096 {
            return Err(Failure::Input("ecdh_contract_bound"));
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| Failure::Input("ecdh_contract_encoding"))?;
        let f: Vec<_> = text.split_terminator('\n').collect();
        if !matches!(f.len(), 11 | 12)
            || f[0] != "ecdh-contract"
            || !matches!(f[1], "session" | "advanced")
            || !matches!(
                f[2],
                "kdf"
                    | "shared"
                    | "length"
                    | "invalid"
                    | "opaque"
                    | "peer-empty"
                    | "peer-zero"
                    | "peer-truncated"
                    | "peer-other-curve"
            )
        {
            return Err(Failure::Input("ecdh_contract_fields"));
        }
        let kdf = match f[3] {
            "x963" => EcdhKdf::X963Sha256.identifier(),
            "concat" => EcdhKdf::ConcatSha256.identifier(),
            value => {
                EcdhKdf::Native(value.parse().map_err(|_| Failure::Input("ecdh_kdf"))?).identifier()
            }
        };
        let shared = match f[4] {
            "absent" => None,
            "empty" => Some(Vec::new()),
            "binary" => Some(vec![0xff, 0, 0xff]),
            _ => return Err(Failure::Input("ecdh_shared_data")),
        };
        let output_length = f[5]
            .parse()
            .map_err(|_| Failure::Input("ecdh_output_length"))?;
        if output_length > 33 {
            return Err(Failure::Input("ecdh_output_bound"));
        }
        let decode = |i| hex(f[i], 128).map_err(Failure::Input);
        let vector = ecdh_fixture::Vector {
            advanced: f[1] == "advanced",
            parameters: decode(6)?,
            private: decode(7)?,
            peer: decode(8)?,
            expected: decode(9)?,
        };
        let mac = decode(10)?;
        if vector.parameters != [6, 8, 42, 134, 72, 206, 61, 3, 1, 7]
            || vector.private.len() != 32
            || vector.peer.len() != 65
            || vector.peer[0] != 4
            || vector.expected.len() != 32
            || mac.len() != 32
        {
            return Err(Failure::Input("ecdh_p256_dimensions"));
        }
        let peer_override = if f[2].starts_with("peer-") {
            if f.len() != 12
                || kdf != fe11_sys::CKD_NULL as u64
                || shared.is_some()
                || output_length != 32
            {
                return Err(Failure::Input("ecdh_peer_single_fault"));
            }
            let peer = decode(11)?;
            let valid_mutation = match f[2] {
                "peer-empty" => peer.is_empty(),
                "peer-zero" => {
                    peer.len() == 65 && peer[0] == 4 && peer[1..].iter().all(|byte| *byte == 0)
                }
                "peer-truncated" => peer == vector.peer[..64],
                "peer-other-curve" => peer.len() == 97 && peer[0] == 4,
                _ => false,
            };
            if !valid_mutation {
                return Err(Failure::Input("ecdh_peer_mutation_shape"));
            }
            Some(peer)
        } else {
            if f.len() != 11 {
                return Err(Failure::Input("ecdh_unexpected_peer_override"));
            }
            None
        };
        Ok(Self {
            vector,
            action: f[2].to_owned(),
            kdf,
            shared,
            output_length,
            mac,
            peer_override,
        })
    }
    fn advanced(&self) -> bool {
        self.vector.advanced
    }
    fn import(&self, owner: &Owner) -> Result<NativeObjectRef> {
        self.vector.import(owner)
    }
    fn parameters(&self) -> NativeKeyDerivation<'_> {
        NativeKeyDerivation::Ecdh {
            kdf: self.kdf,
            cofactor: false,
            peer_public: self.peer_override.as_deref().unwrap_or(&self.vector.peer),
            shared_data: self.shared.as_deref(),
        }
    }
    fn expected(&self) -> &[u8] {
        &self.vector.expected
    }
    fn observation(&self) -> (&'static str, Producer) {
        ("ecdh_parameter_contract", Producer::TestOracle)
    }
    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        retained: &mut Option<CreatedObjectSet>,
        report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        let mut attributes = Vec::from(derived_value::template_attributes(self.output_length));
        if self.action == "opaque" {
            for a in &mut attributes {
                if a.attribute == StandardAttribute::SENSITIVE {
                    a.value = AttributeInputValue::Boolean(true);
                }
                if a.attribute == StandardAttribute::EXTRACTABLE {
                    a.value = AttributeInputValue::Boolean(false);
                }
            }
            attributes.push(AttributeInput {
                attribute: StandardAttribute::SIGN.into(),
                value: AttributeInputValue::Boolean(true),
            });
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
            Owner::Session(s) => s.derive_native_key(key, self.parameters(), request),
            Owner::Advanced(s) => s.derive_native_key(key, self.parameters(), request),
        };
        let created = match result {
            Ok(created) => {
                *retained = Some(created.objects);
                Some(created.observation)
            }
            Err(error) => {
                report
                    .observation(
                        Phase::Body,
                        "derivation_object_returned",
                        Producer::Native,
                        Observation::Boolean(false),
                    )
                    .map_err(|_| Failure::Input("report_write"))?;
                let permitted = matches!(&error,Error::Native { function:"C_DeriveKey",code,may_have_effect }
                    if if self.action=="peer-empty" {
                        *code==fe11_sys::CKR_MECHANISM_PARAM_INVALID as u64
                    } else if self.peer_override.is_some() {
                        *code==fe11_sys::CKR_GENERAL_ERROR as u64 && *may_have_effect
                    } else if matches!(self.action.as_str(),"kdf"|"shared"|"invalid") {
                        *code==fe11_sys::CKR_MECHANISM_PARAM_INVALID as u64
                    } else if self.action=="length" {
                        [fe11_sys::CKR_ATTRIBUTE_VALUE_INVALID as u64,
                         fe11_sys::CKR_KEY_SIZE_RANGE as u64,
                         fe11_sys::CKR_TEMPLATE_INCONSISTENT as u64].contains(code)
                         || (self.output_length==33 && [fe11_sys::CKR_GENERAL_ERROR as u64,
                             fe11_sys::CKR_FUNCTION_FAILED as u64].contains(code))
                    } else { false });
                if !permitted {
                    return Err(error.into());
                }
                outcome::record(report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("report_write"))?;
                None
            }
        };
        let Some(observation) = created else {
            return Ok(());
        };
        report
            .observation(
                Phase::Body,
                "derivation_object_returned",
                Producer::Native,
                Observation::Boolean(true),
            )
            .map_err(|_| Failure::Input("report_write"))?;
        observation?;
        if matches!(self.action.as_str(), "kdf" | "shared" | "invalid")
            || self.output_length == 33
            || self.peer_override.is_some()
        {
            return Err(Failure::Oracle("unexpected_ecdh_parameter_acceptance"));
        }
        let objects = retained
            .as_ref()
            .ok_or(Failure::Input("ecdh_creation_owner"))?
            .as_slice();
        if objects.len() != 1 {
            return Err(Failure::Oracle("ecdh_creation_count"));
        }
        if self.action == "opaque" {
            return self.opaque(owner, &objects[0]);
        }
        let length = read(
            owner,
            &objects[0],
            StandardAttribute::VALUE_LEN,
            std::mem::size_of::<fe11_sys::CK_ULONG>(),
        )?;
        let value = read(owner, &objects[0], StandardAttribute::VALUE, 32)?;
        let native_length = length.unsigned()?;
        report
            .observation(
                Phase::Body,
                "derived_value_length",
                Producer::Native,
                Observation::Number(native_length),
            )
            .map_err(|_| Failure::Input("report_write"))?;
        if length.calls != (AttributeReadCalls::Direct { code: 0 })
            || value.calls != (AttributeReadCalls::Direct { code: 0 })
            || native_length != self.output_length as u64
        {
            return Err(Failure::Oracle("ecdh_exact_requested_length"));
        }
        let expected = &self.vector.expected[32 - self.output_length..];
        let FlatAttributeValue::Available(bytes) = value.value else {
            return Err(Failure::Oracle("ecdh_derived_value_unavailable"));
        };
        report
            .observation(
                Phase::Body,
                "derived_value_bytes",
                Producer::Native,
                Observation::Number(bytes.as_bytes().len() as u64),
            )
            .map_err(|_| Failure::Input("report_write"))?;
        if bytes.as_bytes() != expected {
            return Err(Failure::Oracle("ecdh_trailing_shared_secret_bytes"));
        }
        Ok(())
    }
}

fn read(
    owner: &Owner,
    key: &NativeObjectRef,
    attribute: StandardAttribute,
    capacity: usize,
) -> Result<FlatAttributeObservation> {
    let plan = FlatAttributeReadPlan::Buffer { capacity };
    match owner {
        Owner::Session(s) => s.read_flat_attribute(key, attribute, plan),
        Owner::Advanced(s) => s.read_flat_attribute(key, attribute, plan),
    }
}

impl Case {
    fn opaque(&self, owner: &Owner, key: &NativeObjectRef) -> std::result::Result<(), Failure> {
        for (attribute, expected) in [
            (StandardAttribute::SENSITIVE, true),
            (StandardAttribute::EXTRACTABLE, false),
        ] {
            let value = read(owner, key, attribute, 1)?;
            if value.calls != (AttributeReadCalls::Direct { code: 0 })
                || value.boolean()? != expected
            {
                return Err(Failure::Oracle("ecdh_opaque_protection"));
            }
        }
        // Demonstrate non-exportability, then use the opaque key. This read must
        // return no bytes; it is never a substitute for the independent MAC.
        let value = read(owner, key, StandardAttribute::VALUE, 32)?;
        if value.calls
            != (AttributeReadCalls::Direct {
                code: fe11_sys::CKR_ATTRIBUTE_SENSITIVE as u64,
            })
            || !matches!(
                value.value,
                FlatAttributeValue::Unavailable(AttributeUnavailableCause::Sensitive)
            )
        {
            return Err(Failure::Oracle("ecdh_opaque_value_exposed"));
        }
        let tag = owner.compute(
            key,
            NativeMacAlgorithm::SHA256_HMAC,
            MessageRoute::Single,
            &[b"abc"],
            InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: 3,
            },
            32,
        )?;
        if tag.as_bytes() != self.mac {
            return Err(Failure::Oracle("ecdh_opaque_mac_witness"));
        }
        Ok(())
    }
}
