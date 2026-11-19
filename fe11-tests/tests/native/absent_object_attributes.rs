// SPDX-License-Identifier: Apache-2.0
//! Individual attribute probes on an explicitly constructed session object.
use crate::{
    object_owner::Owner, outcome::Failure,
    report::{Observation, Phase, Producer, Report}, single_key_case::SingleKeyCase,
};
use fe11::*;
use std::{fs::File, io::{Read, Write}, path::Path};

use super::attribute_probe_object::Object;

pub(super) struct Case {
    object: Object,
    attributes: Vec<StandardAttribute>,
}

impl SingleKeyCase for Case {
    const ASSERTION: &'static str = "each_absent_attribute_has_its_native_cause";
    const PRODUCER: Producer = Producer::TestOracle;

    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut text = String::new();
        File::open(path).and_then(|f| f.take(16385).read_to_string(&mut text))
            .map_err(|_| Failure::Input("attribute_fixture_read"))?;
        if text.len() > 16384 { return Err(Failure::Input("attribute_fixture_size")); }
        let mut lines = text.lines();
        let object = Object::read(&mut lines)?;
        let mut attributes = Vec::new();
        for name in lines {
            let attribute = StandardAttribute::ALL.iter().copied().find(|a| a.name() == name)
                .ok_or(Failure::Input("unknown_attribute_name"))?;
            if attributes.len() >= 200 || attributes.contains(&attribute) {
                return Err(Failure::Input("invalid_flat_attribute_list"));
            }
            attributes.push(attribute);
        }
        if attributes.is_empty() { return Err(Failure::Input("empty_attribute_list")); }
        Ok(Self { object, attributes })
    }

    fn advanced(&self) -> bool { false }

    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        self.object.import(owner)
    }

    fn check<W: Write>(&self, owner: &Owner, key: &NativeObjectRef, report: &mut Report<W>)
        -> std::result::Result<(), Failure> {
        let Owner::Session(session) = owner else { return Err(Failure::Input("session_required")); };
        let mut every_absent = true;
        for attribute in &self.attributes {
            // One native request per field makes the return code unambiguous.
            let invalid = fe11_sys::CKR_ATTRIBUTE_TYPE_INVALID as u64;
            let absent = if attribute.layout() == AttributeLayout::Template {
                let observed = session.read_template_attribute(
                    key, *attribute, TemplateAttributeReadPlan::LengthOnly,
                    AttributeTemplateLimits {
                        maximum_depth: 0,
                        maximum_attributes: 1,
                        maximum_value_bytes: 0,
                    },
                )?;
                observed.call().code == invalid && observed.call().attribute_count == 1
                    && observed.root().attribute_identifier() == attribute.identifier()
                    && matches!(observed.root().value(),
                        TemplateAttributeValue::Unavailable(AttributeUnavailableCause::Unsupported))
            } else {
                let field = session.read_flat_attribute(key, *attribute, FlatAttributeReadPlan::LengthOnly)?;
                field.calls == (AttributeReadCalls::Size { code: invalid })
                    && matches!(field.value, FlatAttributeValue::Unavailable(AttributeUnavailableCause::Unsupported))
            };
            report.observation(Phase::Body, attribute.name(), Producer::TestOracle, Observation::Boolean(absent))
                .map_err(|_| Failure::Input("attribute_observation_write"))?;
            every_absent &= absent;
        }
        if every_absent { Ok(()) } else { Err(Failure::Oracle("attribute_absence_mismatch")) }
    }
}
