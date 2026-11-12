// SPDX-License-Identifier: Apache-2.0
//! Borrowed destination operands, distinct from post-operation observations.

use super::DestinationRecipe;
use crate::{
    destination_controls::DestinationIdentity, managed::ManagedIdentity, session::SessionAccess,
    AttributeInput, AttributeInputValue, AttributeValue, DestinationPlan, DestinationReport,
    IdentityAttribute, ManagedClass, Result, Session, StandardAttribute,
};

// A duplicate target operand has no single meaning for a destination query.
// Preserve the native template unchanged, but do not guess which value wins.
fn target_bytes<'a>(
    input: &'a [AttributeInput<'a>],
    attribute: StandardAttribute,
    previous: Option<&'a AttributeValue>,
) -> Option<&'a [u8]> {
    let mut matches = input.iter().filter(|value| value.attribute == attribute);
    match (matches.next(), matches.next()) {
        (None, _) => match previous {
            Some(AttributeValue::Available(bytes)) => Some(bytes),
            _ => None,
        },
        (Some(value), None) => match &value.value {
            AttributeInputValue::Bytes(bytes) => Some(bytes),
            _ => None,
        },
        _ => None,
    }
}

pub(super) struct InputIdentity<'a> {
    class: ManagedClass,
    fields: [(IdentityAttribute, Option<&'a [u8]>); 4],
}

impl<'a> InputIdentity<'a> {
    pub(super) fn new(
        class: ManagedClass,
        input: &'a [AttributeInput<'a>],
        previous: Option<&'a ManagedIdentity>,
    ) -> Self {
        use IdentityAttribute as Identity;
        use StandardAttribute as Attribute;
        Self {
            class,
            fields: [
                (
                    Identity::Id,
                    target_bytes(
                        input,
                        Attribute::ID,
                        previous.map(ManagedIdentity::id_observation),
                    ),
                ),
                (
                    Identity::Label,
                    target_bytes(
                        input,
                        Attribute::LABEL,
                        previous.map(ManagedIdentity::label_observation),
                    ),
                ),
                (
                    Identity::Application,
                    target_bytes(
                        input,
                        Attribute::APPLICATION,
                        previous.map(ManagedIdentity::application_observation),
                    ),
                ),
                (
                    Identity::ObjectId,
                    target_bytes(
                        input,
                        Attribute::OBJECT_ID,
                        previous.map(ManagedIdentity::object_type_observation),
                    ),
                ),
            ],
        }
    }

    pub(super) fn destination(&self, session: &Session) -> Result<DestinationRecipe<'a>> {
        let selected: &[IdentityAttribute] = if self.class == ManagedClass::Data {
            &[
                IdentityAttribute::Application,
                IdentityAttribute::ObjectId,
                IdentityAttribute::Label,
            ]
        } else {
            &[IdentityAttribute::Id]
        };
        let mut parts = [None, None, None];
        for (part, field) in parts.iter_mut().zip(selected) {
            *part = self
                .fields
                .iter()
                .find(|(kind, _)| kind == field)
                .and_then(|(_, bytes)| *bytes);
        }
        DestinationRecipe::with_parts(session, self.class, parts)
    }

    pub(super) fn identity(&self) -> DestinationIdentity<'_> {
        DestinationIdentity::Metadata {
            class: self.class,
            fields: &self.fields,
        }
    }
    pub(super) fn observe_local(
        &self,
        plan: DestinationPlan,
        state: &SessionAccess<'_>,
        session: &Session,
    ) -> Result<DestinationReport> {
        DestinationReport::observe_local(plan, state, session, self.identity())
    }
}
