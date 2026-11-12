// SPDX-License-Identifier: Apache-2.0
//! Explicit metadata and search observations on a live administrative reference.
use crate::{
    Attribute, AttributeReadPlan, AttributeUnavailableCause, AttributeValue, Error, ManagedClass,
    ManagedObjectRef, Observation, Result, SearchPlan, Session,
};
use std::collections::BTreeSet;
use std::sync::Arc;
mod evaluation;

pub(crate) mod resident;

/// Public metadata retained for caller interpretation alongside a current read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IdentityAttribute {
    /// CKA_CLASS.
    Class,
    /// CKA_KEY_TYPE, when admitted as a key.
    KeyType,
    /// CKA_ID, when part of the admitted metadata.
    Id,
    /// CKA_LABEL.
    Label,
    /// Exact CKA_UNIQUE_ID evidence, including unavailable causes.
    UniqueId,
    /// CKA_APPLICATION for data objects.
    Application,
    /// CKA_OBJECT_ID data type, not native object identity.
    ObjectId,
}
impl IdentityAttribute {
    pub(crate) fn attribute(self) -> Attribute {
        match self {
            Self::Class => Attribute::Class,
            Self::KeyType => Attribute::KeyType,
            Self::Id => Attribute::Id,
            Self::Label => Attribute::Label,
            Self::UniqueId => Attribute::UniqueId,
            Self::Application => Attribute::Application,
            Self::ObjectId => Attribute::ObjectType,
        }
    }
}

/// Explicit template recipe. Selector is a convenience, not an identity proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReferenceTemplate {
    /// Class and ID for keys/certificates; class/application/type/label for data.
    Selector,
    /// Exactly the chosen reference or supplied-destination fields, including an empty template.
    Fields(Arc<BTreeSet<IdentityAttribute>>),
}
impl ReferenceTemplate {
    pub(crate) fn contains(&self, field: IdentityAttribute, class: ManagedClass) -> bool {
        match self {
            Self::Fields(fields) => fields.contains(&field),
            Self::Selector => {
                field == IdentityAttribute::Class
                    || if class == ManagedClass::Data {
                        matches!(
                            field,
                            IdentityAttribute::Application
                                | IdentityAttribute::ObjectId
                                | IdentityAttribute::Label
                        )
                    } else {
                        field == IdentityAttribute::Id
                    }
            }
        }
    }
}

/// Search only the current session's visible objects. No implicit query or policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReferenceSearchPlan {
    /// Do not enumerate objects and make no cardinality/presence claim.
    NotRequested,
    /// Build the template from exactly these retained public metadata fields.
    /// A missing template operand produces unavailable evidence, not a broader query.
    Observe {
        /// Exactly selected bound fields or explicit selector recipe.
        template: ReferenceTemplate,
        /// Per-call result ceiling and batch size.
        resources: SearchPlan,
    },
}

/// Explicit observations for one reference, without inherited application policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectReferencePlan {
    /// Optional query selection and its resource budget.
    pub search: Arc<ReferenceSearchPlan>,
    /// Exactly these metadata fields are read; no implicit comparison adds reads.
    pub attributes: Arc<BTreeSet<IdentityAttribute>>,
    /// Aggregate metadata reading budget and clarification strategy.
    pub read: AttributeReadPlan,
}

/// Public evidence for this call only. No content bytes, hashes or raw handles.
pub struct ObjectReferenceReport {
    selection: ObjectReferencePlan,
    content: crate::ContentReport,
    bound: Vec<(IdentityAttribute, AttributeValue)>,
    current: crate::attributes::owned::resident::AttributeSnapshot,
    cardinality: Observation<u64>,
    reference_present: Observation<bool>,
    // The bound table and its payloads remain live across compound operations.
    // Drop every report field before returning their prepared reservation.
    _bound_credit: Option<crate::symmetric::memory::Credit>,
}
impl std::fmt::Debug for ObjectReferenceReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObjectReferenceReport")
            .field("selection", &self.selection)
            .field("content", &self.content)
            .field("bound", &self.bound)
            .field("current", &self.current)
            .field("cardinality", &self.cardinality)
            .field("reference_present", &self.reference_present)
            .finish()
    }
}
fn field(
    values: &[(IdentityAttribute, AttributeValue)],
    key: IdentityAttribute,
) -> &AttributeValue {
    values
        .iter()
        .find(|(k, _)| *k == key)
        .map_or(&AttributeValue::NotRequested, |(_, v)| v)
}
fn bytes(value: &[u8]) -> Result<AttributeValue> {
    let mut owned = Vec::new();
    owned.try_reserve_exact(value.len()).map_err(|_| {
        Error::Rejected(crate::RejectionReason::ObjectReferences(
            crate::ObjectReferencesRejection::ReferenceMetadataAllocation,
        ))
    })?;
    owned.extend_from_slice(value);
    Ok(AttributeValue::Available(owned))
}
fn initial(object: &ManagedObjectRef, key: IdentityAttribute) -> Result<AttributeValue> {
    let id = &object.identity;
    match key {
        IdentityAttribute::Class => bytes(&id.class.raw().to_ne_bytes()),
        IdentityAttribute::KeyType => match id.key_type {
            Some(k) => bytes(&k.to_ne_bytes()),
            None => Ok(AttributeValue::NotRequested),
        },
        IdentityAttribute::Id if id.class == ManagedClass::Data => Ok(AttributeValue::NotRequested),
        IdentityAttribute::Id => Ok(id.id_observation().clone()),
        IdentityAttribute::Label => Ok(id.label_observation().clone()),
        IdentityAttribute::Application if id.class == ManagedClass::Data => {
            Ok(id.application_observation().clone())
        }
        IdentityAttribute::ObjectId if id.class == ManagedClass::Data => {
            Ok(id.object_type_observation().clone())
        }
        IdentityAttribute::Application | IdentityAttribute::ObjectId => {
            Ok(AttributeValue::NotRequested)
        }
        IdentityAttribute::UniqueId => match id
            .properties
            .attribute_observation(crate::Attribute::UniqueId)
        {
            AttributeValue::Available(value) => bytes(value),
            AttributeValue::NotRequested => Ok(AttributeValue::NotRequested),
            AttributeValue::Sensitive => Ok(AttributeValue::Sensitive),
            AttributeValue::Unsupported => Ok(AttributeValue::Unsupported),
            AttributeValue::Indeterminate => Ok(AttributeValue::Indeterminate),
        },
    }
}
impl ObjectReferenceReport {
    /// Independent content observation for this call; content bytes are not retained.
    pub fn content(&self) -> &crate::ContentReport {
        &self.content
    }
    /// Exact owned choices for this check; no native call.
    pub fn selection(&self) -> &ObjectReferencePlan {
        &self.selection
    }
    /// Retained admission-time metadata, or NotRequested when absent from this check.
    pub fn bound(&self, key: IdentityAttribute) -> &AttributeValue {
        field(&self.bound, key)
    }
    /// Exact current metadata observation, including unavailable status.
    pub fn current(&self, key: IdentityAttribute) -> &AttributeValue {
        self.current.get(key.attribute().raw())
    }
    /// Count of visible matches, or an explicit missing observation.
    pub fn cardinality(&self) -> Observation<u64> {
        self.cardinality
    }
    /// Whether this native reference occurred in the selected search result.
    pub fn reference_present(&self) -> Observation<bool> {
        self.reference_present
    }

    /// Pure report construction for the path with no native observation. The
    /// full public route selects its resident owner before taking possession.
    pub(crate) fn observe_local(
        selection: ObjectReferencePlan,
        state: &crate::session::SessionAccess<'_>,
        session: &Session,
        object: &ManagedObjectRef,
        content: crate::ContentObservation,
    ) -> Result<Self> {
        if resident::preparation::Initial::requires_preparation(
            &selection,
            object,
            resident::content_plan(&content),
        )? {
            return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::ReferenceObservationRequiresPreparedOwner,
            )));
        }
        let handle = session.managed_handle(state, object)?;
        let bound = evaluation::bound(&selection, object)?;
        let search = evaluation::SearchEvidence::observe(&selection, None, handle)?;
        let current = evaluation::CurrentEvidence::observe(&selection, Default::default())?;
        let content = content.observe_local()?;
        object.identity.access.result(
            session,
            state,
            Ok(evaluation::report(
                selection, bound, search, current, content, None,
            )),
        )
    }
}
