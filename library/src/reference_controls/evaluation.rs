// SPDX-License-Identifier: Apache-2.0
//! Pure reference evidence, shared by ordinary and resident protocols.
use super::*;
use crate::attributes::TemplateSink;
use fe11_sys::{CK_OBJECT_HANDLE, CK_ULONG};

const DOMAIN: [IdentityAttribute; 7] = [
    IdentityAttribute::Class,
    IdentityAttribute::KeyType,
    IdentityAttribute::Id,
    IdentityAttribute::Label,
    IdentityAttribute::UniqueId,
    IdentityAttribute::Application,
    IdentityAttribute::ObjectId,
];

fn bound_requested(
    selection: &ObjectReferencePlan,
    object: &ManagedObjectRef,
    key: IdentityAttribute,
) -> bool {
    let template = matches!(selection.search.as_ref(), ReferenceSearchPlan::Observe { template, .. }
        if template.contains(key, object.identity.class));
    selection.attributes.contains(&key) || template
}

/// Count the same immutable metadata projection without creating its copies.
pub(super) fn bound_requested_bytes(
    selection: &ObjectReferencePlan,
    object: &ManagedObjectRef,
) -> Result<usize> {
    let mut total = 0usize;
    for key in DOMAIN {
        if bound_requested(selection, object, key) {
            total = initial_bytes(object, key, |bytes| {
                std::mem::size_of::<(IdentityAttribute, AttributeValue)>()
                    .checked_add(bytes.map_or(0, <[u8]>::len))
                    .and_then(|value| total.checked_add(value))
                    .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                        crate::ObjectReferencesRejection::ReferenceMetadataSize,
                    )))
            })?;
        }
    }
    Ok(total)
}

/// The vector's capacity, not only its initialized slice, owns storage.
pub(super) fn bound_allocated_bytes(
    bound: &Vec<(IdentityAttribute, AttributeValue)>,
) -> Result<usize> {
    let base = bound
        .capacity()
        .checked_mul(std::mem::size_of::<(IdentityAttribute, AttributeValue)>())
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
            crate::ObjectReferencesRejection::ReferenceMetadataSize,
        )))?;
    bound.iter().try_fold(base, |total, (_, value)| {
        let bytes = match value {
            AttributeValue::Available(bytes) => bytes.capacity(),
            _ => 0,
        };
        total
            .checked_add(bytes)
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::ReferenceMetadataSize,
            )))
    })
}

pub(super) fn bound(
    selection: &ObjectReferencePlan,
    object: &ManagedObjectRef,
) -> Result<Vec<(IdentityAttribute, AttributeValue)>> {
    let requested = |key| bound_requested(selection, object, key);
    let mut bound = Vec::new();
    bound
        .try_reserve_exact(DOMAIN.iter().filter(|key| requested(**key)).count())
        .map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::ReferenceMetadataAllocation,
            ))
        })?;
    for key in DOMAIN {
        if requested(key) {
            bound.push((key, initial(object, key)?));
        }
    }
    Ok(bound)
}

/// Visit retained public metadata without allocating an intermediate copy.
/// The numeric fields are encoded only for the duration of the recipe visit.
fn initial_bytes<T>(
    object: &ManagedObjectRef,
    key: IdentityAttribute,
    visit: impl FnOnce(Option<&[u8]>) -> Result<T>,
) -> Result<T> {
    let id = &object.identity;
    let value = match key {
        IdentityAttribute::Class => return visit(Some(&id.class.raw().to_ne_bytes())),
        IdentityAttribute::KeyType => {
            return match id.key_type {
                Some(kind) => visit(Some(&kind.to_ne_bytes())),
                None => visit(None),
            }
        }
        IdentityAttribute::Id if id.class == ManagedClass::Data => return visit(None),
        IdentityAttribute::Id => id.id_observation(),
        IdentityAttribute::Label => id.label_observation(),
        IdentityAttribute::UniqueId => id
            .properties
            .attribute_observation(crate::Attribute::UniqueId),
        IdentityAttribute::Application if id.class == ManagedClass::Data => {
            id.application_observation()
        }
        IdentityAttribute::ObjectId if id.class == ManagedClass::Data => {
            id.object_type_observation()
        }
        IdentityAttribute::Application | IdentityAttribute::ObjectId => return visit(None),
    };
    visit(match value {
        AttributeValue::Available(bytes) => Some(bytes),
        _ => None,
    })
}

/// A missing operand is unavailable evidence, never a broadened native query.
/// TemplateSize and Template execute the identical borrowed recipe.
pub(super) fn template<S: TemplateSink>(
    selection: &ObjectReferencePlan,
    object: &ManagedObjectRef,
) -> Result<Option<(SearchPlan, S)>> {
    let ReferenceSearchPlan::Observe {
        template,
        resources,
        ..
    } = selection.search.as_ref()
    else {
        return Ok(None);
    };
    let mut sink = S::empty();
    let mut complete = true;
    for key in DOMAIN
        .into_iter()
        .filter(|key| template.contains(*key, object.identity.class))
    {
        initial_bytes(object, key, |bytes| {
            let Some(bytes) = bytes else {
                complete = false;
                return Ok(());
            };
            match key {
                IdentityAttribute::Class | IdentityAttribute::KeyType => sink.integer(
                    key.attribute().raw(),
                    CK_ULONG::from_ne_bytes(bytes.try_into().map_err(|_| {
                        Error::Rejected(crate::RejectionReason::AttributePreparation(
                            crate::AttributePreparationRejection::ReferenceTemplateIntegerWidth,
                        ))
                    })?),
                ),
                _ => sink.bytes(key.attribute().raw(), bytes),
            }
            Ok(())
        })?;
    }
    Ok(complete.then_some((*resources, sink)))
}

pub(super) struct SearchEvidence {
    pub(super) cardinality: Observation<u64>,
    pub(super) reference_present: Observation<bool>,
}
impl SearchEvidence {
    pub(super) fn observe(
        selection: &ObjectReferencePlan,
        found: Option<&[CK_OBJECT_HANDLE]>,
        handle: CK_OBJECT_HANDLE,
    ) -> Result<Self> {
        let (cardinality, reference_present) = match selection.search.as_ref() {
            ReferenceSearchPlan::NotRequested => {
                (Observation::NotRequested, Observation::NotRequested)
            }
            ReferenceSearchPlan::Observe { .. } => match found {
                Some(found) => (
                    Observation::Observed(u64::try_from(found.len()).map_err(|_| {
                        Error::Rejected(crate::RejectionReason::ObjectReferences(
                            crate::ObjectReferencesRejection::ReferenceCardinalityWidth,
                        ))
                    })?),
                    Observation::Observed(found.contains(&handle)),
                ),
                None => (
                    Observation::Unavailable(AttributeUnavailableCause::Unspecified),
                    Observation::Unavailable(AttributeUnavailableCause::Unspecified),
                ),
            },
        };
        Ok(Self {
            cardinality,
            reference_present,
        })
    }
}

pub(super) struct CurrentEvidence {
    pub(super) current: crate::attributes::owned::resident::AttributeSnapshot,
}
impl CurrentEvidence {
    pub(super) fn observe(
        selection: &ObjectReferencePlan,
        observed: crate::attributes::owned::resident::AttributeSnapshot,
    ) -> Result<Self> {
        if observed.len() != selection.attributes.len() {
            return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::ReferenceSnapshotLength,
            )));
        }
        Ok(Self { current: observed })
    }
}
pub(super) fn report(
    selection: ObjectReferencePlan,
    bound: Vec<(IdentityAttribute, AttributeValue)>,
    search: SearchEvidence,
    current: CurrentEvidence,
    content: crate::ContentReport,
    bound_credit: Option<crate::symmetric::memory::Credit>,
) -> ObjectReferenceReport {
    ObjectReferenceReport {
        selection,
        content,
        bound,
        current: current.current,
        cardinality: search.cardinality,
        reference_present: search.reference_present,
        _bound_credit: bound_credit,
    }
}
