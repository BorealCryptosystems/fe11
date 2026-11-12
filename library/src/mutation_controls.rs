// SPDX-License-Identifier: Apache-2.0
//! Explicit before/after native attribute observations for one mutation.
use crate::{Attribute, AttributeReadPlan, AttributeValue, Error, Result, Session};
use fe11_sys::CK_OBJECT_HANDLE;
use std::collections::BTreeSet;
use std::sync::Arc;

/// An explicit set of public attributes and its own native reading budget.
#[derive(Clone, Debug)]
pub struct MutationObservationPlan {
    /// Exactly these fields are read; no comparison adds fields implicitly.
    pub attributes: Arc<BTreeSet<Attribute>>,
    /// Byte budget and optional individual clarification of this stage.
    pub read: AttributeReadPlan,
}

/// Independent choices for one copy, label or generic attribute mutation.
/// No implicit policy is selected by the library.
#[derive(Clone, Debug)]
pub struct ObjectMutationPlan {
    /// Explicit source-reference observations for this call.
    pub source: crate::ObjectReferencePlan,
    /// Independent destination query, cardinality and recorded-role choices.
    pub destination: crate::DestinationPlan,
    /// Observations of the source before the native mutation.
    pub before: MutationObservationPlan,
    /// Observations of the resulting object after native success.
    pub after: MutationObservationPlan,
}

/// Evidence belonging to an individual mutation. A report alone does not
/// establish a new reference or reactivate a revoked alias.
/// Getters return retained observations and never dispatch native calls.
pub struct ObjectMutationReport {
    selection: ObjectMutationPlan,
    reference: crate::ObjectReferenceReport,
    before: crate::attributes::owned::resident::AttributeSnapshot,
    after: crate::attributes::owned::resident::AttributeSnapshot,
}

// The root routes every nonempty observation through its resident owner.
// This local path therefore constructs only the explicit empty snapshot.
fn snapshot(
    plan: &MutationObservationPlan,
) -> Result<crate::attributes::owned::resident::AttributeSnapshot> {
    if !plan.attributes.is_empty() {
        return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
            crate::ObjectMutationRejection::MutationObservationRequiresPreparedOwner,
        )));
    }
    Ok(Default::default())
}
impl MutationObservationPlan {
    pub(crate) fn observed_values(
        &self,
        values: crate::attributes::owned::resident::AttributeSnapshot,
    ) -> Result<crate::attributes::owned::resident::AttributeSnapshot> {
        if values.len() != self.attributes.len() {
            return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::MutationObservationFieldCount,
            )));
        }
        Ok(values)
    }
}

impl ObjectMutationReport {
    /// Source-reference observations belonging to this mutation only.
    pub fn reference_report(&self) -> &crate::ObjectReferenceReport {
        &self.reference
    }

    /// Exact selections owned by this operation.
    pub fn selection(&self) -> &ObjectMutationPlan {
        &self.selection
    }

    /// Before observation, or NotRequested when absent from the selected set.
    pub fn before(&self, field: Attribute) -> &AttributeValue {
        self.before.get(field.raw())
    }

    /// After observation, or NotRequested when absent from the selected set.
    pub fn after(&self, field: Attribute) -> &AttributeValue {
        self.after.get(field.raw())
    }

    pub(crate) fn prepare(
        selection: ObjectMutationPlan,
        reference: crate::ObjectReferenceReport,
        _state: &crate::session::SessionAccess<'_>,
        _session: &Session,
        _object: CK_OBJECT_HANDLE,
    ) -> Result<Self> {
        let before = snapshot(&selection.before)?;
        Self::from_before(selection, reference, before)
    }

    pub(crate) fn from_before(
        selection: ObjectMutationPlan,
        reference: crate::ObjectReferenceReport,
        before: crate::attributes::owned::resident::AttributeSnapshot,
    ) -> Result<Self> {
        Ok(Self {
            selection,
            reference,
            before,
            after: Default::default(),
        })
    }

    pub(crate) fn finish(
        self,
        _state: &crate::session::SessionAccess<'_>,
        _session: &Session,
        _object: CK_OBJECT_HANDLE,
    ) -> Result<Self> {
        let after = snapshot(&self.selection.after)?;
        self.finish_observed(after)
    }

    pub(crate) fn finish_observed(
        mut self,
        after: crate::attributes::owned::resident::AttributeSnapshot,
    ) -> Result<Self> {
        self.after = after;
        Ok(self)
    }
}


