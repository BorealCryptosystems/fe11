// SPDX-License-Identifier: Apache-2.0
//! Borrowed descriptions of the closed historical metadata domains.
use super::*;

#[derive(Clone, Copy)]
pub(crate) enum Recipe<'a> {
    Reference(&'a crate::ObjectReferencePlan),
    Mutation(&'a crate::MutationObservationPlan),
    Required {
        fields: &'a [CK_ATTRIBUTE_TYPE],
        maximum: usize,
    },
    /// One native field, preserving the distinction between sensitive,
    /// unsupported and indeterminate results for caller-selected controls.
    Precise {
        field: CK_ATTRIBUTE_TYPE,
        maximum: usize,
    },
    Public {
        fields: &'a [crate::Attribute],
        plan: AttributeReadPlan,
    },
    Controls(&'a crate::ObjectAdmission),
    History(crate::HistoryObservationPlan),
    Fingerprint {
        fields: &'a [FingerprintAttribute],
        plan: AttributeReadPlan,
    },
}
impl Recipe<'_> {
    pub(super) fn export_len(self) -> usize {
        match self {
            Self::Public { .. } | Self::Reference(_) | Self::Mutation(_) => self.len(),
            Self::Controls(admission) => admission.public_attributes.len(),
            _ => 0,
        }
    }
    pub(super) fn export_field(self, index: usize) -> CK_ATTRIBUTE_TYPE {
        match self {
            Self::Controls(admission) => admission.public_attributes[index].raw(),
            _ => self.field(index),
        }
    }
    pub(crate) fn len(self) -> usize {
        match self {
            Self::Reference(selection) => selection.attributes.len(),
            Self::Mutation(selection) => selection.attributes.len(),
            Self::Required { fields, .. } => fields.len(),
            Self::Precise { .. } => 1,
            Self::Public { fields, .. } => fields.len(),
            Self::Controls(admission) => admission.observation_field_iter().count(),
            Self::History(plan) => plan.field_iter().count(),
            Self::Fingerprint { fields, .. } => fields.len(),
        }
    }
    pub(super) fn field(self, index: usize) -> CK_ATTRIBUTE_TYPE {
        match self {
            Self::Reference(selection) => selection
                .attributes
                .iter()
                .nth(index)
                .expect("validated reference field index")
                .attribute()
                .raw(),
            Self::Mutation(selection) => selection
                .attributes
                .iter()
                .nth(index)
                .expect("validated mutation field index")
                .raw(),
            Self::Required { fields, .. } => fields[index],
            Self::Precise { field, .. } => {
                assert_eq!(index, 0, "validated precise field index");
                field
            }
            Self::Public { fields, .. } => fields[index].raw(),
            Self::Controls(admission) => admission
                .observation_field_iter()
                .nth(index)
                .expect("validated observation index"),
            Self::History(plan) => plan
                .field_iter()
                .nth(index)
                .expect("validated history field index"),
            Self::Fingerprint { fields, .. } => fields[index].raw(),
        }
    }
    pub(crate) fn validate(self) -> Result<()> {
        if let Self::Controls(admission) = self {
            admission.validate_public_selection()?;
        }
        let count = self.len();
        bounds::ck_length(count)?;
        if matches!(self, Self::Controls(_) | Self::Required { .. }) {
            for index in 0..count {
                if (0..index).any(|previous| self.field(previous) == self.field(index)) {
                    return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::DuplicateAttribute,
                    )));
                }
            }
        }
        Ok(())
    }
    pub(super) fn unique_len(self) -> usize {
        (0..self.len())
            .filter(|index| !(0..*index).any(|previous| self.field(previous) == self.field(*index)))
            .count()
    }
    pub(super) fn plan(self) -> AttributeReadPlan {
        match self {
            Self::Reference(selection) => selection.read,
            Self::Mutation(selection) => selection.read,
            Self::Required { maximum, .. } | Self::Precise { maximum, .. } => AttributeReadPlan {
                maximum_bytes: maximum,
                clarification: AttributeClarification::BatchOnly,
            },
            Self::Public { plan, .. } | Self::Fingerprint { plan, .. } => plan,
            Self::Controls(admission) => AttributeReadPlan {
                maximum_bytes: admission.observation.maximum_bytes,
                clarification: AttributeClarification::BatchOnly,
            },
            Self::History(plan) => AttributeReadPlan {
                maximum_bytes: plan.maximum_bytes,
                clarification: AttributeClarification::BatchOnly,
            },
        }
    }
    pub(super) fn output(self) -> OutputKind {
        match self {
            Self::Public { .. } | Self::Reference(_) | Self::Mutation(_) => OutputKind::Public,
            Self::Fingerprint { .. } => OutputKind::Fingerprint,
            Self::Controls(_) | Self::History(_) => OutputKind::Observed,
            Self::Required { .. } => OutputKind::Required,
            Self::Precise { .. } => OutputKind::Precise,
        }
    }
    pub(super) fn request(self) -> RequestKind {
        if matches!(
            self,
            Self::Controls(_) | Self::History(_) | Self::Required { .. } | Self::Precise { .. }
        ) && self.len() == 1
        {
            RequestKind::Individual { index: 0 }
        } else {
            RequestKind::Batch
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum OutputKind {
    Public,
    Fingerprint,
    Observed,
    Required,
    Precise,
}
pub(super) enum Output {
    Public(AttributeSnapshot),
    Observed(ObservedAttributes),
    Required(RequiredAttributes),
    Precise(MechanismValues),
}
