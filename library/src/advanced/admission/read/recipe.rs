// SPDX-License-Identifier: Apache-2.0
//! Borrowed, allocation-free descriptions of the admitted observation stages.
use crate::crypto::KeyAdmissionDescription;
use crate::{Error, ObjectAdmission, Result};
use fe11_sys::{CKA_ALLOWED_MECHANISMS, CK_ATTRIBUTE_TYPE};

#[derive(Clone, Copy)]
pub(super) enum Kind {
    Required,
    Material,
    History,
    Mechanisms,
    Properties,
}
impl Kind {
    pub(super) const ALL: [Self; 5] = [
        Self::Required,
        Self::Material,
        Self::History,
        Self::Mechanisms,
        Self::Properties,
    ];
    pub(super) fn index(self) -> usize {
        match self {
            Self::Required => 0,
            Self::Material => 1,
            Self::History => 2,
            Self::Mechanisms => 3,
            Self::Properties => 4,
        }
    }
}
#[derive(Clone, Copy)]
pub(super) struct Recipe<'a> {
    pub policy: &'a dyn KeyAdmissionDescription,
    pub private: bool,
    pub kind: Kind,
}
impl<'a> Recipe<'a> {
    fn objects(self) -> &'a ObjectAdmission {
        self.policy.object_observation(self.private)
    }
    fn history(self) -> Option<crate::HistoryObservationPlan> {
        self.policy.history_observation(self.private)
    }
    fn mechanisms(self) -> &'a crate::MechanismObservationPlan {
        self.policy.mechanism_observation(self.private)
    }
    pub(super) fn visit(self, mut field: impl FnMut(CK_ATTRIBUTE_TYPE)) {
        match self.kind {
            Kind::Required => self.policy.visit_required(self.private, &mut field),
            Kind::Material => self.policy.visit_material(self.private, &mut field),
            Kind::History => {
                if let Some(history) = self.history() {
                    history.field_iter().for_each(field);
                }
            }
            Kind::Mechanisms => {
                if matches!(
                    self.mechanisms(),
                    crate::MechanismObservationPlan::Read { .. }
                ) {
                    field(CKA_ALLOWED_MECHANISMS);
                }
            }
            Kind::Properties => self.objects().observation_field_iter().for_each(field),
        }
    }
    pub(super) fn shape(self) -> Result<(usize, usize, bool)> {
        if matches!(self.kind, Kind::Properties) {
            self.objects().validate_public_selection()?;
        }
        let mut count = Some(0usize);
        self.visit(|_| count = count.and_then(|n| n.checked_add(1)));
        let count = count.ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
            crate::KeyAdmissionRejection::OwnedAttributeMetadata,
        )))?;
        if count == 0 && matches!(self.kind, Kind::Required) {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::OwnedAttributeRequest,
            )));
        }
        crate::bounds::ck_length(count)?;
        let limit = match self.kind {
            Kind::Required | Kind::Material => self.objects().metadata.maximum_bytes,
            Kind::History => self.history().map_or(0, |plan| plan.maximum_bytes),
            Kind::Mechanisms => match *self.mechanisms() {
                crate::MechanismObservationPlan::Read { maximum_bytes } => maximum_bytes,
                _ => 0,
            },
            Kind::Properties => self.objects().observation.maximum_bytes,
        };
        let precise = matches!(self.kind, Kind::Mechanisms)
            || (count == 1 && matches!(self.kind, Kind::History | Kind::Properties));
        Ok((count, limit, precise))
    }
}
