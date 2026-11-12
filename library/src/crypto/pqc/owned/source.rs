// SPDX-License-Identifier: Apache-2.0
//! Disjoint creation and existing-pair inputs; no synthetic creation defaults.

use super::super::{PqcAlgorithm, PqcKeySpec};

use crate::{Error, ObjectAdmission, Result};

pub(super) enum Source {
    Generate {
        request: PqcKeySpec,
        protection: crate::CurrentKeyProtection,
        visibility: crate::ObjectVisibility,
    },
    Existing {
        id: Vec<u8>,
        algorithm: PqcAlgorithm,
        public_admission: ObjectAdmission,
        private_admission: ObjectAdmission,
    },
}
impl Source {
    pub(super) fn algorithm(&self) -> PqcAlgorithm {
        match self {
            Self::Generate { request, .. } => request.algorithm,
            Self::Existing { algorithm, .. } => *algorithm,
        }
    }
    pub(super) fn id(&self) -> &[u8] {
        match self {
            Self::Generate { request, .. } => &request.id,
            Self::Existing { id, .. } => id,
        }
    }
    pub(super) fn admission(&self, private: bool) -> &ObjectAdmission {
        match self {
            Self::Generate { request, .. } => {
                if private {
                    &request.private_admission
                } else {
                    &request.public_admission
                }
            }
            Self::Existing {
                public_admission,
                private_admission,
                ..
            } => {
                if private {
                    private_admission
                } else {
                    public_admission
                }
            }
        }
    }
    pub(super) fn generation_request(&self) -> Result<&PqcKeySpec> {
        match self {
            Self::Generate { request, .. } => Ok(request),
            Self::Existing { .. } => Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::ExistingPqcPairHasNoGenerationRequest,
            ))),
        }
    }

    pub(super) fn templates_as<T: crate::attributes::TemplateSink>(&self) -> Result<(T, T)> {
        match self {
            Self::Generate {
                request,
                protection,
                visibility,
            } => Ok(super::super::admission::templates_as(
                request,
                *protection,
                *visibility,
            )),
            Self::Existing { .. } => Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::ExistingPqcPairHasNoCreationTemplates,
            ))),
        }
    }
}


