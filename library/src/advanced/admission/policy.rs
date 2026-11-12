// SPDX-License-Identifier: Apache-2.0
//! Project each key request into its templates and requested observations.
//! Public and private members of a key pair retain their distinct admission settings.

use super::*;

impl KeyPolicy {
    pub(super) fn history_plan(&self) -> Option<crate::HistoryObservationPlan> {
        match self {
            Self::Symmetric { spec, .. } => Some(spec.history),
            Self::DerivationBase(p) => Some(p.history_plan()),
            Self::Pair(pair) if pair.private => pair.prepared.private_history_plan(),
            _ => None,
        }
    }

    pub(super) fn object_admission(&self) -> &crate::ObjectAdmission {
        match self {
            Self::Symmetric { spec, .. } => &spec.admission,
            Self::DerivationBase(p) => p.admission(),
            Self::VerificationPublic { prepared, .. } => &prepared.object_admission,
            Self::Pair(pair) => {
                if pair.private {
                    pair.prepared.private_admission()
                } else {
                    pair.prepared.public_admission()
                }
            }
        }
    }

    pub(super) fn mechanisms(&self) -> &crate::MechanismObservationPlan {
        match self {
            Self::Symmetric { spec, .. } => &spec.mechanisms,
            Self::DerivationBase(p) => p.mechanisms(),
            Self::VerificationPublic { prepared, .. } => &prepared.mechanisms,
            Self::Pair(pair) => {
                if pair.private {
                    pair.prepared.mechanisms()
                } else {
                    pair.prepared.public_mechanisms()
                }
            }
        }
    }

    pub(super) fn id(&self) -> &[u8] {
        match self {
            Self::Symmetric { spec, .. } => &spec.id,
            Self::DerivationBase(p) => p.id(),
            Self::VerificationPublic { prepared, .. } => &prepared.id,
            Self::Pair(pair) => pair.prepared.id(),
        }
    }

    pub(super) fn class(&self) -> ManagedClass {
        match self {
            Self::Symmetric { .. } => ManagedClass::SecretKey,
            Self::DerivationBase(p) => p.class(),
            Self::VerificationPublic { .. } => ManagedClass::PublicKey,
            Self::Pair(pair) => {
                if pair.private {
                    ManagedClass::PrivateKey
                } else {
                    ManagedClass::PublicKey
                }
            }
        }
    }
}

// Generation descriptions are also available from unbound family inputs.
// This adapter keeps existing prepared-policy callers on the same builders.
impl crate::crypto::KeyGenerationDescription for KeyPolicy {
    fn generation_identity(&self) -> Result<crate::crypto::GenerationIdentity<'_>> {
        Ok(match self {
            Self::Symmetric { spec, .. } => crate::crypto::GenerationIdentity {
                id: &spec.id,
                label: &spec.label,
            },
            Self::DerivationBase(base) => crate::crypto::GenerationIdentity {
                id: base.id(),
                label: base.label(),
            },
            Self::Pair(pair) => pair.prepared.generation_identity()?,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::CreationDestinationOwner,
                )))
            }
        })
    }

    fn generation_mechanism(&self) -> Result<fe11_sys::CK_MECHANISM_TYPE> {
        match self {
            Self::Symmetric { spec, .. } => spec.algorithm.generation(spec.hmac_key_type),
            Self::DerivationBase(base) => base
                .generation_template_as::<crate::attributes::TemplateSize>()
                .map(|(kind, _)| kind),
            Self::Pair(pair) => pair.prepared.generation_mechanism(),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::GenerationPolicy,
            ))),
        }
    }

    fn generation_templates_as<T: crate::attributes::TemplateSink>(
        &self,
    ) -> Result<(T, Option<T>)> {
        match self {
            Self::Symmetric { spec, .. } => Ok((keys::generation_template_as(spec)?, None)),
            Self::DerivationBase(base) => Ok((base.generation_template_as()?.1, None)),
            Self::Pair(pair) => {
                let (public, private) = pair.prepared.generation_templates_as()?;
                Ok((public, Some(private)))
            }
            _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::GenerationPolicy,
            ))),
        }
    }
}

// Initial plans and installed owners feed the same read/search recipes.
// This adapter preserves the installed owner's family-specific field order.
impl crate::crypto::KeyAdmissionDescription for KeyPolicy {
    fn is_pair(&self) -> bool {
        matches!(self, Self::Pair(_))
    }

    fn admission_id(&self) -> &[u8] {
        KeyPolicy::id(self)
    }

    fn admission_class(&self) -> ManagedClass {
        KeyPolicy::class(self)
    }

    fn object_observation(&self, private: bool) -> &crate::ObjectAdmission {
        match self {
            KeyPolicy::Pair(pair) if private => pair.prepared.private_admission(),
            KeyPolicy::Pair(pair) => pair.prepared.public_admission(),
            _ => KeyPolicy::object_admission(self),
        }
    }

    fn history_observation(&self, private: bool) -> Option<crate::HistoryObservationPlan> {
        match self {
            KeyPolicy::Pair(pair) if private => pair.prepared.private_history_plan(),
            KeyPolicy::Pair(_) => None,
            _ => KeyPolicy::history_plan(self),
        }
    }

    fn mechanism_observation(&self, private: bool) -> &crate::MechanismObservationPlan {
        match self {
            KeyPolicy::Pair(pair) if private => pair.prepared.mechanisms(),
            KeyPolicy::Pair(pair) => pair.prepared.public_mechanisms(),
            _ => KeyPolicy::mechanisms(self),
        }
    }

    fn visit_required(&self, private: bool, field: &mut dyn FnMut(fe11_sys::CK_ATTRIBUTE_TYPE)) {
        match self {
            KeyPolicy::Symmetric { .. } => [fe11_sys::CKA_CLASS, fe11_sys::CKA_KEY_TYPE]
                .into_iter()
                .for_each(field),
            KeyPolicy::DerivationBase(p) => p.field_iter().for_each(field),
            KeyPolicy::VerificationPublic { .. } => [fe11_sys::CKA_CLASS, fe11_sys::CKA_KEY_TYPE]
                .into_iter()
                .for_each(field),
            KeyPolicy::Pair(pair) => match &pair.prepared {
                PreparedPair::Classical(p) => p.field_iter(private).for_each(field),
                PreparedPair::Kem(p) => p.field_iter().for_each(field),
                PreparedPair::Pqc(p) => p.field_iter().for_each(field),
                PreparedPair::Agreement(p) => p.field_iter().for_each(field),
            },
        }
    }

    fn visit_material(&self, private: bool, field: &mut dyn FnMut(fe11_sys::CK_ATTRIBUTE_TYPE)) {
        match self {
            KeyPolicy::VerificationPublic { prepared } => {
                prepared.material_field_iter().for_each(field)
            }
            KeyPolicy::Pair(pair) if !private => match &pair.prepared {
                PreparedPair::Classical(_) => {}
                PreparedPair::Kem(_) | PreparedPair::Pqc(_) => field(fe11_sys::CKA_VALUE),
                PreparedPair::Agreement(_) => field(fe11_sys::CKA_EC_POINT),
            },
            _ => {}
        }
    }
}
