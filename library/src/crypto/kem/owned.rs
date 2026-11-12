// SPDX-License-Identifier: Apache-2.0
//! Owned ML-KEM pair inputs; read public material only after class validation.
use super::{KemDecapsulationKey, KemEncapsulationKey, KemKeyPair, KemKeySpec, KemPublicKey};

use crate::{
    attributes::RequiredAttributes, mechanism_policy::PreparedMechanismAttributes,
    symmetric::memory::Credit, Error, ManagedObjectRef, Result,
};
use fe11_sys::*;

mod preparation;
mod source;
pub(crate) use preparation::{KemPairInitial, KemPairPlan, KemPairStorage};
use source::Source;

enum PublicState {
    AwaitingStorage,
    AwaitingIdentity(KemPublicKey),
    ReadPermitted(KemPublicKey),
    Observed(KemPublicKey),
    Published,
}

pub(crate) struct PreparedKemPair {
    source: Source,
    pub(crate) public_policy: PreparedMechanismAttributes,
    pub(crate) private_policy: PreparedMechanismAttributes,
    public: PublicState,
    _credit: Credit,
}
// These inputs contain no copied selection ID or encoded mechanism list.
// Generation owns only the request supplied by the caller; selection borrows ID.
enum KemOwnerInput<'a> {
    Generation {
        request: KemKeySpec,
        protection: crate::CurrentKeyProtection,
        visibility: crate::ObjectVisibility,
    },
    Existing {
        id: &'a [u8],
        parameter_set: super::MlKemParameterSet,
        public_admission: crate::ObjectAdmission,
        private_admission: crate::ObjectAdmission,
    },
}

enum KemInputStorage {
    Generation,
    Existing(Vec<u8>),
}

/// Initial family inputs, distinct from the later public-observation plan.
pub(crate) struct KemOwnerPlan<'a> {
    input: KemOwnerInput<'a>,
    public_policy: crate::MechanismAttributes<'a>,
    private_policy: crate::MechanismAttributes<'a>,
}

pub(crate) struct KemOwnerStorage {
    input: KemInputStorage,
    public_policy: PreparedMechanismAttributes,
    private_policy: PreparedMechanismAttributes,
}

/// Converted native lists and copied selection data; no caller request.
pub(crate) struct KemBoundOwnerStorage {
    storage: KemOwnerStorage,
    credit: Credit,
}

fn owner_bytes(source: usize, public_policy: usize, private_policy: usize) -> Result<usize> {
    [
        std::mem::size_of::<PreparedKemPair>(),
        source,
        public_policy,
        private_policy,
    ]
    .into_iter()
    .try_fold(0usize, |total, n| {
        total
            .checked_add(n)
            .ok_or(Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                crate::KeyEncapsulationRejection::MlKemPairOwnerSize,
            )))
    })
}

impl<'a> KemOwnerPlan<'a> {
    pub(crate) fn generating(
        request: KemKeySpec,
        public_policy: crate::MechanismAttributes<'a>,
        private_policy: crate::MechanismAttributes<'a>,
        protection: crate::CurrentKeyProtection,
        visibility: crate::ObjectVisibility,
    ) -> Result<Self> {
        request.validate()?;
        public_policy.validate()?;
        private_policy.validate()?;
        Ok(Self {
            input: KemOwnerInput::Generation {
                request,
                protection,
                visibility,
            },
            public_policy,
            private_policy,
        })
    }

    pub(crate) fn selected(
        id: &'a [u8],
        expected_spki: &[u8],
        public_policy: crate::MechanismObservationPlan,
        private_policy: crate::MechanismObservationPlan,
        public_admission: crate::ObjectAdmission,
        private_admission: crate::ObjectAdmission,
    ) -> Result<Self> {
        crate::bounds::ck_length(id.len())?;
        let (parameter_set, _) = KemPublicKey::borrow_spki(expected_spki)?;
        super::validate_observation_budgets(parameter_set, &public_admission, &private_admission)?;
        // Selection has observation choices, never a creation-template request.
        let policy = |admission| crate::MechanismAttributes {
            request: crate::MechanismRequest::Omitted,
            admission,
        };
        Ok(Self {
            input: KemOwnerInput::Existing {
                id,
                parameter_set,
                public_admission,
                private_admission,
            },
            public_policy: policy(public_policy),
            private_policy: policy(private_policy),
        })
    }
}

impl KemOwnerPlan<'_> {
    fn source_bytes(&self) -> Result<usize> {
        match &self.input {
            KemOwnerInput::Generation { request, .. } => request
                .id
                .capacity()
                .checked_add(request.label.capacity())
                .ok_or(Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                    crate::KeyEncapsulationRejection::MlKemPairSourceStorage,
                ))),
            KemOwnerInput::Existing { id, .. } => Ok(id.len()),
        }
    }

    pub(crate) fn requested_bytes(&self) -> Result<usize> {
        owner_bytes(
            self.source_bytes()?,
            self.public_policy.requested_bytes()?,
            self.private_policy.requested_bytes()?,
        )
    }

    pub(crate) fn allocate(&self) -> Result<KemOwnerStorage> {
        let input = match &self.input {
            KemOwnerInput::Generation { .. } => KemInputStorage::Generation,
            KemOwnerInput::Existing { id, .. } => {
                let mut owned_id = Vec::new();
                owned_id.try_reserve_exact(id.len()).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                        crate::KeyEncapsulationRejection::MlKemSelectionIdAllocation,
                    ))
                })?;
                owned_id.extend_from_slice(id);
                KemInputStorage::Existing(owned_id)
            }
        };
        Ok(KemOwnerStorage {
            input,
            public_policy: self.public_policy.prepare()?,
            private_policy: self.private_policy.prepare()?,
        })
    }

    pub(crate) fn allocated_bytes(&self, storage: &KemOwnerStorage) -> Result<usize> {
        let source = match (&self.input, &storage.input) {
            (KemOwnerInput::Generation { .. }, KemInputStorage::Generation) => {
                self.source_bytes()?
            }
            (KemOwnerInput::Existing { .. }, KemInputStorage::Existing(id)) => id.capacity(),
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                    crate::KeyEncapsulationRejection::MlKemInputPreparationChanged,
                )))
            }
        };
        owner_bytes(
            source,
            storage.public_policy.retained_request_bytes()?,
            storage.private_policy.retained_request_bytes()?,
        )
    }

    /// Complete every fallible storage conversion and credit split while the
    /// input plan is only borrowed. A retry can discard this candidate without
    /// consuming caller-transferred requests or observation choices.
    pub(crate) fn prepare_owner(
        &self,
        storage: KemOwnerStorage,
        prepaid: &mut Credit,
    ) -> Result<KemBoundOwnerStorage> {
        Ok(KemBoundOwnerStorage {
            credit: prepaid.split(self.allocated_bytes(&storage)?)?,
            storage,
        })
    }

    /// Validate before taking either owner. On refusal the caller still holds
    /// all inputs and can release its access guards before discarding them.
    /// The successful transfer neither allocates nor waits for another credit.
    pub(crate) fn finish_owner(
        plan: &mut Option<Self>,
        prepared: &mut Option<KemBoundOwnerStorage>,
    ) -> Result<PreparedKemPair> {
        let input = plan
            .as_ref()
            .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::FamilyInputPlanAbsent,
            )))?;
        let candidate =
            prepared
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::FamilyOwnerStorageAbsent,
                )))?;
        if !matches!(
            (&input.input, &candidate.storage.input),
            (
                KemOwnerInput::Generation { .. },
                KemInputStorage::Generation
            ) | (KemOwnerInput::Existing { .. }, KemInputStorage::Existing(_))
        ) {
            return Err(Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                crate::KeyEncapsulationRejection::MlKemInputPreparationChanged,
            )));
        }
        let plan = plan.take().expect("family input checked before transfer");
        let prepared = prepared
            .take()
            .expect("family storage checked before transfer");

        let KemBoundOwnerStorage { storage, credit } = prepared;
        let source = match (plan.input, storage.input) {
            (
                KemOwnerInput::Generation {
                    request,
                    protection,
                    visibility,
                },
                KemInputStorage::Generation,
            ) => Source::Generate {
                request,
                protection,
                visibility,
            },
            (
                KemOwnerInput::Existing {
                    parameter_set,
                    public_admission,
                    private_admission,
                    ..
                },
                KemInputStorage::Existing(id),
            ) => Source::Existing {
                id,
                parameter_set,
                public_admission,
                private_admission,
            },
            _ => unreachable!("family input/storage pairing checked before transfer"),
        };
        Ok(PreparedKemPair {
            source,
            public_policy: storage.public_policy,
            private_policy: storage.private_policy,
            public: PublicState::AwaitingStorage,
            _credit: credit,
        })
    }
}

impl crate::crypto::KeyGenerationDescription for KemOwnerPlan<'_> {
    fn generation_identity(&self) -> Result<crate::crypto::GenerationIdentity<'_>> {
        let KemOwnerInput::Generation { request, .. } = &self.input else {
            return Err(Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                crate::KeyEncapsulationRejection::ExistingMlKemPairHasNoGenerationRequest,
            )));
        };
        Ok(crate::crypto::GenerationIdentity {
            id: &request.id,
            label: &request.label,
        })
    }
    fn generation_mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        let KemOwnerInput::Generation { .. } = &self.input else {
            return Err(Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                crate::KeyEncapsulationRejection::ExistingMlKemPairHasNoGenerationRequest,
            )));
        };
        Ok(CKM_ML_KEM_KEY_PAIR_GEN)
    }
    fn generation_templates_as<T: crate::attributes::TemplateSink>(
        &self,
    ) -> Result<(T, Option<T>)> {
        let KemOwnerInput::Generation {
            request,
            protection,
            visibility,
        } = &self.input
        else {
            return Err(Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                crate::KeyEncapsulationRejection::ExistingMlKemPairHasNoCreationTemplates,
            )));
        };
        let (mut public, mut private) =
            super::admission::templates_as(request, *protection, *visibility);
        self.public_policy.apply_borrowed(&mut public)?;
        self.private_policy.apply_borrowed(&mut private)?;
        Ok((public, Some(private)))
    }
}

impl crate::crypto::KeyAdmissionDescription for KemOwnerPlan<'_> {
    fn is_pair(&self) -> bool {
        true
    }
    fn admission_id(&self) -> &[u8] {
        match &self.input {
            KemOwnerInput::Generation { request, .. } => &request.id,
            KemOwnerInput::Existing { id, .. } => id,
        }
    }
    fn admission_class(&self) -> crate::ManagedClass {
        crate::ManagedClass::PublicKey
    }
    fn object_observation(&self, private: bool) -> &crate::ObjectAdmission {
        match &self.input {
            KemOwnerInput::Generation { request, .. } => {
                if private {
                    &request.private_admission
                } else {
                    &request.public_admission
                }
            }
            KemOwnerInput::Existing {
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
    fn history_observation(&self, _private: bool) -> Option<crate::HistoryObservationPlan> {
        None
    }
    fn mechanism_observation(&self, private: bool) -> &crate::MechanismObservationPlan {
        if private {
            &self.private_policy.admission
        } else {
            &self.public_policy.admission
        }
    }
    fn visit_required(&self, _private: bool, field: &mut dyn FnMut(CK_ATTRIBUTE_TYPE)) {
        [CKA_CLASS, CKA_KEY_TYPE, CKA_PARAMETER_SET]
            .into_iter()
            .for_each(field);
    }
    fn visit_material(&self, private: bool, field: &mut dyn FnMut(CK_ATTRIBUTE_TYPE)) {
        if !private {
            field(CKA_VALUE);
        }
    }
}

impl PreparedKemPair {
    pub(crate) fn id(&self) -> &[u8] {
        self.source.id()
    }
    pub(crate) fn public_admission(&self) -> &crate::ObjectAdmission {
        self.source.admission(false)
    }
    pub(crate) fn private_admission(&self) -> &crate::ObjectAdmission {
        self.source.admission(true)
    }
    pub(crate) fn generation_request(&self) -> Result<&KemKeySpec> {
        self.source.generation_request()
    }
    pub(crate) fn templates_as<T: crate::attributes::TemplateSink>(&self) -> Result<(T, T)> {
        let (mut public, mut private) = self.source.templates_as::<T>()?;
        self.public_policy.apply(&mut public)?;
        self.private_policy.apply(&mut private)?;
        Ok((public, private))
    }
    pub(crate) fn field_iter(&self) -> impl Iterator<Item = CK_ATTRIBUTE_TYPE> {
        [CKA_CLASS, CKA_KEY_TYPE, CKA_PARAMETER_SET].into_iter()
    }
    pub(crate) fn validate(&mut self, private: bool, values: &RequiredAttributes) -> Result<()> {
        values.integer(
            CKA_CLASS,
            if private {
                CKO_PRIVATE_KEY
            } else {
                CKO_PUBLIC_KEY
            },
        )?;
        values.integer(CKA_KEY_TYPE, CKK_ML_KEM)?;
        values.integer(CKA_PARAMETER_SET, self.source.parameter_set().raw())?;
        if !private {
            if !matches!(self.public, PublicState::AwaitingIdentity(_)) {
                return Err(Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                    crate::KeyEncapsulationRejection::MlKemPublicIdentityAlreadyObserved,
                )));
            }
            // Only this transition permits the separate CKA_VALUE read. Move
            // its already credited storage; no allocation is needed here.
            let PublicState::AwaitingIdentity(storage) =
                std::mem::replace(&mut self.public, PublicState::Published)
            else {
                unreachable!("public identity phase checked")
            };
            self.public = PublicState::ReadPermitted(storage);
        }
        Ok(())
    }
    pub(crate) fn observe_public(&mut self, values: &RequiredAttributes) -> Result<()> {
        let PublicState::ReadPermitted(public) = &mut self.public else {
            return Err(Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                crate::KeyEncapsulationRejection::MlKemValueRequiresPublicIdentity,
            )));
        };
        public.observe_raw(values.bytes(CKA_VALUE)?)?;
        let PublicState::ReadPermitted(public) =
            std::mem::replace(&mut self.public, PublicState::Published)
        else {
            unreachable!("public observation phase checked")
        };
        self.public = PublicState::Observed(public);
        Ok(())
    }
    pub(crate) fn complete(&self) -> Result<()> {
        if !matches!(self.public, PublicState::Observed(_)) {
            return Err(Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                crate::KeyEncapsulationRejection::MlKemPublicObservationIncomplete,
            )));
        }
        Ok(())
    }
    pub(crate) fn finish(
        &mut self,
        public: ManagedObjectRef,
        private: ManagedObjectRef,
        public_allowed: crate::MechanismObservationReport,
        private_allowed: crate::MechanismObservationReport,
    ) -> Result<KemKeyPair> {
        self.complete()?;
        let PublicState::Observed(key) =
            std::mem::replace(&mut self.public, PublicState::Published)
        else {
            unreachable!("ML-KEM public state checked before consuming it")
        };
        Ok(KemKeyPair {
            public: KemEncapsulationKey {
                managed: public,
                public: key,
                allowed: public_allowed,
            },
            private: KemDecapsulationKey {
                managed: private,
                parameter_set: self.source.parameter_set(),
                allowed: private_allowed,
            },
        })
    }
}
