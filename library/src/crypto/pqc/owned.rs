// SPDX-License-Identifier: Apache-2.0
//! Native PQC pair ownership and explicit public observations.
use super::{PqcKeyPair, PqcKeySpec, PqcPublicKey, PqcSigningKey, PqcVerificationKey};
use crate::{
    attributes::RequiredAttributes, mechanism_policy::PreparedMechanismAttributes,
    symmetric::memory::Credit, Error, ManagedObjectRef, Result,
};
use fe11_sys::*;
mod preparation;
mod source;
pub(crate) use preparation::{PqcPairInitial, PqcPairPlan, PqcPairStorage};
use source::Source;

enum PublicState {
    AwaitingStorage,
    AwaitingIdentity(PqcPublicKey),
    ReadPermitted(PqcPublicKey),
    Observed {
        key: PqcPublicKey,
        fingerprint: [u8; 32],
    },
    Published,
}
pub(crate) struct PreparedPqcPair {
    source: Source,
    pub(crate) public_policy: PreparedMechanismAttributes,
    pub(crate) private_policy: PreparedMechanismAttributes,
    public: PublicState,
    _credit: Credit,
}
// These inputs contain no copied selection ID or encoded mechanism list.
// Generation owns only the request supplied by the caller; selection borrows ID.
enum PqcOwnerInput<'a> {
    Generation {
        request: PqcKeySpec,
        protection: crate::CurrentKeyProtection,
        visibility: crate::ObjectVisibility,
    },
    Existing {
        id: &'a [u8],
        algorithm: super::PqcAlgorithm,
        public_admission: crate::ObjectAdmission,
        private_admission: crate::ObjectAdmission,
    },
}

enum PqcInputStorage {
    Generation,
    Existing(Vec<u8>),
}

/// Initial family inputs, distinct from the later public-observation plan.
pub(crate) struct PqcOwnerPlan<'a> {
    input: PqcOwnerInput<'a>,
    public_policy: crate::MechanismAttributes<'a>,
    private_policy: crate::MechanismAttributes<'a>,
}

pub(crate) struct PqcOwnerStorage {
    input: PqcInputStorage,
    public_policy: PreparedMechanismAttributes,
    private_policy: PreparedMechanismAttributes,
}

/// Converted native lists and copied selection data; no caller request.
pub(crate) struct PqcBoundOwnerStorage {
    storage: PqcOwnerStorage,
    credit: Credit,
}

fn owner_bytes(source: usize, public_policy: usize, private_policy: usize) -> Result<usize> {
    [
        std::mem::size_of::<PreparedPqcPair>(),
        source,
        public_policy,
        private_policy,
    ]
    .into_iter()
    .try_fold(0usize, |total, n| {
        total
            .checked_add(n)
            .ok_or(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcPairOwnerSize,
            )))
    })
}

impl<'a> PqcOwnerPlan<'a> {
    pub(crate) fn generating(
        request: PqcKeySpec,
        public_policy: crate::MechanismAttributes<'a>,
        private_policy: crate::MechanismAttributes<'a>,
        protection: crate::CurrentKeyProtection,
        visibility: crate::ObjectVisibility,
    ) -> Result<Self> {
        request.validate()?;
        public_policy.validate()?;
        private_policy.validate()?;
        Ok(Self {
            input: PqcOwnerInput::Generation {
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
        let (algorithm, _) = PqcPublicKey::borrow_spki(expected_spki)?;
        super::keys::validate_observation_budgets(
            algorithm,
            &public_admission,
            &private_admission,
        )?;
        // Selection has observation choices, never a creation-template request.
        let policy = |admission| crate::MechanismAttributes {
            request: crate::MechanismRequest::Omitted,
            admission,
        };
        Ok(Self {
            input: PqcOwnerInput::Existing {
                id,
                algorithm,
                public_admission,
                private_admission,
            },
            public_policy: policy(public_policy),
            private_policy: policy(private_policy),
        })
    }
}

impl PqcOwnerPlan<'_> {
    fn source_bytes(&self) -> Result<usize> {
        match &self.input {
            PqcOwnerInput::Generation { request, .. } => request
                .id
                .capacity()
                .checked_add(request.label.capacity())
                .ok_or(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                    crate::PostQuantumKeysRejection::PqcPairSourceStorage,
                ))),
            PqcOwnerInput::Existing { id, .. } => Ok(id.len()),
        }
    }

    pub(crate) fn requested_bytes(&self) -> Result<usize> {
        owner_bytes(
            self.source_bytes()?,
            self.public_policy.requested_bytes()?,
            self.private_policy.requested_bytes()?,
        )
    }

    pub(crate) fn allocate(&self) -> Result<PqcOwnerStorage> {
        let input = match &self.input {
            PqcOwnerInput::Generation { .. } => PqcInputStorage::Generation,
            PqcOwnerInput::Existing { id, .. } => {
                let mut owned_id = Vec::new();
                owned_id.try_reserve_exact(id.len()).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                        crate::PostQuantumKeysRejection::PqcSelectionIdAllocation,
                    ))
                })?;
                owned_id.extend_from_slice(id);
                PqcInputStorage::Existing(owned_id)
            }
        };
        Ok(PqcOwnerStorage {
            input,
            public_policy: self.public_policy.prepare()?,
            private_policy: self.private_policy.prepare()?,
        })
    }

    pub(crate) fn allocated_bytes(&self, storage: &PqcOwnerStorage) -> Result<usize> {
        let source = match (&self.input, &storage.input) {
            (PqcOwnerInput::Generation { .. }, PqcInputStorage::Generation) => {
                self.source_bytes()?
            }
            (PqcOwnerInput::Existing { .. }, PqcInputStorage::Existing(id)) => id.capacity(),
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                    crate::PostQuantumKeysRejection::PqcInputPreparationChanged,
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
        storage: PqcOwnerStorage,
        prepaid: &mut Credit,
    ) -> Result<PqcBoundOwnerStorage> {
        Ok(PqcBoundOwnerStorage {
            credit: prepaid.split(self.allocated_bytes(&storage)?)?,
            storage,
        })
    }

    /// Validate before taking either owner. On refusal the caller still holds
    /// all inputs and can release its access guards before discarding them.
    /// The successful transfer neither allocates nor waits for another credit.
    pub(crate) fn finish_owner(
        plan: &mut Option<Self>,
        prepared: &mut Option<PqcBoundOwnerStorage>,
    ) -> Result<PreparedPqcPair> {
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
                PqcOwnerInput::Generation { .. },
                PqcInputStorage::Generation
            ) | (PqcOwnerInput::Existing { .. }, PqcInputStorage::Existing(_))
        ) {
            return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcInputPreparationChanged,
            )));
        }
        let plan = plan.take().expect("family input checked before transfer");
        let prepared = prepared
            .take()
            .expect("family storage checked before transfer");

        let PqcBoundOwnerStorage { storage, credit } = prepared;
        let source = match (plan.input, storage.input) {
            (
                PqcOwnerInput::Generation {
                    request,
                    protection,
                    visibility,
                },
                PqcInputStorage::Generation,
            ) => Source::Generate {
                request,
                protection,
                visibility,
            },
            (
                PqcOwnerInput::Existing {
                    algorithm,
                    public_admission,
                    private_admission,
                    ..
                },
                PqcInputStorage::Existing(id),
            ) => Source::Existing {
                id,
                algorithm,
                public_admission,
                private_admission,
            },
            _ => unreachable!("family input/storage pairing checked before transfer"),
        };
        Ok(PreparedPqcPair {
            source,
            public_policy: storage.public_policy,
            private_policy: storage.private_policy,
            public: PublicState::AwaitingStorage,
            _credit: credit,
        })
    }
}

impl crate::crypto::KeyGenerationDescription for PqcOwnerPlan<'_> {
    fn generation_identity(&self) -> Result<crate::crypto::GenerationIdentity<'_>> {
        let PqcOwnerInput::Generation { request, .. } = &self.input else {
            return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::ExistingPqcPairHasNoGenerationRequest,
            )));
        };
        Ok(crate::crypto::GenerationIdentity {
            id: &request.id,
            label: &request.label,
        })
    }
    fn generation_mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        let PqcOwnerInput::Generation { request, .. } = &self.input else {
            return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::ExistingPqcPairHasNoGenerationRequest,
            )));
        };
        Ok(request.algorithm.generation_mechanism())
    }
    fn generation_templates_as<T: crate::attributes::TemplateSink>(
        &self,
    ) -> Result<(T, Option<T>)> {
        let PqcOwnerInput::Generation {
            request,
            protection,
            visibility,
        } = &self.input
        else {
            return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::ExistingPqcPairHasNoCreationTemplates,
            )));
        };
        let (mut public, mut private) =
            super::admission::templates_as(request, *protection, *visibility);
        self.public_policy.apply_borrowed(&mut public)?;
        self.private_policy.apply_borrowed(&mut private)?;
        Ok((public, Some(private)))
    }
}

impl crate::crypto::KeyAdmissionDescription for PqcOwnerPlan<'_> {
    fn is_pair(&self) -> bool {
        true
    }
    fn admission_id(&self) -> &[u8] {
        match &self.input {
            PqcOwnerInput::Generation { request, .. } => &request.id,
            PqcOwnerInput::Existing { id, .. } => id,
        }
    }
    fn admission_class(&self) -> crate::ManagedClass {
        crate::ManagedClass::PublicKey
    }
    fn object_observation(&self, private: bool) -> &crate::ObjectAdmission {
        match &self.input {
            PqcOwnerInput::Generation { request, .. } => {
                if private {
                    &request.private_admission
                } else {
                    &request.public_admission
                }
            }
            PqcOwnerInput::Existing {
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

impl PreparedPqcPair {
    pub(crate) fn generation_mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self
            .source
            .generation_request()?
            .algorithm
            .generation_mechanism())
    }
    pub(crate) fn generation_request(&self) -> Result<&PqcKeySpec> {
        self.source.generation_request()
    }
    pub(crate) fn id(&self) -> &[u8] {
        self.source.id()
    }
    pub(crate) fn public_admission(&self) -> &crate::ObjectAdmission {
        self.source.admission(false)
    }
    pub(crate) fn private_admission(&self) -> &crate::ObjectAdmission {
        self.source.admission(true)
    }
    pub(crate) fn key_type(&self) -> CK_KEY_TYPE {
        self.source.algorithm().key_type()
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
        validate_identity(
            values,
            if private {
                CKO_PRIVATE_KEY
            } else {
                CKO_PUBLIC_KEY
            },
            self.source.algorithm(),
        )?;
        if !private {
            if !matches!(self.public, PublicState::AwaitingIdentity(_)) {
                return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                    crate::PostQuantumKeysRejection::PqcPublicIdentityAlreadyObserved,
                )));
            }
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
        let PublicState::ReadPermitted(key) = &mut self.public else {
            return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcValueRequiresPublicIdentity,
            )));
        };
        key.observe_raw(values.bytes(CKA_VALUE)?)?;
        let fingerprint = key.spki_fingerprint()?;
        let PublicState::ReadPermitted(key) =
            std::mem::replace(&mut self.public, PublicState::Published)
        else {
            unreachable!("public observation phase checked")
        };
        self.public = PublicState::Observed { key, fingerprint };
        Ok(())
    }
    fn public(&self) -> Result<(&PqcPublicKey, [u8; 32])> {
        match &self.public {
            PublicState::Observed { key, fingerprint } => Ok((key, *fingerprint)),
            _ => Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcPublicObservationIncomplete,
            ))),
        }
    }

    pub(crate) fn finish(
        &mut self,
        public: ManagedObjectRef,
        private: ManagedObjectRef,
        public_allowed: crate::MechanismObservationReport,
        private_allowed: crate::MechanismObservationReport,
    ) -> Result<PqcKeyPair> {
        let (_, fingerprint) = self.public()?;
        let PublicState::Observed { key, .. } =
            std::mem::replace(&mut self.public, PublicState::Published)
        else {
            unreachable!("public observation checked")
        };
        Ok(PqcKeyPair {
            public: PqcVerificationKey {
                managed: public,
                algorithm: self.source.algorithm(),
                fingerprint,
                policy: public_allowed,
            },
            private: PqcSigningKey {
                managed: private,
                algorithm: self.source.algorithm(),
                fingerprint,
                policy: private_allowed,
            },
            public_key: key,
        })
    }
}

// Check structural identity before reading CKA_VALUE. Property restrictions
// belong to caller-selected controls and are deliberately absent here.
pub(super) fn validate_identity(
    values: &RequiredAttributes,
    class: CK_OBJECT_CLASS,
    algorithm: super::PqcAlgorithm,
) -> Result<()> {
    values.integer(CKA_CLASS, class)?;
    values.integer(CKA_KEY_TYPE, algorithm.key_type())?;
    values.integer(CKA_PARAMETER_SET, algorithm.description().parameter)
}
