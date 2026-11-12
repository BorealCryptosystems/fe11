// SPDX-License-Identifier: Apache-2.0
//! Size and allocate key-pair admission requests before native generation or search.
//! Prepared owners carry their templates and publication storage together.

use super::*;

impl<'a> ClassicalPairPlan<'a> {
    pub(crate) fn selected(
        id: &'a [u8],
        spki: &'a [u8],
        profiles: &'a [SignatureProfile],
        mechanisms: crate::MechanismObservationPlan,
        public_mechanisms: crate::MechanismObservationPlan,
        public_admission: crate::ObjectAdmission,
        private_admission: crate::ObjectAdmission,
        semantics: crate::EdwardsOptions,
    ) -> Result<Self> {
        crate::bounds::ck_length(id.len())?;
        let algorithm = classical_public_algorithm(spki)?;
        let plan = ClassicalPairPlan {
            input: ClassicalPairInput::Existing {
                id,
                spki,
                profiles,
                algorithm,
                mechanisms,
                public_admission,
                private_admission,
            },
            publication: Publication::Ordinary,
            semantics,
            public_mechanisms,
        };
        // Geometry is checked before the native function/registry preflight.
        plan.requested_bytes()?;
        Ok(plan)
    }

    pub(crate) fn generating(
        spec: ClassicalKeySpec,
        public_mechanisms: crate::MechanismObservationPlan,
        semantics: crate::EdwardsOptions,
        extra: usize,
    ) -> Result<Self> {
        crate::bounds::metadata_lengths(&spec.id, spec.label.as_bytes())?;
        if let ClassicalKeyAlgorithm::Rsa { bits } = spec.algorithm {
            // Reject an unrepresentable native argument before reserving
            // reference or buffer credits. This is not a cryptographic policy.
            crate::bounds::ck_length(bits)?;
        }

        let plan = ClassicalPairPlan {
            input: ClassicalPairInput::Generation {
                request: spec,
                extra,
            },
            publication: Publication::Ordinary,
            semantics,
            public_mechanisms,
        };
        plan.requested_bytes()?;
        Ok(plan)
    }
}

impl ClassicalPairPlan<'_> {
    pub(crate) fn requested_bytes(&self) -> Result<usize> {
        match &self.input {
            ClassicalPairInput::Existing {
                id, spki, profiles, ..
            } => classical_owner_bytes(&[
                id.len(),
                signature_profile_bytes(profiles.len())?,
                profile_bytes(profiles.len())?,
                spki.len(),
            ]),
            ClassicalPairInput::Generation { request, extra } => classical_owner_bytes(&[
                *extra,
                profile_bytes(request.profiles.len())?,
                request.id.capacity(),
                request.label.capacity(),
                // The request retains this Vec separately from the native template,
                // including spare capacity that is not part of CKA_PUBLIC_EXPONENT.
                request
                    .rsa_public_exponent
                    .as_ref()
                    .map_or(0, Vec::capacity),
                signature_profile_bytes(request.profiles.capacity())?,
            ]),
        }
    }

    pub(crate) fn allocate(&self) -> Result<ClassicalPairStorage> {
        Ok(match &self.input {
            ClassicalPairInput::Existing {
                id, spki, profiles, ..
            } => {
                let mut owned_id = Vec::new();
                owned_id.try_reserve_exact(id.len()).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::ClassicalIdentityAllocation,
                    ))
                })?;
                let mut owned_profiles = Vec::new();
                owned_profiles
                    .try_reserve_exact(profiles.len())
                    .map_err(|_| {
                        Error::Rejected(crate::RejectionReason::ClassicalSignatures(
                            crate::ClassicalSignaturesRejection::ClassicalProfileAllocation,
                        ))
                    })?;
                let verification_profiles = profile_storage(profiles.len())?;
                let spki = crate::crypto::integer_key::PublicDerStorage::allocate(spki.len())?;
                ClassicalPairStorage::Existing {
                    id: owned_id,
                    profiles: owned_profiles,
                    verification_profiles,
                    spki,
                }
            }
            ClassicalPairInput::Generation { request, .. } => ClassicalPairStorage::Generation {
                verification_profiles: profile_storage(request.profiles.len())?,
            },
        })
    }

    pub(crate) fn allocated_bytes(&self, storage: &ClassicalPairStorage) -> Result<usize> {
        match (&self.input, storage) {
            (
                ClassicalPairInput::Existing { .. },
                ClassicalPairStorage::Existing {
                    id,
                    profiles,
                    verification_profiles,
                    spki,
                },
            ) => classical_owner_bytes(&[
                id.capacity(),
                signature_profile_bytes(profiles.capacity())?,
                profile_bytes(verification_profiles.capacity())?,
                spki.allocated(),
            ]),
            (
                ClassicalPairInput::Generation { request, extra },
                ClassicalPairStorage::Generation {
                    verification_profiles,
                },
            ) => classical_owner_bytes(&[
                *extra,
                profile_bytes(verification_profiles.capacity())?,
                request.id.capacity(),
                request.label.capacity(),
                // The request retains this Vec separately from the native template,
                // including spare capacity that is not part of CKA_PUBLIC_EXPONENT.
                request
                    .rsa_public_exponent
                    .as_ref()
                    .map_or(0, Vec::capacity),
                signature_profile_bytes(request.profiles.capacity())?,
            ]),
            _ => Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::ClassicalPairPreparationChanged,
                ),
            )),
        }
    }

    /// Complete every fallible storage conversion and credit split while the
    /// input plan is only borrowed. A retry can discard this candidate without
    /// consuming caller-transferred requests or observation choices.
    pub(crate) fn prepare_owner(
        &self,
        storage: ClassicalPairStorage,
        prepaid: &mut Credit,
    ) -> Result<ClassicalPairOwnerStorage> {
        let mut credit = prepaid.split(self.allocated_bytes(&storage)?)?;
        let (signing_capacity, verification_capacity) = match (&self.input, &storage) {
            (
                ClassicalPairInput::Existing { .. },
                ClassicalPairStorage::Existing {
                    profiles,
                    verification_profiles,
                    ..
                },
            ) => (profiles.capacity(), verification_profiles.capacity()),
            (
                ClassicalPairInput::Generation { request, .. },
                ClassicalPairStorage::Generation {
                    verification_profiles,
                },
            ) => (
                request.profiles.capacity(),
                verification_profiles.capacity(),
            ),
            _ => {
                return Err(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::ClassicalPairPreparationChanged,
                    ),
                ))
            }
        };
        let [signing_profile_credit, verification_profile_credit] = credit.split_group([
            signature_profile_bytes(signing_capacity)?,
            profile_bytes(verification_capacity)?,
        ])?;
        let storage = match (&self.input, storage) {
            (
                ClassicalPairInput::Existing {
                    id, spki, profiles, ..
                },
                ClassicalPairStorage::Existing {
                    id: mut owned_id,
                    profiles: mut owned_profiles,
                    mut verification_profiles,
                    spki: storage,
                },
            ) => {
                let spki = storage.bind(spki, &mut credit)?;
                owned_id.extend_from_slice(id);
                owned_profiles.extend_from_slice(profiles);
                verification_profiles.extend(profiles.iter().map(verification_profile));
                ClassicalBoundStorage::Existing {
                    id: owned_id,
                    profiles: owned_profiles,
                    verification_profiles,
                    spki,
                }
            }
            (
                ClassicalPairInput::Generation { request, .. },
                ClassicalPairStorage::Generation {
                    mut verification_profiles,
                },
            ) => {
                verification_profiles.extend(request.profiles.iter().map(verification_profile));
                ClassicalBoundStorage::Generation {
                    verification_profiles,
                }
            }
            _ => {
                return Err(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::ClassicalPairPreparationChanged,
                    ),
                ))
            }
        };
        Ok(ClassicalPairOwnerStorage {
            storage,
            signing_profile_credit,
            verification_profile_credit,
            credit,
        })
    }

    /// Validate before taking either owner. On refusal the caller still holds
    /// all inputs and can release its access guards before discarding them.
    /// The successful transfer neither allocates nor waits for another credit.
    pub(crate) fn finish_owner(
        plan: &mut Option<Self>,
        prepared: &mut Option<ClassicalPairOwnerStorage>,
    ) -> Result<PreparedClassicalPair> {
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
            (&input.input, &candidate.storage),
            (
                ClassicalPairInput::Existing { .. },
                ClassicalBoundStorage::Existing { .. }
            ) | (
                ClassicalPairInput::Generation { .. },
                ClassicalBoundStorage::Generation { .. }
            )
        ) {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::ClassicalPairPreparationChanged,
                ),
            ));
        }
        let plan = plan.take().expect("family input checked before transfer");
        let prepared = prepared
            .take()
            .expect("family storage checked before transfer");

        let ClassicalPairOwnerStorage {
            storage,
            signing_profile_credit,
            verification_profile_credit,
            credit,
        } = prepared;
        let (source, verification_profiles) = match (plan.input, storage) {
            (
                ClassicalPairInput::Existing {
                    algorithm,
                    mechanisms,
                    public_admission,
                    private_admission,
                    ..
                },
                ClassicalBoundStorage::Existing {
                    id,
                    profiles,
                    verification_profiles,
                    spki,
                },
            ) => (
                PairSource::Existing {
                    identity: ExistingPairIdentity {
                        public_admission,
                        private_admission,
                        mechanisms,
                        algorithm,
                        id,
                        profiles,
                    },
                    public: ClassicalPublicMaterial {
                        algorithm,
                        transport: None,
                        spki,
                    },
                },
                verification_profiles,
            ),
            (
                ClassicalPairInput::Generation { request, .. },
                ClassicalBoundStorage::Generation {
                    verification_profiles,
                },
            ) => (
                PairSource::Generation {
                    request,
                    public: GeneratedPublic::AwaitingObservation,
                },
                verification_profiles,
            ),
            _ => unreachable!("classical input/storage pairing checked before transfer"),
        };
        Ok(PreparedClassicalPair {
            verification_profiles,

            publication: plan.publication,
            semantics: plan.semantics,
            public_mechanisms: plan.public_mechanisms,
            source,
            signing_profile_credit: Some(signing_profile_credit),
            verification_profile_credit: Some(verification_profile_credit),
            _credit: credit,
        })
    }
}

impl crate::crypto::KeyGenerationDescription for ClassicalPairPlan<'_> {
    fn generation_identity(&self) -> Result<crate::crypto::GenerationIdentity<'_>> {
        let ClassicalPairInput::Generation { request, .. } = &self.input else {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::ClassicalCreationRequestAbsent,
                ),
            ));
        };
        Ok(crate::crypto::GenerationIdentity {
            id: &request.id,
            label: &request.label,
        })
    }

    fn generation_mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        let ClassicalPairInput::Generation { request, .. } = &self.input else {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::ClassicalCreationRequestAbsent,
                ),
            ));
        };
        Ok(request.algorithm.generation())
    }

    fn generation_templates_as<T: crate::attributes::TemplateSink>(
        &self,
    ) -> Result<(T, Option<T>)> {
        let ClassicalPairInput::Generation { request, .. } = &self.input else {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::ClassicalCreationRequestAbsent,
                ),
            ));
        };
        let (public, private) = super::super::generation_templates_as(request, self.semantics)?;
        Ok((public, Some(private)))
    }
}

impl crate::crypto::KeyAdmissionDescription for ClassicalPairPlan<'_> {
    fn is_pair(&self) -> bool {
        true
    }

    fn admission_id(&self) -> &[u8] {
        match &self.input {
            ClassicalPairInput::Existing { id, .. } => id,
            ClassicalPairInput::Generation { request, .. } => &request.id,
        }
    }

    fn admission_class(&self) -> crate::ManagedClass {
        crate::ManagedClass::PublicKey
    }

    fn object_observation(&self, private: bool) -> &crate::ObjectAdmission {
        match &self.input {
            ClassicalPairInput::Existing {
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
            ClassicalPairInput::Generation { request, .. } => {
                if private {
                    &request.private_admission
                } else {
                    &request.public_admission
                }
            }
        }
    }

    fn history_observation(&self, private: bool) -> Option<crate::HistoryObservationPlan> {
        if private {
            self.publication.history_plan()
        } else {
            None
        }
    }

    fn mechanism_observation(&self, private: bool) -> &crate::MechanismObservationPlan {
        if !private {
            return &self.public_mechanisms;
        }
        match &self.input {
            ClassicalPairInput::Existing { mechanisms, .. } => mechanisms,
            ClassicalPairInput::Generation { request, .. } => &request.mechanisms,
        }
    }

    fn visit_required(&self, private: bool, field: &mut dyn FnMut(CK_ATTRIBUTE_TYPE)) {
        let algorithm = match &self.input {
            ClassicalPairInput::Existing { algorithm, .. } => *algorithm,
            ClassicalPairInput::Generation { request, .. } => request.algorithm,
        };
        classical_field_iter(
            algorithm,
            private,
            self.publication.is_transport(),
            self.publication.is_rsa_transport(),
        )
        .for_each(field);
    }

    fn visit_material(&self, _private: bool, _field: &mut dyn FnMut(CK_ATTRIBUTE_TYPE)) {}
}
