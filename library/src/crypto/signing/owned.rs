// SPDX-License-Identifier: Apache-2.0
//! Prepared pair templates and native public observations, without synchronous calls.
use super::*;

use crate::symmetric::memory::Credit;

mod transport;
use transport::Publication;
pub(crate) struct PreparedClassicalPair {
    source: PairSource,
    verification_profiles: Vec<VerificationProfile>,
    publication: Publication,
    semantics: crate::EdwardsOptions,
    pub(crate) public_mechanisms: crate::MechanismObservationPlan,
    // Split during preparation; each published key retains its own allocation.
    signing_profile_credit: Option<Credit>,
    verification_profile_credit: Option<Credit>,
    _credit: Credit,
}

/// Map the caller's signature profiles once, before native publication.
fn verification_profile(profile: &SignatureProfile) -> VerificationProfile {
    match profile {
        SignatureProfile::RsaPkcs1(h) => VerificationProfile::RsaPkcs1(*h),
        SignatureProfile::RsaPss(p) => VerificationProfile::RsaPss(*p),
        SignatureProfile::Ecdsa(h) => VerificationProfile::Ecdsa(*h),
        SignatureProfile::Ed25519 => VerificationProfile::Ed25519,
        SignatureProfile::Ed448 => VerificationProfile::Ed448,
        SignatureProfile::EdDsa(p) => VerificationProfile::EdDsa(*p),
    }
}

fn profile_bytes(count: usize) -> Result<usize> {
    count
        .checked_mul(std::mem::size_of::<VerificationProfile>())
        .ok_or(Error::Rejected(
            crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::ClassicalProfileCapacityOverflow,
            ),
        ))
}

fn profile_storage(count: usize) -> Result<Vec<VerificationProfile>> {
    let mut profiles = Vec::new();
    profiles.try_reserve_exact(count).map_err(|_| {
        Error::Rejected(crate::RejectionReason::ClassicalSignatures(
            crate::ClassicalSignaturesRejection::ClassicalProfileAllocation,
        ))
    })?;
    Ok(profiles)
}

struct ExistingPairIdentity {
    algorithm: ClassicalKeyAlgorithm,
    id: Vec<u8>,
    profiles: Vec<SignatureProfile>,
    mechanisms: crate::MechanismObservationPlan,
    public_admission: crate::ObjectAdmission,
    private_admission: crate::ObjectAdmission,
}

struct ClassicalPublicMaterial {
    algorithm: ClassicalKeyAlgorithm,
    spki: crate::crypto::integer_key::PublicDer,
    transport: Option<(
        crate::crypto::integer_key::PublicDer,
        crate::crypto::integer_key::PublicDer,
    )>,
}
impl ClassicalPublicMaterial {
    fn new(
        spki: crate::crypto::integer_key::PublicDer,
        algorithm: ClassicalKeyAlgorithm,
    ) -> Result<Self> {
        let observed = classical_public_algorithm(&spki)?;
        // The view must use the observed representation. RSA size is metadata,
        // not a postcondition imposed on the provider's generation request.
        if !matches!(
            (algorithm, observed),
            (
                ClassicalKeyAlgorithm::Rsa { .. },
                ClassicalKeyAlgorithm::Rsa { .. }
            )
        ) && observed != algorithm
        {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::ClassicalPublicRepresentationMismatch,
                ),
            ));
        }
        Ok(Self {
            algorithm: observed,
            spki,
            transport: None,
        })
    }
}

enum GeneratedPublic {
    AwaitingObservation,
    Preparing(crate::crypto::integer_key::PublicDerNeed),
    Prepared(crate::crypto::integer_key::PublicDerCandidate),
    Observed(ClassicalPublicMaterial),
}

enum PairSource {
    Existing {
        identity: ExistingPairIdentity,
        public: ClassicalPublicMaterial,
    },
    Generation {
        request: ClassicalKeySpec,
        public: GeneratedPublic,
    },
}

/// Initial input only: selection borrows its identity/SPKI/profiles;
/// generation owns only the request already transferred by the caller.
enum ClassicalPairInput<'a> {
    Existing {
        id: &'a [u8],
        spki: &'a [u8],
        profiles: &'a [SignatureProfile],
        algorithm: ClassicalKeyAlgorithm,
        mechanisms: crate::MechanismObservationPlan,
        public_admission: crate::ObjectAdmission,
        private_admission: crate::ObjectAdmission,
    },
    Generation {
        request: ClassicalKeySpec,
        extra: usize,
    },
}

pub(crate) struct ClassicalPairPlan<'a> {
    input: ClassicalPairInput<'a>,
    publication: Publication,
    semantics: crate::EdwardsOptions,
    public_mechanisms: crate::MechanismObservationPlan,
}

/// Candidate-only allocations. A capacity retry drops this whole value before
/// waiting again; no copied selection or public DER survives in the plan.
pub(crate) enum ClassicalPairStorage {
    Existing {
        id: Vec<u8>,
        profiles: Vec<SignatureProfile>,
        verification_profiles: Vec<VerificationProfile>,
        spki: crate::crypto::integer_key::PublicDerStorage,
    },
    Generation {
        verification_profiles: Vec<VerificationProfile>,
    },
}

/// All fallible public-DER binding and vector filling has completed. The
/// caller's generation request and observation choices remain in the plan.
enum ClassicalBoundStorage {
    Existing {
        id: Vec<u8>,
        profiles: Vec<SignatureProfile>,
        verification_profiles: Vec<VerificationProfile>,
        spki: crate::crypto::integer_key::PublicDer,
    },
    Generation {
        verification_profiles: Vec<VerificationProfile>,
    },
}
pub(crate) struct ClassicalPairOwnerStorage {
    storage: ClassicalBoundStorage,
    signing_profile_credit: Credit,
    verification_profile_credit: Credit,
    credit: Credit,
}

fn classical_owner_bytes(parts: &[usize]) -> Result<usize> {
    parts.iter().try_fold(
        std::mem::size_of::<PreparedClassicalPair>(),
        |sum, bytes| {
            sum.checked_add(*bytes).ok_or(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::ClassicalPairOwnerSizeOverflow,
                ),
            ))
        },
    )
}

fn signature_profile_bytes(count: usize) -> Result<usize> {
    count
        .checked_mul(std::mem::size_of::<SignatureProfile>())
        .ok_or(Error::Rejected(
            crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::ClassicalProfileCapacityOverflow,
            ),
        ))
}

// Initial plans and installed owners enumerate the same structural fields.
fn classical_field_iter(
    algorithm: ClassicalKeyAlgorithm,
    private: bool,
    transport: bool,
    rsa_transport: bool,
) -> impl Iterator<Item = CK_ATTRIBUTE_TYPE> {
    let (fields, count) = identity_fields(
        if private {
            CKO_PRIVATE_KEY
        } else {
            CKO_PUBLIC_KEY
        },
        algorithm,
    );
    let extra = if !private {
        Some(match algorithm {
            ClassicalKeyAlgorithm::Rsa { .. } => CKA_MODULUS,
            _ => CKA_EC_POINT,
        })
    } else if transport && matches!(algorithm, ClassicalKeyAlgorithm::Rsa { .. }) {
        // Public components on a private transport key; no private integer.
        Some(CKA_MODULUS)
    } else {
        None
    };
    fields
        .into_iter()
        .take(count)
        .filter(move |field| !rsa_transport || *field != CKA_MODULUS_BITS)
        .chain(extra)
}

impl PreparedClassicalPair {
    pub(crate) fn id(&self) -> &[u8] {
        match &self.source {
            PairSource::Existing { identity, .. } => &identity.id,
            PairSource::Generation { request, .. } => &request.id,
        }
    }
    fn algorithm(&self) -> ClassicalKeyAlgorithm {
        match &self.source {
            PairSource::Existing { identity, .. } => identity.algorithm,
            PairSource::Generation {
                public: GeneratedPublic::Observed(public),
                ..
            } => public.algorithm,
            PairSource::Generation { request, .. } => request.algorithm,
        }
    }
    pub(crate) fn mechanisms(&self) -> &crate::MechanismObservationPlan {
        match &self.source {
            PairSource::Existing { identity, .. } => &identity.mechanisms,
            PairSource::Generation { request, .. } => &request.mechanisms,
        }
    }
    pub(crate) fn public_admission(&self) -> &crate::ObjectAdmission {
        match &self.source {
            PairSource::Existing { identity, .. } => &identity.public_admission,
            PairSource::Generation { request, .. } => &request.public_admission,
        }
    }
    pub(crate) fn private_admission(&self) -> &crate::ObjectAdmission {
        match &self.source {
            PairSource::Existing { identity, .. } => &identity.private_admission,
            PairSource::Generation { request, .. } => &request.private_admission,
        }
    }
    pub(crate) fn generation_request(&self) -> Result<&ClassicalKeySpec> {
        match &self.source {
            PairSource::Generation { request, .. } => Ok(request),
            PairSource::Existing { .. } => Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::ClassicalCreationRequestAbsent,
                ),
            )),
        }
    }
    fn public_material(&self) -> Result<&ClassicalPublicMaterial> {
        match &self.source {
            PairSource::Existing { public, .. }
            | PairSource::Generation {
                public: GeneratedPublic::Observed(public),
                ..
            } => Ok(public),
            PairSource::Generation {
                public:
                    GeneratedPublic::AwaitingObservation
                    | GeneratedPublic::Preparing(_)
                    | GeneratedPublic::Prepared(_),
                ..
            } => Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::ClassicalPublicObservationsAbsent,
                ),
            )),
        }
    }

    pub(crate) fn generation_templates_as<T: crate::attributes::TemplateSink>(
        &self,
    ) -> Result<(T, T)> {
        super::generation_templates_as(self.generation_request()?, self.semantics)
    }
    pub(crate) fn key_type(&self) -> CK_KEY_TYPE {
        self.algorithm().key_type()
    }
    pub(crate) fn generation_mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.generation_request()?.algorithm.generation())
    }

    pub(crate) fn field_iter(&self, private: bool) -> impl Iterator<Item = CK_ATTRIBUTE_TYPE> {
        classical_field_iter(
            self.algorithm(),
            private,
            self.is_transport(),
            self.is_rsa_transport(),
        )
    }
    fn validate_identity(
        &self,
        values: &attributes::RequiredAttributes,
        private: bool,
    ) -> Result<()> {
        let class = if private {
            CKO_PRIVATE_KEY
        } else {
            CKO_PUBLIC_KEY
        };
        if self.is_rsa_transport() {
            values.integer(CKA_CLASS, class)?;
            values.integer(CKA_KEY_TYPE, CKK_RSA)
        } else {
            validate_identity_fields(values, class, self.algorithm(), self.semantics)
        }
    }
    /// Describe storage for the completed observation without retaining its
    /// borrowed recipe in a waiter. RequiredAttributes remain with Admission.
    pub(crate) fn prepare_observation(
        &mut self,
        private: bool,
        values: &attributes::RequiredAttributes,
    ) -> Result<()> {
        if private {
            return Ok(());
        }
        if matches!(
            &self.source,
            PairSource::Generation {
                public: GeneratedPublic::AwaitingObservation,
                ..
            }
        ) {
            self.validate_identity(values, false)?;
            let encoding =
                public_encoding::PublicEncoding::new(values, self.algorithm(), self.semantics)?;
            let need = crate::crypto::integer_key::PublicDerNeed::new(
                encoding.length()?,
                self.is_transport(),
            );
            if let PairSource::Generation { public, .. } = &mut self.source {
                *public = GeneratedPublic::Preparing(need);
            }
        }
        Ok(())
    }

    pub(crate) fn observation_need(&self) -> Option<crate::crypto::integer_key::PublicDerNeed> {
        match &self.source {
            PairSource::Generation {
                public: GeneratedPublic::Preparing(length),
                ..
            } => Some(*length),
            _ => None,
        }
    }

    pub(crate) fn attach_observation(
        &mut self,
        candidate: crate::crypto::integer_key::PublicDerCandidate,
    ) -> Result<()> {
        if self.observation_need() != Some(candidate.need()) {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AdmissionPreparationChanged,
            )));
        }
        if let PairSource::Generation { public, .. } = &mut self.source {
            *public = GeneratedPublic::Prepared(candidate);
        }
        Ok(())
    }

    pub(crate) fn validate(
        &mut self,
        private: bool,
        values: &attributes::RequiredAttributes,
    ) -> Result<()> {
        if !private && matches!(&self.source, PairSource::Generation { .. }) {
            self.validate_identity(values, false)?;
            let encoding =
                public_encoding::PublicEncoding::new(values, self.algorithm(), self.semantics)?;
            let PairSource::Generation { public, .. } = &mut self.source else {
                return Err(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::ClassicalPublicObservationsAbsent,
                    ),
                ));
            };
            let GeneratedPublic::Prepared(candidate) =
                std::mem::replace(public, GeneratedPublic::AwaitingObservation)
            else {
                return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::AdmissionPreparationChanged,
                )));
            };
            let material = candidate.encode(&encoding)?;
            let mut observed = ClassicalPublicMaterial::new(material.primary, self.algorithm())?;
            observed.transport = material.transport;
            // Both generations remain charged during replacement. The old
            // payload drops before its credit, including on failure/unwind.
            if let PairSource::Generation { public, .. } = &mut self.source {
                *public = GeneratedPublic::Observed(observed);
            }
        }
        self.validate_identity(values, private)?;
        Ok(())
    }

    /// Called after the required attribute decoding has completed. Both routes
    /// check EC_PARAMS, but only generation decodes the native public EC_POINT;
    /// an existing pair retains the caller's public declaration independently.
    fn edwards_encoding_report(&self, private: bool) -> Option<crate::EdwardsEncodingReport> {
        self.algorithm().edwards_curve().map(|_| {
            if private || matches!(&self.source, PairSource::Existing { .. }) {
                crate::EdwardsEncodingReport::parameters_only(self.semantics.parameter_encoding)
            } else {
                crate::EdwardsEncodingReport::public(
                    self.semantics.parameter_encoding,
                    self.semantics.point_encoding,
                )
            }
        })
    }

    fn finish_private(
        &mut self,
        private: ManagedObjectRef,
        allowed: crate::MechanismObservationReport,
    ) -> Result<SigningKey> {
        let algorithm = self.algorithm();
        let fingerprint = Sha256::digest(&self.public_material()?.spki).into();
        let profile_credit = self.signing_profile_credit.take().ok_or(Error::Rejected(
            crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::SigningProfilesAlreadyPublished,
            ),
        ))?;
        let profiles = match &mut self.source {
            PairSource::Existing { identity, .. } => std::mem::take(&mut identity.profiles),
            PairSource::Generation { request, .. } => std::mem::take(&mut request.profiles),
        };
        Ok(SigningKey {
            edwards_encoding: self.edwards_encoding_report(true),
            managed: private,
            algorithm,
            fingerprint,
            _profiles: profiles,
            mechanism_report: allowed,
            _profiles_credit: profile_credit,
        })
    }

    pub(crate) fn finish(
        &mut self,
        public: ManagedObjectRef,
        private: ManagedObjectRef,
        public_allowed: crate::MechanismObservationReport,
        private_allowed: crate::MechanismObservationReport,
    ) -> Result<ClassicalKeyPair> {
        let material = self.public_material()?;
        let fingerprint: [u8; 32] = Sha256::digest(&material.spki).into();
        let rsa = match self.algorithm() {
            ClassicalKeyAlgorithm::Rsa { bits } => Some(super::super::verification::RsaMetadata {
                bits,
                exponent_class: super::super::integer_key::rsa_der(&material.spki)?.exponent_class,
            }),
            _ => None,
        };
        let private = self.finish_private(private, private_allowed)?;
        let material = match &mut self.source {
            PairSource::Existing { public, .. }
            | PairSource::Generation {
                public: GeneratedPublic::Observed(public),
                ..
            } => public,
            _ => {
                return Err(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::ClassicalPublicObservationsAbsent,
                    ),
                ))
            }
        };
        let profile_credit = self
            .verification_profile_credit
            .take()
            .ok_or(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::VerificationProfilesAlreadyPublished,
                ),
            ))?;
        let public_der = material.spki.take_bytes();
        let profiles = std::mem::take(&mut self.verification_profiles);
        Ok(ClassicalKeyPair {
            public: VerificationKey {
                _import_credit: Some(profile_credit),
                edwards_encoding: self.edwards_encoding_report(false),
                edwards: match self.algorithm() {
                    ClassicalKeyAlgorithm::Ed25519 => {
                        Some(super::super::public_key::EdwardsCurve::Ed25519)
                    }
                    ClassicalKeyAlgorithm::Ed448 => {
                        Some(super::super::public_key::EdwardsCurve::Ed448)
                    }
                    _ => None,
                },
                managed: public,
                fingerprint,
                profiles,
                mechanism_report: public_allowed,
                curve: self.algorithm().curve(),
                dsa: None,
                rsa,
            },
            private,
            public_der,
        })
    }
}

mod preparation;
