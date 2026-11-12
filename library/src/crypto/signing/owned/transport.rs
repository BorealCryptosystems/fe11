// SPDX-License-Identifier: Apache-2.0
//! Transport publication from the retained native observations.
use super::*;
use crate::{
    BaseProtection, HistoryObservationPlan, SigningIntroductionSpec, TransportSigningKeyPair,
};

pub(super) enum Publication {
    Ordinary,
    Transport(TransportPublication),
}

impl Publication {
    pub(super) fn is_rsa_transport(&self) -> bool {
        matches!(self, Publication::Transport(p) if matches!(p.destination, Destination::RsaKek))
    }
    pub(super) fn is_transport(&self) -> bool {
        matches!(self, Publication::Transport(_))
    }
    pub(super) fn history_plan(&self) -> Option<crate::HistoryObservationPlan> {
        match self {
            Publication::Ordinary => None,
            Publication::Transport(publication) => Some(publication.history),
        }
    }
}

#[derive(Clone, Copy)]
enum Destination {
    Signing,
    RsaKek,
}

pub(super) struct TransportPublication {
    destination: Destination,
    history: HistoryObservationPlan,
    observed: Option<BaseProtection>,
}

/// Result material transferred together after native observation completes.
struct TransportMaterial {
    public: crate::crypto::integer_key::PublicDer,
    private: crate::crypto::integer_key::PublicDer,
    profiles: Vec<SignatureProfile>,
}

impl ClassicalPairPlan<'_> {
    pub(crate) fn generating_transport(
        spec: SigningIntroductionSpec,
        public_mechanisms: crate::MechanismObservationPlan,
        semantics: crate::EdwardsOptions,
    ) -> Result<Self> {
        let SigningIntroductionSpec {
            key,

            history_observation,
        } = spec;
        let mut plan = Self::generating(key, public_mechanisms, semantics, 0)?;
        plan.publication = Publication::Transport(TransportPublication {
            destination: Destination::Signing,
            history: history_observation,
            observed: None,
        });
        Ok(plan)
    }

    pub(crate) fn generating_rsa_transport(
        spec: crate::RsaKeyEncryptionSpec,
        public_mechanisms: crate::MechanismObservationPlan,
        private_mechanisms: crate::MechanismObservationPlan,
        semantics: crate::EdwardsOptions,
    ) -> Result<Self> {
        spec.validate()?;
        let crate::RsaKeyEncryptionSpec {
            public_exponent,
            native_protection,
            public_visibility,
            private_visibility,
            public_usages,
            private_usages,
            history_observation,
            public_admission,
            private_admission,
            bits,
            id,
            label,
            persistent,
        } = spec;
        let key = ClassicalKeySpec {
            rsa_public_exponent: public_exponent,
            private_protection: native_protection,
            public_visibility,
            private_visibility,
            public_usages,
            private_usages,
            public_admission,
            private_admission,
            mechanisms: private_mechanisms,
            algorithm: ClassicalKeyAlgorithm::Rsa { bits },
            id,
            label,
            persistent,
            profiles: Vec::new(),
        };
        let mut plan = Self::generating_transport(
            SigningIntroductionSpec {
                key,

                history_observation,
            },
            public_mechanisms,
            semantics,
        )?;
        if let Publication::Transport(publication) = &mut plan.publication {
            publication.destination = Destination::RsaKek;
        }
        Ok(plan)
    }
}

impl PreparedClassicalPair {
    pub(crate) fn is_rsa_transport(&self) -> bool {
        self.publication.is_rsa_transport()
    }

    pub(crate) fn is_transport(&self) -> bool {
        self.publication.is_transport()
    }

    pub(crate) fn history_plan(&self) -> Option<crate::HistoryObservationPlan> {
        self.publication.history_plan()
    }

    pub(crate) fn observe_history(&mut self, snapshot: BaseProtection) -> Result<()> {
        let Publication::Transport(publication) = &mut self.publication else {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::ClassicalHistoryOwnerAbsent,
                ),
            ));
        };

        crate::transport::secret_keys::report(snapshot, crate::IntroductionOrigin::Generated)?;
        publication.observed = Some(snapshot);
        Ok(())
    }

    fn prepare_transport_report(&self) -> Result<crate::IntroductionReport> {
        let Publication::Transport(publication) = &self.publication else {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::TransportPublicationAbsent,
                ),
            ));
        };

        crate::transport::secret_keys::report(
            publication.observed.ok_or(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::TransportHistoryAbsent,
                ),
            ))?,
            crate::IntroductionOrigin::Generated,
        )
    }

    fn commit_transport_result(&mut self) -> Result<TransportMaterial> {
        let Publication::Transport(_) = &mut self.publication else {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::TransportHistoryOwnerAbsent,
                ),
            ));
        };
        let PairSource::Generation {
            request,
            public: GeneratedPublic::Observed(material),
        } = &mut self.source
        else {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::ClassicalPublicObservationsAbsent,
                ),
            ));
        };
        if material.transport.is_none() {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::TransportPublicationAbsent,
                ),
            ));
        }
        // DER owners remain resident through fallible observation. Transfer both
        // publications together once their presence has been established.
        let (public, private) = material
            .transport
            .take()
            .expect("validated transport publication material");
        Ok(TransportMaterial {
            public,
            private,
            profiles: std::mem::take(&mut request.profiles),
        })
    }

    pub(crate) fn finish_rsa_transport(
        &mut self,
        public: ManagedObjectRef,
        private: ManagedObjectRef,
        public_allowed: crate::MechanismObservationReport,
        private_allowed: crate::MechanismObservationReport,
    ) -> Result<crate::RsaKeyEncryptionPair> {
        if !self.is_rsa_transport() {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::RsaTransportResultOwnerMismatch,
            )));
        }
        let ClassicalKeyAlgorithm::Rsa { .. } = self.algorithm() else {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::RsaTransportAlgorithm,
                ),
            ));
        };
        let report = self.prepare_transport_report()?;
        let material = self.commit_transport_result()?;
        Ok(crate::RsaKeyEncryptionPair::from_parts(
            crate::RsaKeyEncryptionPublic::from_parts(
                public,
                material.public.into_bytes(),
                public_allowed,
            ),
            crate::RsaKeyEncryptionPrivate::from_parts(
                private,
                material.private.into_bytes(),
                private_allowed,
                report,
            ),
        ))
    }

    pub(crate) fn finish_transport(
        &mut self,
        public: ManagedObjectRef,
        private: ManagedObjectRef,
        public_allowed: crate::MechanismObservationReport,
        private_allowed: crate::MechanismObservationReport,
    ) -> Result<TransportSigningKeyPair> {
        match &self.publication {
            Publication::Transport(TransportPublication {
                destination: Destination::Signing,
                ..
            }) => (),
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::TransportSigningResultOwnerMismatch,
                )))
            }
        };
        let algorithm = self.algorithm();
        let fingerprint = Sha256::digest(&self.public_material()?.spki).into();
        let report = self.prepare_transport_report()?;
        let material = self.commit_transport_result()?;
        let profile_credit = self.signing_profile_credit.take().ok_or(Error::Rejected(
            crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::SigningProfilesAlreadyPublished,
            ),
        ))?;
        let private = SigningKey {
            edwards_encoding: self.edwards_encoding_report(true),
            managed: private,
            algorithm,
            fingerprint,
            _profiles: material.profiles,
            mechanism_report: private_allowed,
            _profiles_credit: profile_credit,
        };
        Ok(TransportSigningKeyPair {
            public_edwards_encoding: self.edwards_encoding_report(false),
            public_mechanism_report: public_allowed,
            private: super::super::introduced::from_signing_key(
                private,
                material.private.into_bytes(),
                report,
            ),
            public,
            public_der: material.public.into_bytes(),
        })
    }
}
