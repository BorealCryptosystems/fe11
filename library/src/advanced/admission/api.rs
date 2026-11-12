// SPDX-License-Identifier: Apache-2.0
//! Start key generation or discovery with caller-selected observations.
//! Preparation transfers the request to the admission owner before native progression.

use super::*;

impl AdvancedSession {
    /// Generate a dedicated AES KEK; poll for `CreatedObjects`.
    /// Its separate observation yields `GeneratedObjects::AesKeyEncryptionKey`.
    /// Retain the created objects even when that observation fails.
    /// Convenience views and native usage attributes are independent choices.
    pub fn generate_aes_key_encryption_key(
        &self,
        spec: crate::AesKeyEncryptionSpec,
    ) -> Result<OperationTicket> {
        self.start_key_admission(
            input::Input::Symmetric(Some(input::SymmetricInput::aes_kek(spec)?)),
            true,
        )
    }

    /// Select an existing AES KEK without creating a witness object.
    /// Poll for AesKeyEncryptionKey with its actual observed provenance.
    pub fn find_aes_key_encryption_key(
        &self,
        spec: crate::AesKeyEncryptionSpec,
    ) -> Result<OperationTicket> {
        self.start_key_admission(
            input::Input::Symmetric(Some(input::SymmetricInput::aes_kek(spec)?)),
            false,
        )
    }

    /// Generate a native symmetric key with an explicit introduction request.
    /// Poll for `CreatedObjects`, whose separate observation yields
    /// `GeneratedObjects::IntroducedSymmetricKey`. Retain the objects even if
    /// observation fails. The export view does not change native extractability.
    pub fn generate_transport_symmetric_key(
        &self,
        spec: crate::SymmetricIntroductionSpec,
    ) -> Result<OperationTicket> {
        self.start_key_admission(
            input::Input::Symmetric(Some(input::SymmetricInput::introduced_symmetric(spec)?)),
            true,
        )
    }

    /// Select an existing symmetric key and preserve its observed provenance.
    /// Poll for IntroducedSymmetricKey; selection performs no key creation.
    pub fn find_introduced_symmetric_key(
        &self,
        spec: crate::SymmetricIntroductionSpec,
    ) -> Result<OperationTicket> {
        self.start_key_admission(
            input::Input::Symmetric(Some(input::SymmetricInput::introduced_symmetric(spec)?)),
            false,
        )
    }

    /// Start admission of one existing protected native key in this session.
    /// Poll its ticket for SymmetricKey; no creation, export or fallback occurs.
    pub fn find_symmetric_key(&self, spec: SymmetricKeySpec) -> Result<OperationTicket> {
        self.start_symmetric_admission(spec)
    }

    /// Admit an existing AES key against the explicitly requested mechanisms.
    /// The key's protections and permissions are observed without alteration.
    pub fn find_aes_key(&self, spec: SymmetricKeySpec) -> Result<OperationTicket> {
        if !matches!(
            spec.algorithm,
            crate::SymmetricAlgorithm::Aes128
                | crate::SymmetricAlgorithm::Aes192
                | crate::SymmetricAlgorithm::Aes256
        ) {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AesKeyRequired,
            )));
        }
        self.start_symmetric_admission(spec)
    }

    pub(super) fn start_symmetric_admission(
        &self,
        spec: SymmetricKeySpec,
    ) -> Result<OperationTicket> {
        spec.validate()?;
        self.start_key_admission(input::Input::symmetric(spec, Publication::Ordinary), false)
    }

    /// Resolve an existing RSA, DSA, Weierstrass or Edwards public key by ID
    /// and canonical SPKI, sharing the synchronous selector's observations.
    /// No login, private counterpart or key creation is required.
    pub fn find_classical_verification_key(
        &self,
        id: &[u8],
        expected_spki: &[u8],
        profiles: &[crate::VerificationProfile],
        mechanisms: crate::MechanismObservationPlan,
        object_admission: crate::ObjectAdmission,
    ) -> Result<OperationTicket> {
        // Borrowed validation precedes the common resource preparation.
        let prepared = crate::crypto::VerificationPlan::selected(
            id,
            expected_spki,
            profiles,
            mechanisms,
            object_admission,
            self.session.inner.crypto_options.edwards,
        )?;
        self.start_key_admission(input::Input::Verification(Some(prepared)), false)
    }

    /// Admit an existing RSA, ECDSA or pure Edwards pair against its canonical SPKI.
    /// Poll for `ClassicalKeyPair` after the caller-selected observations complete.
    /// Observations match `Session::find_classical_key_pair`; no signature,
    /// hashing route or proof of possession is performed by this admission.
    pub fn find_classical_key_pair(
        &self,
        id: &[u8],
        expected_spki: &[u8],
        profiles: &[crate::SignatureProfile],

        mechanisms: crate::MechanismObservationPlan,
        public_mechanisms: crate::MechanismObservationPlan,
        public_admission: crate::ObjectAdmission,
        private_admission: crate::ObjectAdmission,
    ) -> Result<OperationTicket> {
        let prepared = crate::crypto::ClassicalPairPlan::selected(
            id,
            expected_spki,
            profiles,
            mechanisms,
            public_mechanisms,
            public_admission,
            private_admission,
            self.session.inner.crypto_options.edwards,
        )?;
        self.start_key_admission(input::Input::Classical(Some(prepared)), false)
    }

    /// Generate an RSA, ECDSA or pure Edwards pair using the synchronous templates.
    /// Poll for `CreatedObjects` containing the pair and its separate observation
    /// outcome. No challenge is signed and no private key value is read. Published
    /// objects remain owned even if a requested observation subsequently fails.
    pub fn generate_classical_key_pair(
        &self,
        spec: crate::ClassicalKeySpec,

        public_mechanisms: crate::MechanismObservationPlan,
    ) -> Result<OperationTicket> {
        let prepared = crate::crypto::ClassicalPairPlan::generating(
            spec,
            public_mechanisms,
            self.session.inner.crypto_options.edwards,
            0,
        )?;
        self.start_key_admission(input::Input::Classical(Some(prepared)), true)
    }

    /// Generate an RSA wrapping/unwrapping pair without a signature witness.
    /// Poll for `CreatedObjects` containing the pair and its separate observation
    /// outcome; a requested observation failure does not destroy published objects.
    pub fn generate_rsa_key_encryption_pair(
        &self,
        spec: crate::RsaKeyEncryptionSpec,
        public_mechanisms: crate::MechanismObservationPlan,
        private_mechanisms: crate::MechanismObservationPlan,
    ) -> Result<OperationTicket> {
        let prepared = crate::crypto::ClassicalPairPlan::generating_rsa_transport(
            spec,
            public_mechanisms,
            private_mechanisms,
            self.session.inner.crypto_options.edwards,
        )?;
        self.start_key_admission(input::Input::Classical(Some(prepared)), true)
    }

    /// Generate a transport signing pair through the shared classical owner.
    /// Poll for `CreatedObjects` containing the pair and its separate observation
    /// outcome. No challenge signature or proof of possession is performed.
    /// Published objects remain owned after a requested observation failure.
    pub fn generate_transport_signing_key_pair(
        &self,
        spec: crate::SigningIntroductionSpec,

        public_mechanisms: crate::MechanismObservationPlan,
    ) -> Result<OperationTicket> {
        let prepared = crate::crypto::ClassicalPairPlan::generating_transport(
            spec,
            public_mechanisms,
            self.session.inner.crypto_options.edwards,
        )?;
        self.start_key_admission(input::Input::Classical(Some(prepared)), true)
    }

    /// Generate an ML-KEM pair with explicit native templates and selected observations.
    /// Poll for `CreatedObjects` containing the pair. Public material is read after
    /// observing its public object identity. No signature, encapsulation or private
    /// value export is used as an implicit generation condition. The separate
    /// observation outcome does not destroy the published objects on refusal.
    pub fn generate_kem_key_pair(
        &self,
        spec: crate::KemKeySpec,
        public_policy: crate::MechanismAttributes<'_>,
        private_policy: crate::MechanismAttributes<'_>,
        protection: crate::CurrentKeyProtection,
        public_visibility: crate::ObjectVisibility,
    ) -> Result<OperationTicket> {
        let prepared = crate::crypto::kem::KemOwnerPlan::generating(
            spec,
            public_policy,
            private_policy,
            protection,
            public_visibility,
        )?;
        self.start_key_admission(input::Input::Kem(Some(prepared)), true)
    }

    /// Select existing ML-KEM objects by ID and the supplied SPKI's parameter set.
    /// Returned public material comes from observation, without comparing it to
    /// the supplied declaration.
    /// Poll for `OperationProgress::KemKeyPair`. This performs no private
    /// possession proof or implicit encapsulation. A refusal never destroys
    /// existing objects; public and private observations remain independent.
    pub fn find_kem_key_pair(
        &self,
        id: &[u8],
        expected_spki: &[u8],
        public_policy: crate::MechanismObservationPlan,
        private_policy: crate::MechanismObservationPlan,
        public_admission: crate::ObjectAdmission,
        private_admission: crate::ObjectAdmission,
    ) -> Result<OperationTicket> {
        let prepared = crate::crypto::kem::KemOwnerPlan::selected(
            id,
            expected_spki,
            public_policy,
            private_policy,
            public_admission,
            private_admission,
        )?;
        self.start_key_admission(input::Input::Kem(Some(prepared)), false)
    }

    /// Select existing PQC objects and retain the supplied public declaration.
    /// No private/public comparison, challenge signature or proof is performed.
    /// Requested native observations remain independent. Poll for the pair result;
    /// a refusal never destroys the existing objects.
    pub fn find_pqc_key_pair(
        &self,
        id: &[u8],
        expected_spki: &[u8],

        public_policy: crate::MechanismObservationPlan,
        private_policy: crate::MechanismObservationPlan,
        public_admission: crate::ObjectAdmission,
        private_admission: crate::ObjectAdmission,
    ) -> Result<OperationTicket> {
        let prepared = crate::crypto::pqc::PqcOwnerPlan::selected(
            id,
            expected_spki,
            public_policy,
            private_policy,
            public_admission,
            private_admission,
        )?;
        self.start_key_admission(input::Input::Pqc(Some(prepared)), false)
    }

    /// Generate a native PQC signature pair and perform the requested observations.
    /// No private value is read and no challenge is signed. The created references
    /// are published before optional observation; an observation failure retains
    /// both objects and any auxiliary output in the creation result.
    pub fn generate_pqc_key_pair(
        &self,
        spec: crate::PqcKeySpec,

        public_policy: crate::MechanismAttributes<'_>,
        private_policy: crate::MechanismAttributes<'_>,
        protection: crate::CurrentKeyProtection,
        public_visibility: crate::ObjectVisibility,
    ) -> Result<OperationTicket> {
        let prepared = crate::crypto::pqc::PqcOwnerPlan::generating(
            spec,
            public_policy,
            private_policy,
            protection,
            public_visibility,
        )?;
        self.start_key_admission(input::Input::Pqc(Some(prepared)), true)
    }

    /// Generate a Weierstrass agreement pair with the synchronous facade's
    /// exact templates and selected history observations. No possession probe.
    pub fn generate_agreement_key(
        &self,
        spec: crate::AgreementKeySpec,
        current: crate::CurrentKeyProtection,
        admission: crate::HistoryObservationPlan,
    ) -> Result<OperationTicket> {
        self.start_agreement_pair(
            crate::crypto::derivation::AgreementRequest::Weierstrass(spec),
            current,
            admission,
        )
    }

    /// Generate a Montgomery pair using the explicitly selected native domain.
    /// Poll for `CreatedObjects`, whose separate observation yields
    /// `GeneratedObjects::MontgomeryKeyPair`. Retain the objects even if
    /// observation fails; native public bytes are never DER-wrapped.
    pub fn generate_montgomery_key(
        &self,
        spec: crate::MontgomeryKeySpec,
        current: crate::CurrentKeyProtection,
        admission: crate::HistoryObservationPlan,
    ) -> Result<OperationTicket> {
        self.start_agreement_pair(
            crate::crypto::derivation::AgreementRequest::Montgomery(spec),
            current,
            admission,
        )
    }

    /// Generate an agreement pair retaining the caller's transport view and
    /// exact introduction/history evidence; no private possession probe.
    pub fn generate_transport_agreement_key(
        &self,
        spec: crate::AgreementIntroductionSpec,
    ) -> Result<OperationTicket> {
        let prepared = crate::crypto::derivation::AgreementPairPlan::transport(spec)?;
        self.start_key_admission(input::Input::Agreement(Some(prepared)), true)
    }

    pub(super) fn start_agreement_pair(
        &self,
        request: crate::crypto::derivation::AgreementRequest,
        current: crate::CurrentKeyProtection,
        admission: crate::HistoryObservationPlan,
    ) -> Result<OperationTicket> {
        let prepared =
            crate::crypto::derivation::AgreementPairPlan::new(request, current, admission)?;
        self.start_key_admission(input::Input::Agreement(Some(prepared)), true)
    }

    /// Select an existing Weierstrass derivation base; no public pair is inferred.
    pub fn find_agreement_key(
        &self,
        spec: crate::AgreementKeySpec,
        admission: crate::HistoryObservationPlan,
    ) -> Result<OperationTicket> {
        self.start_derivation_base(
            crate::crypto::derivation::DerivationBaseRequest::Agreement(spec),
            None,
            admission,
        )
    }

    /// Select an existing Montgomery derivation base with its exact native domain.
    pub fn find_montgomery_key(
        &self,
        spec: crate::MontgomeryKeySpec,
        admission: crate::HistoryObservationPlan,
    ) -> Result<OperationTicket> {
        self.start_derivation_base(
            crate::crypto::derivation::DerivationBaseRequest::Montgomery(spec),
            None,
            admission,
        )
    }

    /// Select an existing HKDF base with the explicitly supplied type and length.
    pub fn find_hkdf_key(
        &self,
        spec: crate::HkdfKeySpec,
        admission: crate::HistoryObservationPlan,
    ) -> Result<OperationTicket> {
        self.start_derivation_base(
            crate::crypto::derivation::DerivationBaseRequest::Hkdf(spec),
            None,
            admission,
        )
    }

    /// Generate one opaque HKDF base, preserving its Generic/Dedicated type.
    pub fn generate_hkdf_key(
        &self,
        spec: crate::HkdfKeySpec,
        current: crate::CurrentKeyProtection,
        admission: crate::HistoryObservationPlan,
    ) -> Result<OperationTicket> {
        self.start_derivation_base(
            crate::crypto::derivation::DerivationBaseRequest::Hkdf(spec),
            Some(current),
            admission,
        )
    }

    /// Select an existing agreement key with the caller's explicit transport view.
    /// No generation origin, public companion or private possession is inferred.
    pub fn find_introduced_agreement_key(
        &self,
        spec: crate::AgreementIntroductionSpec,
    ) -> Result<OperationTicket> {
        let prepared = crate::crypto::derivation::DerivationBasePlan::introduced_agreement(spec)?;
        self.start_key_admission(input::Input::Base(Some(prepared)), false)
    }

    pub(super) fn start_derivation_base(
        &self,
        request: crate::crypto::derivation::DerivationBaseRequest,
        generation: Option<crate::CurrentKeyProtection>,
        admission: crate::HistoryObservationPlan,
    ) -> Result<OperationTicket> {
        let prepared =
            crate::crypto::derivation::DerivationBasePlan::new(request, generation, admission)?;
        self.start_key_admission(input::Input::Base(Some(prepared)), generation.is_some())
    }

    pub(super) fn start_key_admission(
        &self,
        policy: input::Input<'_>,
        generate: bool,
    ) -> Result<OperationTicket> {
        let mut diagnostics = super::super::poll::PollDiagnostics::default();
        start_admission(
            &self.session,
            policy,
            generate,
            self.pacing,
            crate::session::ReferenceMode::Advanced,
            &mut diagnostics,
        )
    }
}
