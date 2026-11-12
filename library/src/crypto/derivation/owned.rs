// SPDX-License-Identifier: Apache-2.0
//! Agreement pair generation state shared by synchronous and advanced facades.
use super::*;
use crate::{attributes::RequiredAttributes, symmetric::memory::Credit};
use der::{
    asn1::{AnyRef, BitStringRef, ObjectIdentifier, OctetStringRef},
    Decode, Encode,
};
use x509_cert::spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};

pub(crate) enum AgreementRequest {
    Weierstrass(AgreementKeySpec),
    Montgomery(MontgomeryKeySpec),
    Transport(AgreementIntroductionSpec),
}
impl AgreementRequest {
    fn generation_mechanism(&self) -> CK_MECHANISM_TYPE {
        match self {
            AgreementRequest::Weierstrass(_) | AgreementRequest::Transport(_) => {
                CKM_EC_KEY_PAIR_GEN
            }
            AgreementRequest::Montgomery(_) => CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
        }
    }
    pub(crate) fn id(&self) -> &[u8] {
        match self {
            Self::Weierstrass(s) => &s.id,
            Self::Montgomery(s) => &s.id,
            Self::Transport(s) => &s.key.id,
        }
    }
    pub(crate) fn label(&self) -> &str {
        match self {
            Self::Weierstrass(s) => &s.label,
            Self::Montgomery(s) => &s.label,
            Self::Transport(s) => &s.key.label,
        }
    }
    pub(crate) fn persistent(&self) -> bool {
        match self {
            Self::Weierstrass(s) => s.persistent,
            Self::Montgomery(s) => s.persistent,
            Self::Transport(s) => s.key.persistent,
        }
    }
    fn admission(&self, private: bool) -> &crate::ObjectAdmission {
        match self {
            Self::Weierstrass(s) => {
                if private {
                    &s.private_admission
                } else {
                    &s.public_admission
                }
            }
            Self::Transport(s) => {
                if private {
                    &s.key.private_admission
                } else {
                    &s.key.public_admission
                }
            }
            Self::Montgomery(s) => {
                if private {
                    &s.private_admission
                } else {
                    &s.public_admission
                }
            }
        }
    }
    fn mechanisms(&self) -> &crate::MechanismObservationPlan {
        match self {
            Self::Weierstrass(s) => &s.mechanisms,
            Self::Montgomery(s) => &s.mechanisms,
            Self::Transport(s) => &s.key.mechanisms,
        }
    }
    fn key_type(&self) -> CK_KEY_TYPE {
        match self {
            Self::Weierstrass(_) | Self::Transport(_) => CKK_EC,
            Self::Montgomery(_) => CKK_EC_MONTGOMERY,
        }
    }
    fn parameters(&self) -> &'static [u8] {
        match self {
            Self::Weierstrass(s) => s.curve.curve().domain().oid_der,
            Self::Montgomery(s) => s.domain.parameters_der(),
            Self::Transport(s) => s.key.curve.curve().domain().oid_der,
        }
    }
    fn retained_bytes(&self) -> Result<usize> {
        let (id, label) = match self {
            Self::Weierstrass(s) => (&s.id, &s.label),
            Self::Montgomery(s) => (&s.id, &s.label),
            Self::Transport(s) => (&s.key.id, &s.key.label),
        };
        id.capacity()
            .checked_add(label.capacity())
            .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::AgreementRequestSize,
            )))
    }
    fn templates_as<T: crate::attributes::TemplateSink>(
        &self,
        protection: CurrentKeyProtection,
    ) -> Result<(T, T)> {
        let mut public = T::empty();
        public.integer(CKA_CLASS, CKO_PUBLIC_KEY);
        public.integer(CKA_KEY_TYPE, self.key_type());
        public.bytes(CKA_ID, self.id());
        public.bytes(CKA_LABEL, self.label().as_bytes());
        public.bytes(CKA_EC_PARAMS, self.parameters());
        public.boolean(CKA_TOKEN, self.persistent());
        let (visibility, usage, private) = match self {
            Self::Weierstrass(s) => (
                s.public_visibility,
                s.public_usages,
                keys::BaseSpec::Ec(s).template_as(protection)?,
            ),
            Self::Transport(s) => (
                s.key.public_visibility,
                s.key.public_usages,
                keys::BaseSpec::Ec(&s.key).template_as(protection)?,
            ),
            Self::Montgomery(s) => (
                s.public_visibility,
                s.public_usages,
                keys::BaseSpec::Montgomery(s).template_as(protection)?,
            ),
        };
        public.boolean(CKA_PRIVATE, visibility.is_private());
        usage.apply(&mut public);
        Ok((public, private))
    }
}
// The DER descriptor is shared by sizing and encoding. Its borrowed OID and
// point stay in this call; the callback cannot publish a native pointer.
fn with_weierstrass_spki<T>(
    curve: AgreementCurve,
    point: &[u8],
    encode: impl FnOnce(SubjectPublicKeyInfoRef<'_>) -> Result<T>,
) -> Result<T> {
    let oid = ObjectIdentifier::from_der(curve.curve().domain().oid_der).map_err(|_| {
        Error::Rejected(crate::RejectionReason::KeyDerivation(
            crate::KeyDerivationRejection::AgreementOid,
        ))
    })?;
    encode(SubjectPublicKeyInfoRef {
        algorithm: AlgorithmIdentifierRef {
            oid: ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
            parameters: Some(AnyRef::from(&oid)),
        },
        subject_public_key: BitStringRef::from_bytes(point).map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::AgreementPointBitString,
            ))
        })?,
    })
}

fn weierstrass_material_size(curve: AgreementCurve) -> Result<usize> {
    // The closed curve catalogue represents each coordinate in U576. Only
    // the selected width enters DER length calculation; these initialized
    // stack bytes are never treated as an observed key or passed to C.
    let sizing_point = [0u8; 1 + 2 * std::mem::size_of::<crypto_bigint::U576>()];
    let width = 1 + 2 * curve.curve().domain().width;
    let point =
        sizing_point
            .get(..width)
            .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::AgreementPublicSize,
            )))?;
    with_weierstrass_spki(curve, point, |spki| {
        usize::try_from(spki.encoded_len().map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::AgreementSpkiEncoding,
            ))
        })?)
        .map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::AgreementPublicSize,
            ))
        })
    })
}

fn observe_weierstrass(curve: AgreementCurve, raw: &[u8], output: &mut [u8]) -> Result<()> {
    let point = OctetStringRef::from_der(raw).map_err(|_| {
        Error::Rejected(crate::RejectionReason::KeyDerivation(
            crate::KeyDerivationRejection::AgreementNativePointDer,
        ))
    })?;
    if !super::super::canonical::matches(&point, raw).map_err(|_| {
        Error::Rejected(crate::RejectionReason::KeyDerivation(
            crate::KeyDerivationRejection::AgreementPointEncoding,
        ))
    })? {
        return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
            crate::KeyDerivationRejection::AgreementPointNoncanonical,
        )));
    }
    super::super::public_key::validate_weierstrass_encoding(curve.curve(), point.as_bytes())?;
    with_weierstrass_spki(curve, point.as_bytes(), |spki| {
        let expected = output.len();
        let encoded = spki.encode_to_slice(output).map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::AgreementSpkiEncoding,
            ))
        })?;
        if encoded.len() != expected {
            return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::AgreementPublicSize,
            )));
        }
        Ok(())
    })
}

enum PublicMaterial {
    Weierstrass(Vec<u8>),
    Montgomery(MontgomeryPublicKey),
}
impl PublicMaterial {
    fn planned_bytes(request: &AgreementRequest) -> Result<usize> {
        match request {
            AgreementRequest::Weierstrass(spec) => weierstrass_material_size(spec.curve),
            AgreementRequest::Transport(spec) => weierstrass_material_size(spec.key.curve),
            AgreementRequest::Montgomery(spec) => Ok(spec.domain.public_key_length()),
        }
    }
    fn allocate(request: &AgreementRequest, bytes: usize) -> Result<Self> {
        if let AgreementRequest::Montgomery(spec) = request {
            return MontgomeryPublicKey::observation_storage(spec.domain).map(Self::Montgomery);
        }
        let mut storage = Vec::new();
        storage.try_reserve_exact(bytes).map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::AgreementPublicAllocation,
            ))
        })?;
        storage.resize(bytes, 0);
        Ok(Self::Weierstrass(storage))
    }
    fn allocated(&self) -> usize {
        match self {
            Self::Weierstrass(bytes) => bytes.capacity(),
            Self::Montgomery(key) => key.retained_bytes(),
        }
    }
    fn observe(&mut self, request: &AgreementRequest, raw: &[u8]) -> Result<()> {
        match (self, request) {
            (Self::Weierstrass(bytes), AgreementRequest::Weierstrass(spec)) => {
                observe_weierstrass(spec.curve, raw, bytes)
            }
            (Self::Weierstrass(bytes), AgreementRequest::Transport(spec)) => {
                observe_weierstrass(spec.key.curve, raw, bytes)
            }
            (Self::Montgomery(key), AgreementRequest::Montgomery(_)) => key.observe_native(raw),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::AgreementPublicStorageFamily,
            ))),
        }
    }
}

enum PublicState {
    AwaitingIdentity(PublicMaterial),
    ReadPermitted(PublicMaterial),
    Observed(PublicMaterial),
    Published,
}
pub(crate) enum AgreementPairResult {
    Weierstrass(AgreementKeyPair),
    Montgomery(MontgomeryKeyPair),
    Transport(TransportAgreementKeyPair),
}
pub(crate) struct PreparedAgreementPair {
    // Ownership transfers into the private key exactly once at publication.
    // Other phase transitions never clear or replace the request.
    request: Option<AgreementRequest>,
    protection: CurrentKeyProtection,
    history: HistoryObservationPlan,
    history_observation: Option<BaseProtection>,
    public: PublicState,
    pub(crate) public_mechanisms: crate::MechanismObservationPlan,
    _credit: Credit,

}
/// An unadmitted agreement request. Only caller-transferred buffers and
/// scalar geometry survive an initial retry; observation storage does not.
pub(crate) struct AgreementPairPlan {
    request: AgreementRequest,
    protection: CurrentKeyProtection,
    history: HistoryObservationPlan,
    public_bytes: usize,
}

/// Empty public-observation storage for one candidate. It owns no native
/// handle, reference quota or credit until the enclosing admission binds it.
pub(crate) struct AgreementPairStorage {
    public: PublicMaterial,
}

/// Observation allocation and its credit are discarded together on retry.
pub(crate) struct AgreementPairOwnerStorage {
    storage: AgreementPairStorage,
    credit: Credit,
}

impl AgreementPairPlan {
    pub(crate) fn transport(spec: AgreementIntroductionSpec) -> Result<Self> {
        spec.validate()?;
        let protection = spec.native_protection;
        let history = spec.history_observation;
        Self::new(AgreementRequest::Transport(spec), protection, history)
    }

    pub(crate) fn new(
        request: AgreementRequest,
        protection: CurrentKeyProtection,
        history: HistoryObservationPlan,
    ) -> Result<Self> {
        crate::bounds::ck_length(request.id().len())?;
        crate::bounds::ck_length(request.label().len())?;
        history.fields()?;
        let public_bytes = PublicMaterial::planned_bytes(&request)?;
        Ok(Self {
            request,
            protection,
            history,
            public_bytes,
        })
    }

    pub(crate) fn requested_bytes(&self) -> Result<usize> {
        std::mem::size_of::<PreparedAgreementPair>()
            .checked_add(self.request.retained_bytes()?)
            .and_then(|n| n.checked_add(self.public_bytes))
            .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::AgreementOwnerSize,
            )))
    }

    pub(crate) fn allocate(&self) -> Result<AgreementPairStorage> {
        Ok(AgreementPairStorage {
            public: PublicMaterial::allocate(&self.request, self.public_bytes)?,
        })
    }

    pub(crate) fn allocated_bytes(&self, storage: &AgreementPairStorage) -> Result<usize> {
        self.requested_bytes()?
            .checked_add(storage.public.allocated().saturating_sub(self.public_bytes))
            .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::AgreementOwnerSize,
            )))
    }

    /// Complete every fallible storage conversion and credit split while the
    /// input plan is only borrowed. A retry can discard this candidate without
    /// consuming caller-transferred requests or observation choices.
    pub(crate) fn prepare_owner(
        &self,
        storage: AgreementPairStorage,
        prepaid: &mut Credit,
    ) -> Result<AgreementPairOwnerStorage> {
        Ok(AgreementPairOwnerStorage {
            credit: prepaid.split(self.allocated_bytes(&storage)?)?,
            storage,
        })
    }

    /// Validate before taking either owner. On refusal the caller still holds
    /// all inputs and can release its access guards before discarding them.
    /// The successful transfer neither allocates nor waits for another credit.
    pub(crate) fn finish_owner(
        plan: &mut Option<Self>,
        prepared: &mut Option<AgreementPairOwnerStorage>,

    ) -> Result<PreparedAgreementPair> {
        if plan.is_none() {
            return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::FamilyInputPlanAbsent,
            )));
        }
        if prepared.is_none() {
            return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::FamilyOwnerStorageAbsent,
            )));
        }
        let plan = plan.take().expect("family input checked before transfer");
        let prepared = prepared
            .take()
            .expect("family storage checked before transfer");

        Ok(PreparedAgreementPair {

            request: Some(plan.request),
            protection: plan.protection,
            history: plan.history,
            history_observation: None,
            public: PublicState::AwaitingIdentity(prepared.storage.public),
            // Only the private mechanism observation was selected by this API.
            public_mechanisms: crate::MechanismObservationPlan::NotRequested,
            _credit: prepared.credit,
        })
    }
}

impl crate::crypto::KeyGenerationDescription for AgreementPairPlan {
    fn generation_identity(&self) -> Result<crate::crypto::GenerationIdentity<'_>> {
        Ok(crate::crypto::GenerationIdentity {
            id: self.request.id(),
            label: self.request.label(),
        })
    }
    fn generation_mechanism(&self) -> Result<CK_MECHANISM_TYPE> {
        Ok(self.request.generation_mechanism())
    }
    fn generation_templates_as<T: crate::attributes::TemplateSink>(
        &self,
    ) -> Result<(T, Option<T>)> {
        let (public, private) = self.request.templates_as(self.protection)?;
        Ok((public, Some(private)))
    }
}

impl crate::crypto::KeyAdmissionDescription for AgreementPairPlan {
    fn is_pair(&self) -> bool {
        true
    }
    fn admission_id(&self) -> &[u8] {
        self.request.id()
    }
    fn admission_class(&self) -> crate::ManagedClass {
        crate::ManagedClass::PublicKey
    }
    fn object_observation(&self, private: bool) -> &crate::ObjectAdmission {
        self.request.admission(private)
    }
    fn history_observation(&self, private: bool) -> Option<crate::HistoryObservationPlan> {
        private.then_some(self.history)
    }
    fn mechanism_observation(&self, private: bool) -> &crate::MechanismObservationPlan {
        if private {
            self.request.mechanisms()
        } else {
            &crate::MechanismObservationPlan::NotRequested
        }
    }
    fn visit_required(&self, _private: bool, field: &mut dyn FnMut(CK_ATTRIBUTE_TYPE)) {
        [CKA_CLASS, CKA_KEY_TYPE, CKA_EC_PARAMS]
            .into_iter()
            .for_each(field);
    }
    fn visit_material(&self, private: bool, field: &mut dyn FnMut(CK_ATTRIBUTE_TYPE)) {
        if !private {
            field(CKA_EC_POINT);
        }
    }
}

impl PreparedAgreementPair {
    pub(crate) fn request(&self) -> &AgreementRequest {
        self.request
            .as_ref()
            .expect("admission request is retained until publication")
    }
    pub(crate) fn id(&self) -> &[u8] {
        self.request().id()
    }
    pub(crate) fn public_admission(&self) -> &crate::ObjectAdmission {
        self.request().admission(false)
    }
    pub(crate) fn private_admission(&self) -> &crate::ObjectAdmission {
        self.request().admission(true)
    }
    pub(crate) fn mechanisms(&self) -> &crate::MechanismObservationPlan {
        self.request().mechanisms()
    }
    pub(crate) fn key_type(&self) -> CK_KEY_TYPE {
        self.request().key_type()
    }
    pub(crate) fn templates_as<T: crate::attributes::TemplateSink>(&self) -> Result<(T, T)> {
        self.request().templates_as(self.protection)
    }
    pub(crate) fn generation_mechanism(&self) -> CK_MECHANISM_TYPE {
        self.request().generation_mechanism()
    }
    pub(crate) fn history_plan(&self) -> HistoryObservationPlan {
        self.history
    }
    pub(crate) fn observe_history(&mut self, snapshot: BaseProtection) -> Result<()> {
        if self.history_observation.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::AgreementHistoryAlreadyObserved,
            )));
        }

        self.history_observation = Some(snapshot);
        Ok(())
    }
    pub(crate) fn field_iter(&self) -> impl Iterator<Item = CK_ATTRIBUTE_TYPE> {
        [CKA_CLASS, CKA_KEY_TYPE, CKA_EC_PARAMS].into_iter()
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
        values.integer(CKA_KEY_TYPE, self.key_type())?;
        if values.bytes(CKA_EC_PARAMS)? != self.request().parameters() {
            return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::AgreementNativeDomain,
            )));
        }
        if !private {
            if !matches!(self.public, PublicState::AwaitingIdentity(_)) {
                return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::AgreementPublicIdentityAlreadyObserved,
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
        let PublicState::ReadPermitted(storage) = &mut self.public else {
            return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::AgreementPublicMaterialRequiresIdentity,
            )));
        };
        let raw = values.bytes(CKA_EC_POINT)?;
        let request = self
            .request
            .as_ref()
            .expect("admission request retained until publication");
        storage.observe(request, raw)?;
        let PublicState::ReadPermitted(public) =
            std::mem::replace(&mut self.public, PublicState::Published)
        else {
            unreachable!("public observation phase checked")
        };
        self.public = PublicState::Observed(public);
        Ok(())
    }
    pub(crate) fn public_complete(&self) -> Result<()> {
        if matches!(self.public, PublicState::Observed(_)) {
            Ok(())
        } else {
            Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::AgreementPublicObservationIncomplete,
            )))
        }
    }
    pub(crate) fn finish(
        &mut self,
        public: ManagedObjectRef,
        private: ManagedObjectRef,
        mechanism_report: crate::MechanismObservationReport,
    ) -> Result<AgreementPairResult> {
        self.public_complete()?;
        let protection = self.history_observation.ok_or(Error::Rejected(
            crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::AgreementHistoryObservationAbsent,
            ),
        ))?;
        enum FinalHistory {
            Ordinary,
            Transport(crate::IntroductionReport),
        }
        let final_history = match self.request() {
            AgreementRequest::Transport(_) => {
                let report = crate::transport::secret_keys::report(
                    protection,
                    crate::IntroductionOrigin::Generated,
                )?;
                FinalHistory::Transport(report)
            }
            _ => FinalHistory::Ordinary,
        };
        let request =
            self.request
                .take()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::AgreementRequestAlreadyPublished,
                )))?;
        let material = std::mem::replace(&mut self.public, PublicState::Published);
        match (request, material, final_history) {
            (
                AgreementRequest::Weierstrass(spec),
                PublicState::Observed(PublicMaterial::Weierstrass(public_der)),
                FinalHistory::Ordinary,
            ) => Ok(AgreementPairResult::Weierstrass(AgreementKeyPair {
                private: AgreementKey {
                    managed: private,
                    spec,
                    protection,

                    mechanism_report,
                },
                public,
                public_der,
            })),
            (
                AgreementRequest::Montgomery(spec),
                PublicState::Observed(PublicMaterial::Montgomery(public_key)),
                FinalHistory::Ordinary,
            ) => Ok(AgreementPairResult::Montgomery(MontgomeryKeyPair {
                private: MontgomeryKey {
                    managed: private,
                    spec,
                    protection,

                    mechanism_report,
                },
                public,
                public_key,
            })),
            (
                AgreementRequest::Transport(spec),
                PublicState::Observed(PublicMaterial::Weierstrass(public_der)),
                FinalHistory::Transport(report),
            ) => Ok(AgreementPairResult::Transport(TransportAgreementKeyPair {
                private: introduced::finish(private, spec, report, mechanism_report),
                public,
                public_der,
            })),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::AgreementPublicationFamilyMismatch,
            ))),
        }
    }
}
