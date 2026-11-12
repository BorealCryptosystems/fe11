// SPDX-License-Identifier: Apache-2.0
//! Private-only EC agreement introduction, without a public-pair assertion.
use super::super::private_material::{parse_pkcs8, PrivateMaterial};
use super::*;
use crate::{
    attributes::Template, managed, ClassicalKeyAlgorithm, IntroductionOrigin, IntroductionReport,
    ManagedClass, SecretBytes, Session,
};

/// Exact private agreement destination and its explicit export/history policy.
pub struct AgreementIntroductionSpec {
    /// Independent native protection requests.
    pub native_protection: CurrentKeyProtection,
    /// Explicit observation switches and byte budget.
    pub history_observation: HistoryObservationPlan,
    /// Approved domain, identity and storage of the derive-only private key.
    pub key: AgreementKeySpec,
}
impl AgreementIntroductionSpec {
    pub(super) fn validate(&self) -> Result<()> {
        identity(&self.key.id, &self.key.label)?;
        Ok(())
    }
}
pub(super) struct Material {
    pub(super) managed: ManagedObjectRef,
    pub(super) spec: AgreementIntroductionSpec,
    report: IntroductionReport,
    mechanism_report: crate::MechanismObservationReport,
}
#[doc = include_str!("../../../docs/api/crypto/derivation/introduced/IntroducedAgreementKey.md")]
pub struct IntroducedAgreementKey {
    pub(super) inner: Material,
}
macro_rules! observations {
    ($name:ident) => {
        impl $name {
            /// Native mechanism observation and its explicit read selection.
            pub fn mechanism_report(&self) -> &crate::MechanismObservationReport {
                &self.inner.mechanism_report
            }
            /// Administrative reference, without a native handle or private material.
            pub fn managed(&self) -> &ManagedObjectRef {
                &self.inner.managed
            }
            /// Exact native protection and historical observations at admission.
            pub fn report(&self) -> IntroductionReport {
                self.inner.report.clone()
            }
            /// Caller-selected destination curve; consult the report for actual comparisons.
            pub fn curve(&self) -> AgreementCurve {
                self.inner.spec.key.curve
            }
        }
    };
}
observations!(IntroducedAgreementKey);
fn template(spec: &AgreementIntroductionSpec, importing: bool) -> Template {
    template_recipe(spec, importing)
}

fn template_recipe<T: crate::attributes::TemplateSink>(
    spec: &AgreementIntroductionSpec,
    importing: bool,
) -> T {
    let k = &spec.key;
    let mut t = T::empty();
    t.integer(CKA_CLASS, CKO_PRIVATE_KEY);
    t.integer(CKA_KEY_TYPE, CKK_EC);
    t.bytes(CKA_ID, &k.id);
    t.bytes(CKA_LABEL, k.label.as_bytes());
    for (a, v) in [
        (CKA_TOKEN, k.persistent),
        (CKA_PRIVATE, k.private_visibility.is_private()),
        (CKA_SENSITIVE, spec.native_protection.sensitive),
        (CKA_EXTRACTABLE, spec.native_protection.extractable),
    ] {
        t.boolean(a, v);
    }
    k.private_usages.apply(&mut t);
    // PKCS11 private EC attributes: the wrapped PrivateKeyInfo supplies domain
    // parameters at unwrap. C_CreateObject instead requires explicit parameters.
    if importing {
        t.bytes(CKA_EC_PARAMS, k.curve.curve().domain().oid_der);
    }
    t
}
pub(super) fn finish(
    managed: ManagedObjectRef,
    spec: AgreementIntroductionSpec,
    report: IntroductionReport,
    mechanism_report: crate::MechanismObservationReport,
) -> IntroducedAgreementKey {
    let inner = Material {
        managed,
        spec,
        report,
        mechanism_report,
    };
    IntroducedAgreementKey { inner }
}
pub(crate) struct PreparedAgreementRestore {
    pub(crate) spec: AgreementIntroductionSpec,
}
impl PreparedAgreementRestore {
    pub(crate) fn with_observation<T>(
        &self,
        f: impl FnOnce(crate::managed::restoration::Plan<'_>) -> Result<T>,
    ) -> Result<T> {
        use crate::crypto::key_evidence::{Introduction, Order, Spec};
        let identity = [(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_EC)];

        f(crate::managed::restoration::Plan::Key(Spec {
            order: Order::HistoryThenMechanisms,
            introduction: Some(Introduction {
                origin: IntroductionOrigin::Unwrapped,
            }),
            identity: &identity,
            maximum: self.spec.key.private_admission.metadata.maximum_bytes,
            history: self.spec.history_observation,
            mechanisms: Some(&self.spec.key.mechanisms),
        }))
    }
    pub(crate) fn finish_observed(
        self,
        key: ManagedObjectRef,
        evidence: crate::crypto::key_evidence::Evidence,
    ) -> Result<IntroducedAgreementKey> {
        Ok(finish(
            key,
            self.spec,
            evidence
                .introduction
                .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::RestoredAgreementHistoryReportAbsent,
                )))?,
            evidence
                .mechanisms
                .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::RestoredAgreementMechanismReportAbsent,
                )))?,
        ))
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.spec.validate()
    }
    pub(crate) fn template_size(&self) -> crate::attributes::TemplateSize {
        template_recipe(&self.spec, false)
    }
    pub(crate) fn template(&self) -> Template {
        template(&self.spec, false)
    }
}
/// Native generated agreement pair with explicit private-key attribute requests.
/// Generation is observed in this call; historical declarations remain separate.
pub struct TransportAgreementKeyPair {
    /// Private key with its selected operation/wrapping view.
    pub private: IntroducedAgreementKey,
    /// Native public companion from the same atomic generation call.
    pub public: ManagedObjectRef,
    /// Canonical public SPKI, independently validated for the chosen domain.
    pub public_der: Vec<u8>,
}
impl Session {
    /// Generate an agreement pair with explicit native protection requests.
    /// Native protection requests and history observations remain independently selected.
    pub fn generate_transport_agreement_key(
        &self,
        spec: AgreementIntroductionSpec,
    ) -> Result<crate::CreatedObjects<TransportAgreementKeyPair>> {
        let mut diagnostics = crate::advanced::PollDiagnostics::default();
        let prepared = crate::crypto::derivation::AgreementPairPlan::transport(spec)?;
        Ok(
            crate::advanced::agreement_pair_synchronous(self, prepared, &mut diagnostics)?.try_map(
                |result| match result {
                    AgreementPairResult::Transport(pair) => Ok(pair),
                    _ => Err(Error::Rejected(
                        crate::RejectionReason::KeyDerivation(crate::KeyDerivationRejection::TransportAgreementGenerationResultOwnerMismatch),
                    )),
                },
            ),
        )
    }
    /// Import a private derive key from canonical PKCS8 into exact native operands.
    /// The supplied public declaration is not compared with private material.
    /// No public witness is created and no mathematical pair is attested.
    pub fn import_agreement_key(
        &self,
        spec: AgreementIntroductionSpec,
        material: SecretBytes,
        expected_spki: &[u8],
    ) -> Result<crate::CreatedObjects<IntroducedAgreementKey>> {
        let mut diagnostics = None;
        spec.validate()?;
        let material = crate::crypto::private_material::PreparedPrivateInput::borrowed(material);
        let (parsed, binding_report) = parse_pkcs8(
            material.as_slice(),
            ClassicalKeyAlgorithm::Ecdsa(spec.key.curve.curve()),
            expected_spki,
            self.inner.crypto_options.limits.maximum_total_bytes,
        )?;
        let PrivateMaterial::Scalar(bytes) = parsed else {
            return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::AgreementPrivateFamily,
            )));
        };
        let epoch = self.snapshot.authentication_stamp();
        let reference_admission = self.reference_admission_at_epoch(
            crate::session::ReferenceMode::Synchronous,
            epoch,
            |state| {
                state.native.table.C_CreateObject.ok_or(Error::Rejected(
                    crate::RejectionReason::PublicVerification(
                        crate::PublicVerificationRejection::CCreateObjectUnavailable,
                    ),
                ))?;
                Ok(())
            },
        )?;
        let public = template_recipe::<crate::attributes::TemplateSize>(&spec, true);
        let identity = [(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_EC)];

        let prepared = managed::prepare_private_creation(
            self,
            ManagedClass::PrivateKey,
            &spec.key.id,
            spec.key.label.as_bytes(),
            &spec.key.private_admission,
            crate::crypto::key_evidence::Spec {
                order: crate::crypto::key_evidence::Order::HistoryThenMechanisms,
                introduction: Some(crate::crypto::key_evidence::Introduction {
                    origin: IntroductionOrigin::Imported,
                }),
                identity: &identity,

                maximum: spec.key.private_admission.metadata.maximum_bytes,
                history: spec.history_observation,
                mechanisms: Some(&spec.key.mechanisms),
            },
            &public,
            &[(CKA_VALUE, bytes)],
            &[],
            || Ok(template(&spec, true)),
            &reference_admission,
            epoch,
            Some(&material),
            |access| reference_admission.check(access),
        )?;
        drop(material);
        let admission = spec.key.private_admission.clone();
        prepared.finish(
            self,
            &admission,
            reference_admission.progress(),
            &mut diagnostics,
            |key, evidence, _public| {
                let report = evidence
                    .introduction
                    .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                        crate::KeyDerivationRejection::ImportedAgreementHistoryReportAbsent,
                    )))?
                    .with_private_encoding(binding_report);

                Ok(finish(
                    key,
                    spec,
                    report,
                    evidence.mechanisms.ok_or(Error::Rejected(
                        crate::RejectionReason::KeyTransport(
                            crate::KeyTransportRejection::KeyMechanismReportAbsent,
                        ),
                    ))?,
                ))
            },
        )
    }
    /// Restore a private-only agreement key by one native protected unwrap.
    /// No private value is read and no public-pair/possession claim is made.
    pub fn unwrap_agreement_key(
        &self,
        kek: &crate::UnwrappingKey,
        parameters: crate::UnwrapParameters<'_>,
        ciphertext: &[u8],
        spec: AgreementIntroductionSpec,
    ) -> Result<crate::CreatedObjects<IntroducedAgreementKey>> {
        let mut diagnostics = None;
        spec.validate()?;
        if matches!(parameters, crate::UnwrapParameters::RsaOaep { .. }) {
            return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::OaepRequiresASecretKeyDestination,
            )));
        }

        self.unwrap_prepared_agreement(
            kek,
            parameters,
            ciphertext,
            PreparedAgreementRestore { spec },
            &mut diagnostics,
        )
    }
    /// Select one existing derive-only private key, without creating a witness
    /// or asserting its unobserved introduction, history or public possession.
    pub fn find_introduced_agreement_key(
        &self,
        spec: AgreementIntroductionSpec,
    ) -> Result<IntroducedAgreementKey> {
        let mut diagnostics = crate::advanced::PollDiagnostics::default();
        let prepared = crate::crypto::derivation::DerivationBasePlan::introduced_agreement(spec)?;
        match crate::advanced::derivation_base_synchronous(self, prepared, false, &mut diagnostics)
            .and_then(|outcome| outcome.observation)?
        {
            DerivationBaseResult::IntroducedAgreement(key) => Ok(key),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::IntroducedAgreementSelectionResultOwnerMismatch,
            ))),
        }
    }
}
