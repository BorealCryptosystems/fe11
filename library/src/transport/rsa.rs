// SPDX-License-Identifier: Apache-2.0
//! Dedicated RSA transport keys. Public fields never attest a private/public pair on lookup.
use super::kek::TransportKek;
use super::*;
use crate::{
    attributes::Template, bounds, crypto::integer_key, managed, module::State, ManagedClass,
    Session,
};
use fe11_sys::*;
use std::sync::Arc;

/// Exact RSA transport request and observations, independent of a provider.
#[derive(Clone)]
pub struct RsaKeyEncryptionSpec {
    /// Native RSA generation exponent bytes, or omission for the module to decide.
    /// Inactive outside RSA generation; imported/located keys use their actual exponent.
    pub public_exponent: Option<Vec<u8>>,
    /// Native SENSITIVE/EXTRACTABLE request, independent of observations and routing.
    pub native_protection: crate::CurrentKeyProtection,
    /// Native public CKA_PRIVATE request.
    pub public_visibility: crate::ObjectVisibility,
    /// Native private CKA_PRIVATE request.
    pub private_visibility: crate::ObjectVisibility,
    /// Native public usage attributes; omitted entries remain omitted.
    pub public_usages: crate::KeyUsageRequest,
    /// Native private usage attributes; omitted entries remain omitted.
    pub private_usages: crate::KeyUsageRequest,

    /// Explicit native history/protection reads and their aggregate budget.
    pub history_observation: crate::HistoryObservationPlan,
    /// Independent observations for the public object, when produced.
    pub public_admission: crate::ObjectAdmission,
    /// Independent observations for the private object, when produced.
    pub private_admission: crate::ObjectAdmission,
    /// Requested native RSA modulus size; the module decides availability.
    pub bits: usize,
    /// Native CKA_ID bytes; destination observations are selected independently.
    pub id: Vec<u8>,
    /// UTF-8 native label; no library-defined presentation policy.
    pub label: String,
    /// Explicit token persistence; session objects are the default caller choice.
    pub persistent: bool,
}
impl RsaKeyEncryptionSpec {
    pub(crate) fn validate(&self) -> Result<()> {
        bounds::ck_length(self.bits)?;
        crate::bounds::metadata_lengths(&self.id, self.label.as_bytes())?;

        Ok(())
    }
}
// Public keys carry no private history; private keys always own their report.
// The same allocation retains that evidence when a transport view is cloned.
pub(super) struct RsaKek<Report> {
    pub key: ManagedObjectRef,
    spki: Vec<u8>,
    report: Report,
    pub(super) mechanism_report: crate::MechanismObservationReport,
}
/// RSA public key view for native wrapping with retained public-key encoding.
pub struct RsaKeyEncryptionPublic {
    inner: Arc<RsaKek<()>>,
}
impl RsaKeyEncryptionPublic {
    pub(crate) fn from_parts(
        key: ManagedObjectRef,
        spki: Vec<u8>,
        mechanism_report: crate::MechanismObservationReport,
    ) -> Self {
        Self {
            inner: Arc::new(RsaKek {
                key,
                spki,
                mechanism_report,
                report: (),
            }),
        }
    }
    /// Actual mechanism observation, without a local authorization policy.
    pub fn mechanism_report(&self) -> &crate::MechanismObservationReport {
        &self.inner.mechanism_report
    }
    /// Bound object identity without exposing the native handle.
    pub fn managed(&self) -> &ManagedObjectRef {
        &self.inner.key
    }
    /// Canonical public key retained at admission; no external ownership attestation.
    pub fn spki_der(&self) -> &[u8] {
        &self.inner.spki
    }
    /// Native wrapping view; the module validates the selected mechanism.
    pub fn wrapping(&self) -> WrappingKey {
        WrappingKey {
            inner: TransportKek::RsaWrapping(self.inner.clone()),
        }
    }
}
/// Private RSA key view for native unwrapping. A lookup is not a pair attestation.
pub struct RsaKeyEncryptionPrivate {
    inner: Arc<RsaKek<IntroductionReport>>,
}
impl RsaKeyEncryptionPrivate {
    pub(crate) fn from_parts(
        key: ManagedObjectRef,
        spki: Vec<u8>,
        mechanism_report: crate::MechanismObservationReport,
        report: IntroductionReport,
    ) -> Self {
        Self {
            inner: Arc::new(RsaKek {
                key,
                spki,
                mechanism_report,
                report,
            }),
        }
    }
    /// Actual mechanism observation, without a local authorization policy.
    pub fn mechanism_report(&self) -> &crate::MechanismObservationReport {
        &self.inner.mechanism_report
    }
    /// Bound object identity, without private material.
    pub fn managed(&self) -> &ManagedObjectRef {
        &self.inner.key
    }
    /// Exact protections and origin observed at admission.
    pub fn report(&self) -> IntroductionReport {
        self.inner.report.clone()
    }
    /// Native unwrapping view; the module validates the selected mechanism.
    pub fn unwrapping(&self) -> UnwrappingKey {
        UnwrappingKey {
            inner: TransportKek::RsaUnwrapping(self.inner.clone()),
        }
    }
}
/// Pair returned by one successful C_GenerateKeyPair, with coherent public attributes.
/// This type is never constructed by merely finding two objects sharing an ID.
pub struct RsaKeyEncryptionPair {
    public: RsaKeyEncryptionPublic,
    private: RsaKeyEncryptionPrivate,
}
impl RsaKeyEncryptionPair {
    pub(crate) fn from_parts(
        public: RsaKeyEncryptionPublic,
        private: RsaKeyEncryptionPrivate,
    ) -> Self {
        Self { public, private }
    }
    /// Public wrapping object from the same generation invocation.
    pub fn public(&self) -> &RsaKeyEncryptionPublic {
        &self.public
    }
    /// Private unwrapping object from the same generation invocation.
    pub fn private(&self) -> &RsaKeyEncryptionPrivate {
        &self.private
    }
}
fn template(spec: &RsaKeyEncryptionSpec, private: bool) -> Template {
    template_recipe(spec, private)
}

fn template_recipe<T: crate::attributes::TemplateSink>(
    spec: &RsaKeyEncryptionSpec,
    private: bool,
) -> T {
    let mut t = T::empty();
    t.integer(
        CKA_CLASS,
        if private {
            CKO_PRIVATE_KEY
        } else {
            CKO_PUBLIC_KEY
        },
    );
    t.integer(CKA_KEY_TYPE, CKK_RSA);
    t.bytes(CKA_ID, &spec.id);
    t.bytes(CKA_LABEL, spec.label.as_bytes());
    t.boolean(CKA_TOKEN, spec.persistent);
    if private {
        t.boolean(CKA_PRIVATE, spec.private_visibility.is_private());
        t.boolean(CKA_SENSITIVE, spec.native_protection.sensitive);
        t.boolean(CKA_EXTRACTABLE, spec.native_protection.extractable);
        spec.private_usages.apply(&mut t);
    } else {
        t.boolean(CKA_PRIVATE, spec.public_visibility.is_private());
        spec.public_usages.apply(&mut t);
    }
    t
}
pub(super) fn validate_live<Report>(
    s: &State,
    session: &Session,
    k: &RsaKek<Report>,
) -> Result<CK_OBJECT_HANDLE> {
    let h = session.managed_handle(s, &k.key)?;
    super::operations::bound(s, session, &k.key, h)?;
    Ok(h)
}
pub(super) struct PreparedRsaRestore<'a> {
    mechanisms: crate::MechanismObservationPlan,
    pub(super) spec: RsaKeyEncryptionSpec,
    pub(super) spki: &'a [u8],
}
impl PreparedRsaRestore<'_> {
    pub(super) fn with_observation<T>(
        &self,
        f: impl FnOnce(crate::managed::restoration::Plan<'_>) -> Result<T>,
    ) -> Result<T> {
        use crate::crypto::key_evidence::{Introduction, Order, Spec};
        let identity = [(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_RSA)];
        f(crate::managed::restoration::Plan::Rsa(
            crate::crypto::rsa_evidence::Spec {
                identity: Spec {
                    order: Order::HistoryThenMechanisms,
                    introduction: None,
                    identity: &identity,
                    maximum: self.spec.private_admission.metadata.maximum_bytes,
                    history: self.spec.history_observation,
                    mechanisms: None,
                },
                mechanisms: &self.mechanisms,
                introduction: Some(Introduction {
                    origin: IntroductionOrigin::Unwrapped,
                }),
            },
        ))
    }
    pub(super) fn finish_observed(
        self,
        key: ManagedObjectRef,
        evidence: crate::crypto::key_evidence::Evidence,
        spki: integer_key::PublicDer,
    ) -> Result<RsaKeyEncryptionPrivate> {
        Ok(RsaKeyEncryptionPrivate {
            inner: Arc::new(RsaKek {
                mechanism_report: evidence.mechanisms.ok_or(Error::Rejected(
                    crate::RejectionReason::KeyTransport(
                        crate::KeyTransportRejection::RsaRestoredMechanismReportAbsent,
                    ),
                ))?,
                key,
                spki: spki.into_bytes(),
                report: evidence.introduction.ok_or(Error::Rejected(
                    crate::RejectionReason::KeyTransport(
                        crate::KeyTransportRejection::RsaRestoredHistoryReportAbsent,
                    ),
                ))?,
            }),
        })
    }

    pub(super) fn publication_source(&self) -> Option<&[u8]> {
        Some(self.spki)
    }

    pub(super) fn template_size(&self) -> crate::attributes::TemplateSize {
        template_recipe(&self.spec, true)
    }
    pub(super) fn template(&self) -> Template {
        template(&self.spec, true)
    }
}
impl Session {
    /// Restore a private RSA KEK through explicit native unwrapping.
    /// The supplied SPKI describes the typed public view, without a private/public
    /// comparison or possession attestation. The module decides whether the selected
    /// mechanism, wrapping key, blob and destination template form a valid request.
    pub fn unwrap_rsa_unwrapping_key(
        &self,
        kek: &UnwrappingKey,
        parameters: UnwrapParameters<'_>,
        ciphertext: &[u8],
        spec: RsaKeyEncryptionSpec,
        expected_spki: &[u8],
        mechanisms: crate::MechanismObservationPlan,
    ) -> Result<crate::CreatedObjects<RsaKeyEncryptionPrivate>> {
        let mut diagnostics = None;
        spec.validate()?;
        self.validate_transport_public(expected_spki, &spec)?;
        self.unwrap_prepared_rsa(
            kek,
            parameters,
            ciphertext,
            PreparedRsaRestore {
                mechanisms,
                spec,
                spki: expected_spki,
            },
            &mut diagnostics,
        )
    }
    fn validate_transport_public(&self, der: &[u8], spec: &RsaKeyEncryptionSpec) -> Result<()> {
        let p = integer_key::rsa_der(der)?;
        if p.bits != spec.bits {
            return Err(Error::Rejected(crate::RejectionReason::KeyTransport(
                crate::KeyTransportRejection::RsaKekSpkiSize,
            )));
        }
        // Structural decoding and the caller-selected size establish this view;
        // mathematical key validity remains the native module's responsibility.
        Ok(())
    }
    /// Generate an RSA pair with the supplied native exponent, usage and storage requests.
    pub fn generate_rsa_key_encryption_pair(
        &self,
        spec: RsaKeyEncryptionSpec,
        public_mechanisms: crate::MechanismObservationPlan,
        private_mechanisms: crate::MechanismObservationPlan,
    ) -> Result<crate::CreatedObjects<RsaKeyEncryptionPair>> {
        let mut diagnostics = crate::advanced::PollDiagnostics::default();
        let prepared = crate::crypto::ClassicalPairPlan::generating_rsa_transport(
            spec,
            public_mechanisms,
            private_mechanisms,
            self.inner.crypto_options.edwards,
        )?;
        crate::advanced::rsa_transport_synchronous(self, prepared, &mut diagnostics)
    }
    /// Import a caller-supplied canonical RSA public key for native wrapping.
    /// No private object is created and no private/public binding is attested.
    pub fn import_rsa_wrapping_key(
        &self,
        spec: RsaKeyEncryptionSpec,
        spki_der: &[u8],
        mechanisms: crate::MechanismObservationPlan,
    ) -> Result<crate::CreatedObjects<RsaKeyEncryptionPublic>> {
        let mut diagnostics = None;
        spec.validate()?;
        self.validate_transport_public(spki_der, &spec)?;
        let public = integer_key::rsa_der(spki_der)?;
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
        fn import_template<T: crate::attributes::TemplateSink>(
            spec: &RsaKeyEncryptionSpec,
            public: &integer_key::RsaPublic<'_>,
        ) -> T {
            let mut template = template_recipe::<T>(spec, false);
            template.bytes(CKA_MODULUS, public.modulus);
            template.bytes(CKA_PUBLIC_EXPONENT, public.exponent);
            template
        }
        use crate::crypto::public_import::observation::Spec;
        let identity = [(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_KEY_TYPE, CKK_RSA)];
        let evidence = Spec {
            identity: &identity,

            maximum: spec.public_admission.metadata.maximum_bytes,
            mechanisms: &mechanisms,
        };
        managed::create_public_with_publication(
            self,
            spec.id.as_slice().into(),
            spec.label.as_bytes(),
            &spec.public_admission,
            evidence,
            Some(spki_der),
            import_template::<crate::attributes::TemplateSize>(&spec, &public).owned_bytes()?,
            || Ok(import_template(&spec, &public)),
            &reference_admission,
            epoch,
            &mut diagnostics,
            |access| {
                reference_admission.check(access)?;
                self.entry(access)?;
                access.native.table.C_CreateObject.ok_or(Error::Rejected(
                    crate::RejectionReason::PublicVerification(
                        crate::PublicVerificationRejection::CCreateObjectUnavailable,
                    ),
                ))?;
                Ok(())
            },
            |key, mechanism_report, publication| {
                let publication =
                    publication.ok_or(Error::Rejected(crate::RejectionReason::KeyTransport(
                        crate::KeyTransportRejection::RsaPublicPublicationAbsent,
                    )))?;
                Ok(RsaKeyEncryptionPublic {
                    inner: Arc::new(RsaKek {
                        mechanism_report,
                        key,
                        spki: publication.into_bytes(),
                        report: (),
                    }),
                })
            },
        )
    }
    /// Import a private RSA KEK from canonical PKCS8 v1 (INTEGER 0).
    /// Private operands are decoded without mathematical or public-key comparisons.
    /// Input ownership is transferred and erased; no private bytes are returned.
    pub fn import_rsa_unwrapping_key(
        &self,
        spec: RsaKeyEncryptionSpec,
        material: crate::SecretBytes,
        expected_spki: &[u8],
        mechanisms: crate::MechanismObservationPlan,
    ) -> Result<crate::CreatedObjects<RsaKeyEncryptionPrivate>> {
        let mut diagnostics = None;
        spec.validate()?;

        let material = crate::crypto::private_material::PreparedPrivateInput::borrowed(material);
        let (parsed, binding_report) = crate::crypto::private_material::parse_pkcs8(
            material.as_slice(),
            crate::ClassicalKeyAlgorithm::Rsa { bits: spec.bits },
            expected_spki,
            self.inner.crypto_options.limits.maximum_total_bytes,
        )?;
        let crate::crypto::private_material::PrivateMaterial::Rsa {
            modulus,
            exponent,
            components,
        } = parsed
        else {
            return Err(Error::Rejected(crate::RejectionReason::KeyTransport(
                crate::KeyTransportRejection::RsaPrivateMaterialFamily,
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
        fn import_template<T: crate::attributes::TemplateSink>(
            spec: &RsaKeyEncryptionSpec,
            modulus: &[u8],
            exponent: &[u8],
        ) -> T {
            let mut template = template_recipe::<T>(spec, true);
            template.bytes(CKA_MODULUS, modulus);
            template.bytes(CKA_PUBLIC_EXPONENT, exponent);
            template
        }
        let public = import_template::<crate::attributes::TemplateSize>(&spec, modulus, exponent);
        let fields = [
            (CKA_PRIVATE_EXPONENT, components[0]),
            (CKA_PRIME_1, components[1]),
            (CKA_PRIME_2, components[2]),
            (CKA_EXPONENT_1, components[3]),
            (CKA_EXPONENT_2, components[4]),
            (CKA_COEFFICIENT, components[5]),
        ];
        use crate::crypto::key_evidence::{Introduction, Order, Spec as IdentitySpec};
        let identity = [(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_RSA)];
        let evidence = crate::crypto::rsa_evidence::Spec {
            identity: IdentitySpec {
                order: Order::HistoryThenMechanisms,
                introduction: None,
                identity: &identity,
                maximum: spec.private_admission.metadata.maximum_bytes,
                history: spec.history_observation,
                mechanisms: None,
            },
            mechanisms: &mechanisms,
            introduction: Some(Introduction {
                origin: IntroductionOrigin::Imported,
            }),
        };
        let prepared = managed::prepare_rsa_creation(
            self,
            ManagedClass::PrivateKey,
            &spec.id,
            spec.label.as_bytes(),
            &spec.private_admission,
            evidence,
            &public,
            &fields,
            expected_spki,
            || Ok(import_template(&spec, modulus, exponent)),
            &reference_admission,
            epoch,
            Some(&material),
            |access| {
                reference_admission.check(access)?;
                self.entry(access)?;
                access.native.table.C_CreateObject.ok_or(Error::Rejected(
                    crate::RejectionReason::PublicVerification(
                        crate::PublicVerificationRejection::CCreateObjectUnavailable,
                    ),
                ))?;
                Ok(())
            },
        )?;
        drop(material);
        prepared.finish(
            self,
            &spec.private_admission,
            reference_admission.progress(),
            &mut diagnostics,
            |key, evidence, publication_spki| {
                let report = evidence
                    .introduction
                    .ok_or(Error::Rejected(crate::RejectionReason::KeyTransport(
                        crate::KeyTransportRejection::RsaImportedPrivateProtection,
                    )))?
                    .with_private_encoding(binding_report);
                let mechanism_report = evidence.mechanisms.ok_or(Error::Rejected(
                    crate::RejectionReason::KeyTransport(
                        crate::KeyTransportRejection::RsaMechanismReportAbsent,
                    ),
                ))?;

                Ok(RsaKeyEncryptionPrivate {
                    inner: Arc::new(RsaKek {
                        mechanism_report,
                        key,
                        spki: publication_spki.into_bytes(),
                        report,
                    }),
                })
            },
        )
    }
    /// Re-admit one exact wrapping public key against an independently supplied SPKI.
    pub fn find_rsa_wrapping_key(
        &self,
        spec: RsaKeyEncryptionSpec,
        expected_spki: &[u8],
        mechanisms: crate::MechanismObservationPlan,
    ) -> Result<RsaKeyEncryptionPublic> {
        spec.validate()?;
        self.validate_transport_public(expected_spki, &spec)?;
        let reference_admission =
            self.reference_admission(crate::session::ReferenceMode::Synchronous, |state| {
                Self::reference_search_functions(state)?;
                Ok(())
            })?;
        integer_key::rsa_der(expected_spki)?;
        use crate::crypto::public_import::observation::Spec;
        let identity = [(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_KEY_TYPE, CKK_RSA)];
        let evidence = Spec {
            identity: &identity,

            maximum: spec.public_admission.metadata.maximum_bytes,
            mechanisms: &mechanisms,
        };
        managed::key_readmission::observe_public(
            self,
            &spec.id,
            &spec.public_admission,
            evidence,
            expected_spki,
            &reference_admission,
            reference_admission.progress(),
            |access| reference_admission.check(access),
            |key, mechanism_report, publication_spki| {
                Ok(RsaKeyEncryptionPublic {
                    inner: Arc::new(RsaKek {
                        mechanism_report,
                        key,
                        spki: publication_spki.into_bytes(),
                        report: (),
                    }),
                })
            },
        )
    }
    /// Re-admit one private RSA unwrapping key. Public attributes are validated,
    /// but this does not attest possession against a separate public object.
    pub fn find_rsa_unwrapping_key(
        &self,
        spec: RsaKeyEncryptionSpec,
        mechanisms: crate::MechanismObservationPlan,
    ) -> Result<RsaKeyEncryptionPrivate> {
        spec.validate()?;
        let reference_admission =
            self.reference_admission(crate::session::ReferenceMode::Synchronous, |state| {
                Self::reference_search_functions(state)?;
                Ok(())
            })?;
        use crate::crypto::key_evidence::{Order, Spec as IdentitySpec};
        let identity = [(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_KEY_TYPE, CKK_RSA)];
        let evidence = crate::crypto::rsa_evidence::Spec {
            identity: IdentitySpec {
                order: Order::HistoryThenMechanisms,
                introduction: None,
                identity: &identity,
                maximum: spec.private_admission.metadata.maximum_bytes,
                history: spec.history_observation,
                mechanisms: None,
            },
            mechanisms: &mechanisms,
            introduction: None,
        };
        managed::key_readmission::observe_private_rsa(
            self,
            &spec.id,
            &spec.private_admission,
            evidence,
            &reference_admission,
            reference_admission.progress(),
            |access| reference_admission.check(access),
            |key, evidence, der| {
                let protection = evidence.history;
                let origin = match protection.local {
                    crate::Observation::Observed(true) => IntroductionOrigin::ObservedLocal,
                    crate::Observation::Observed(false) => IntroductionOrigin::ObservedNonLocal,
                    _ => IntroductionOrigin::ObservedUnknown,
                };
                let report = secret_keys::report(protection, origin)?;
                let mechanism_report = evidence.mechanisms.ok_or(Error::Rejected(
                    crate::RejectionReason::KeyTransport(
                        crate::KeyTransportRejection::RsaPrivateMechanismReportAbsent,
                    ),
                ))?;
                Ok(RsaKeyEncryptionPrivate {
                    inner: Arc::new(RsaKek {
                        mechanism_report,
                        key,
                        spki: der.into_bytes(),
                        report,
                    }),
                })
            },
        )
    }
}
