// SPDX-License-Identifier: Apache-2.0
//! Explicit signing-key introduction, native history and operation views.
use super::super::private_material::{parse_pkcs8, PrivateMaterial};
use super::*;
use crate::{transport::secret_keys, IntroductionOrigin, IntroductionReport};

/// Native signing destination requests and explicit history observations.
pub struct SigningIntroductionSpec {
    /// Explicit native history/protection reads and their aggregate budget.
    pub history_observation: crate::HistoryObservationPlan,
    /// Identity, algorithm and caller-selected signing profiles.
    pub key: ClassicalKeySpec,
}
impl SigningIntroductionSpec {
    fn validate(&self) -> Result<()> {
        let k = &self.key;
        crate::bounds::metadata_lengths(&k.id, k.label.as_bytes())?;
        Ok(())
    }
}
struct Material {
    managed: ManagedObjectRef,
    algorithm: ClassicalKeyAlgorithm,
    // Preserve ownership when a prepared or generated reference is introduced.
    // Profiles do not restrict the operation selected by the caller.
    _profiles: Vec<SignatureProfile>,
    // A library-prepared allocation keeps its reservation until the vector drops.
    // Caller-owned profiles arrive without a library allocation credit.
    _profiles_credit: Option<crate::symmetric::memory::Credit>,
    allowed: crate::MechanismObservationReport,
    spki: Vec<u8>,
    report: IntroductionReport,
}
impl Material {
    fn view(&self) -> SigningKeyView<'_> {
        SigningKeyView {
            managed: &self.managed,
            algorithm: self.algorithm,
        }
    }
}
#[doc = include_str!("../../../docs/api/crypto/signing/introduced/IntroducedSigningKey.md")]
pub struct IntroducedSigningKey {
    inner: Material,
}
macro_rules! observations {
    ($name:ident) => {
        impl $name {
            /// Selected native mechanism observation.
            pub fn mechanism_report(&self) -> &crate::MechanismObservationReport {
                &self.inner.allowed
            }
            /// Administrative reference without a native handle or private bytes.
            pub fn managed(&self) -> &ManagedObjectRef {
                &self.inner.managed
            }
            /// Exact observed origin, current protections and history.
            pub fn report(&self) -> IntroductionReport {
                self.inner.report.clone()
            }
            /// Supplied public declaration, without an attestation of private correspondence.
            /// Inspect `report().private_encoding_report()` for the private input decoding;
            /// this accessor neither queries the module nor validates a key pair.
            pub fn spki_der(&self) -> &[u8] {
                &self.inner.spki
            }
        }
    };
}
observations!(IntroducedSigningKey);
fn template(
    spec: &SigningIntroductionSpec,
    importing: bool,
    semantics: crate::EdwardsOptions,
) -> Template {
    template_recipe(spec, importing, semantics)
}

fn template_recipe<T: crate::attributes::TemplateSink>(
    spec: &SigningIntroductionSpec,
    importing: bool,
    semantics: crate::EdwardsOptions,
) -> T {
    let k = &spec.key;
    let mut t = T::empty();
    t.integer(CKA_CLASS, CKO_PRIVATE_KEY);
    t.integer(CKA_KEY_TYPE, k.algorithm.key_type());
    t.bytes(CKA_ID, &k.id);
    t.bytes(CKA_LABEL, k.label.as_bytes());
    t.boolean(CKA_TOKEN, k.persistent);
    t.boolean(
        CKA_PRIVATE,
        k.private_visibility == crate::ObjectVisibility::Private,
    );
    t.boolean(CKA_SENSITIVE, k.private_protection.sensitive);
    t.boolean(CKA_EXTRACTABLE, k.private_protection.extractable);
    k.private_usages.apply(&mut t);
    // PKCS11 3.2 tables65/67 footnote6: domain parameters come from the
    // wrapped PrivateKeyInfo and MUST NOT be supplied to C_UnwrapKey.
    // They remain mandatory at import and are verified after both operations.
    if importing && !matches!(k.algorithm, ClassicalKeyAlgorithm::Rsa { .. }) {
        t.bytes(
            CKA_EC_PARAMS,
            k.algorithm.params(semantics.parameter_encoding),
        );
    }
    t
}
fn finish(
    key: ManagedObjectRef,
    spec: SigningIntroductionSpec,
    spki: super::super::integer_key::PublicDer,
    allowed: crate::MechanismObservationReport,
    report: IntroductionReport,
) -> IntroducedSigningKey {
    let material = Material {
        managed: key,
        algorithm: spec.key.algorithm,
        _profiles: spec.key.profiles,
        _profiles_credit: None,
        allowed,
        spki: spki.into_bytes(),
        report,
    };
    IntroducedSigningKey { inner: material }
}
pub(super) fn from_signing_key(
    key: SigningKey,
    spki: Vec<u8>,

    report: IntroductionReport,
) -> IntroducedSigningKey {
    let material = Material {
        managed: key.managed,
        algorithm: key.algorithm,
        _profiles: key._profiles,
        _profiles_credit: Some(key._profiles_credit),
        allowed: key.mechanism_report,
        spki,
        report: report.with_edwards_encoding(key.edwards_encoding),
    };
    IntroducedSigningKey { inner: material }
}

/// A native pair with explicit private-key attributes and history observations.
pub struct TransportSigningKeyPair {
    /// Representations actually read from the public companion, when Edwards.
    pub public_edwards_encoding: Option<crate::EdwardsEncodingReport>,
    /// Selected native mechanism observation for the public companion.
    pub public_mechanism_report: crate::MechanismObservationReport,
    /// Private signer with its selected operation/wrapping view and observation report.
    pub private: IntroducedSigningKey,
    /// Administrative public companion from the same native generation call.
    pub public: ManagedObjectRef,
    /// Canonical SPKI decoded from the generated public object; no possession claim.
    pub public_der: Vec<u8>,
}
// The supplied public declaration is structurally decoded before native
// guards. No verifier or private/public correspondence check is prepared.
pub(crate) struct PreparedSigningRestore<'a> {
    semantics: crate::EdwardsOptions,
    spec: SigningIntroductionSpec,
    spki: &'a [u8],
}
impl PreparedSigningRestore<'_> {
    pub(crate) fn with_observation<T>(
        &self,

        f: impl FnOnce(crate::managed::restoration::Plan<'_>) -> Result<T>,
    ) -> Result<T> {
        use crate::crypto::key_evidence::{Introduction, Order, Spec};
        let algorithm = self.spec.key.algorithm;
        let identity = [
            (CKA_CLASS, CKO_PRIVATE_KEY),
            (CKA_KEY_TYPE, algorithm.key_type()),
        ];
        f(crate::managed::restoration::Plan::Signing {
            evidence: Spec {
                order: Order::HistoryThenMechanisms,
                introduction: Some(Introduction {
                    origin: IntroductionOrigin::Unwrapped,
                }),
                identity: &identity,
                maximum: self.spec.key.private_admission.metadata.maximum_bytes,
                history: self.spec.history_observation,
                mechanisms: Some(&self.spec.key.mechanisms),
            },
        })
    }

    pub(crate) fn finish_observed(
        self,
        key: ManagedObjectRef,
        evidence: crate::crypto::key_evidence::Evidence,
        spki: crate::crypto::integer_key::PublicDer,
    ) -> Result<IntroducedSigningKey> {
        // The template requests an encoding, but this observation plan does not
        // read CKA_EC_PARAMS. Do not turn that request into native evidence.
        Ok(finish(
            key,
            self.spec,
            spki,
            evidence.mechanisms.ok_or(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::RestoredSigningMechanismReportAbsent,
                ),
            ))?,
            evidence.introduction.ok_or(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::RestoredSigningHistoryReportAbsent,
                ),
            ))?,
        ))
    }

    pub(crate) fn publication_source(&self) -> Option<&[u8]> {
        Some(self.spki)
    }

    pub(crate) fn key(&self) -> &ClassicalKeySpec {
        &self.spec.key
    }
    pub(crate) fn validate(&self) -> Result<()> {
        self.spec.validate()
    }
    pub(crate) fn template_size(&self) -> crate::attributes::TemplateSize {
        template_recipe(&self.spec, false, self.semantics)
    }
    pub(crate) fn template(&self) -> Template {
        template(&self.spec, false, self.semantics)
    }
}
impl Session {
    /// Generate a native signing pair with the supplied private-key attributes.
    /// No challenge or possession check is performed.
    /// No private material is read; both facades share the ordinary pair owner.
    pub fn generate_transport_signing_key_pair(
        &self,
        spec: SigningIntroductionSpec,

        public_mechanisms: crate::MechanismObservationPlan,
    ) -> Result<crate::CreatedObjects<TransportSigningKeyPair>> {
        self.generate_transport_signing_key_pair_selected(spec, public_mechanisms)
    }

    fn generate_transport_signing_key_pair_selected(
        &self,
        spec: SigningIntroductionSpec,

        public_mechanisms: crate::MechanismObservationPlan,
    ) -> Result<crate::CreatedObjects<TransportSigningKeyPair>> {
        let mut diagnostics = crate::advanced::PollDiagnostics::default();
        let prepared = crate::crypto::ClassicalPairPlan::generating_transport(
            spec,
            public_mechanisms,
            self.inner.crypto_options.edwards,
        )?;
        crate::advanced::transport_signing_synchronous(self, prepared, &mut diagnostics)
    }
    /// Restore one private signer using native protected unwrapping. No private
    /// component is read or decrypted in Rust. The caller supplies the public
    /// representation for the typed view; Fe11 does not attest its correspondence.
    /// OAEP cannot restore a private-key destination through this API.
    pub fn unwrap_signing_key(
        &self,
        kek: &crate::UnwrappingKey,
        parameters: crate::UnwrapParameters<'_>,
        ciphertext: &[u8],
        spec: SigningIntroductionSpec,
        expected_spki: &[u8],
    ) -> Result<crate::CreatedObjects<IntroducedSigningKey>> {
        let mut diagnostics = None;
        self.unwrap_signing_key_selected(
            kek,
            parameters,
            ciphertext,
            spec,
            expected_spki,
            &mut diagnostics,
        )
    }

    fn unwrap_signing_key_selected(
        &self,
        kek: &crate::UnwrappingKey,
        parameters: crate::UnwrapParameters<'_>,
        ciphertext: &[u8],
        spec: SigningIntroductionSpec,
        expected_spki: &[u8],
        diagnostics: &mut crate::error::ObjectCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<IntroducedSigningKey>> {
        spec.validate()?;
        if matches!(parameters, crate::UnwrapParameters::RsaOaep { .. }) {
            return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::OaepRequiresASecretKeyDestination,
            )));
        }
        let algorithm = spec.key.algorithm;
        self.validate_signing_public(expected_spki, algorithm)?;

        self.unwrap_prepared_signing(
            kek,
            parameters,
            ciphertext,
            PreparedSigningRestore {
                semantics: self.inner.crypto_options.edwards,
                spec,
                spki: expected_spki,
            },
            diagnostics,
        )
    }
    /// Import a private signing object from canonical PKCS8 v1 (INTEGER 0).
    /// Structural decoding supplies native operands; the module decides mathematical
    /// key validity. The public declaration is not compared with private material.
    /// No witness object, challenge, signature or verification is implicit.
    pub fn import_signing_key(
        &self,
        spec: SigningIntroductionSpec,
        material: SecretBytes,
        expected_spki: &[u8],
    ) -> Result<crate::CreatedObjects<IntroducedSigningKey>> {
        let mut diagnostics = None;
        self.import_signing_key_selected(spec, material, expected_spki, &mut diagnostics)
    }

    fn import_signing_key_selected(
        &self,
        spec: SigningIntroductionSpec,
        material: SecretBytes,
        expected_spki: &[u8],
        diagnostics: &mut crate::error::ObjectCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<IntroducedSigningKey>> {
        spec.validate()?;

        let algorithm = spec.key.algorithm;
        let material = crate::crypto::private_material::PreparedPrivateInput::borrowed(material);
        let (parsed, binding_report) = parse_pkcs8(
            material.as_slice(),
            algorithm,
            expected_spki,
            self.inner.crypto_options.limits.maximum_total_bytes,
        )?;

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
            spec: &SigningIntroductionSpec,
            parsed: &PrivateMaterial<'_>,
            semantics: crate::EdwardsOptions,
        ) -> T {
            let mut template = template_recipe::<T>(spec, true, semantics);
            if let PrivateMaterial::Rsa {
                modulus, exponent, ..
            } = parsed
            {
                template.bytes(CKA_MODULUS, modulus);
                template.bytes(CKA_PUBLIC_EXPONENT, exponent);
            }
            template
        }
        let public = import_template::<crate::attributes::TemplateSize>(
            &spec,
            &parsed,
            self.inner.crypto_options.edwards,
        );
        // These are exact ABI shapes, borrowed from the caller-owned PKCS#8.
        // No private component copy survives a possession retry.
        let rsa_components;
        let scalar_component;
        let components = match &parsed {
            PrivateMaterial::Rsa { components, .. } => {
                rsa_components = [
                    (CKA_PRIVATE_EXPONENT, components[0]),
                    (CKA_PRIME_1, components[1]),
                    (CKA_PRIME_2, components[2]),
                    (CKA_EXPONENT_1, components[3]),
                    (CKA_EXPONENT_2, components[4]),
                    (CKA_COEFFICIENT, components[5]),
                ];
                &rsa_components[..]
            }
            PrivateMaterial::Scalar(bytes) => {
                scalar_component = [(CKA_VALUE, *bytes)];
                &scalar_component[..]
            }
        };

        use crate::crypto::key_evidence::{Introduction, Order, Spec};
        let identity = [
            (CKA_CLASS, CKO_PRIVATE_KEY),
            (CKA_KEY_TYPE, algorithm.key_type()),
        ];
        let evidence = Spec {
            order: Order::HistoryThenMechanisms,
            introduction: Some(Introduction {
                origin: IntroductionOrigin::Imported,
            }),
            identity: &identity,
            maximum: spec.key.private_admission.metadata.maximum_bytes,
            history: spec.history_observation,
            mechanisms: Some(&spec.key.mechanisms),
        };
        let prepared = crate::managed::prepare_signing_creation(
            self,
            ManagedClass::PrivateKey,
            &spec.key.id,
            spec.key.label.as_bytes(),
            &spec.key.private_admission,
            evidence,
            false,
            &public,
            components,
            expected_spki,
            || {
                Ok(import_template(
                    &spec,
                    &parsed,
                    self.inner.crypto_options.edwards,
                ))
            },
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
        let admission = spec.key.private_admission.clone();

        prepared.finish_signing(
            self,
            &admission,
            reference_admission.progress(),
            diagnostics,
            |key, evidence, publication_spki| {
                let report = evidence
                    .introduction
                    .ok_or(Error::Rejected(
                        crate::RejectionReason::ClassicalSignatures(
                            crate::ClassicalSignaturesRejection::SigningIntroductionReportAbsent,
                        ),
                    ))?
                    .with_private_encoding(binding_report);
                let permissions = evidence.mechanisms.ok_or(Error::Rejected(
                    crate::RejectionReason::KeyTransport(
                        crate::KeyTransportRejection::KeyMechanismReportAbsent,
                    ),
                ))?;

                Ok(finish(key, spec, publication_spki, permissions, report))
            },
        )
    }
    /// Select an existing private signer and perform the requested observations.
    /// This creates no object and performs no possession signature.
    pub fn find_introduced_signing_key(
        &self,
        spec: SigningIntroductionSpec,
        expected_spki: &[u8],
    ) -> Result<IntroducedSigningKey> {
        self.find_introduced_signing_key_selected(spec, expected_spki)
    }

    fn find_introduced_signing_key_selected(
        &self,
        spec: SigningIntroductionSpec,
        expected_spki: &[u8],
    ) -> Result<IntroducedSigningKey> {
        spec.validate()?;
        let algorithm = spec.key.algorithm;
        self.validate_signing_public(expected_spki, algorithm)?;

        let reference_admission =
            self.reference_admission(crate::session::ReferenceMode::Synchronous, |state| {
                Self::reference_search_functions(state)?;
                Ok(())
            })?;

        use crate::crypto::key_evidence::{Order, Spec};
        let identity = [
            (CKA_CLASS, CKO_PRIVATE_KEY),
            (CKA_KEY_TYPE, algorithm.key_type()),
        ];
        let evidence = Spec {
            order: Order::HistoryThenMechanisms,
            introduction: None,
            identity: &identity,
            maximum: spec.key.private_admission.metadata.maximum_bytes,
            history: spec.history_observation,
            mechanisms: Some(&spec.key.mechanisms),
        };
        let admission = spec.key.private_admission.clone();
        let contextual = false;

        // Keep the native function check borrowed while the observation owner
        // retains the lookup request and its publication storage.

        let (key, evidence, publication_spki) = crate::managed::key_readmission::observe(
            self,
            &spec.key.id,
            &admission,
            evidence,
            expected_spki,
            contextual,
            &reference_admission,
            reference_admission.progress(),
            |access| {
                reference_admission.check(access)?;

                Ok(())
            },
            |key, evidence, publication_spki| Ok((key, evidence, publication_spki)),
        )?;
        let origin = match evidence.history.local {
            crate::Observation::Observed(true) => IntroductionOrigin::ObservedLocal,
            crate::Observation::Observed(false) => IntroductionOrigin::ObservedNonLocal,
            _ => IntroductionOrigin::ObservedUnknown,
        };
        // This lookup observes history and mechanisms, not the native encoding.
        let report = secret_keys::report(evidence.history, origin)?;
        let permissions =
            evidence
                .mechanisms
                .ok_or(Error::Rejected(crate::RejectionReason::KeyTransport(
                    crate::KeyTransportRejection::KeyMechanismReportAbsent,
                )))?;
        Ok(finish(key, spec, publication_spki, permissions, report))
    }
    /// Sign with an introduced private key and an explicit hash route.
    pub fn sign_introduced(
        &self,
        key: &IntroducedSigningKey,
        request: SigningRequest,
        message: &[u8],
        limits: InputLimits,
    ) -> Result<ClassicalSignature> {
        let mut invocation_diagnostics = crate::crypto::ClassicalDiagnostics::default();
        let diagnostics = &mut invocation_diagnostics;
        self.sign_classical_parts(
            key.inner.view(),
            request,
            &[message],
            false,
            limits,
            diagnostics,
        )
    }
    /// Multipart signing with an introduced private key.
    pub fn sign_introduced_multipart(
        &self,
        key: &IntroducedSigningKey,
        request: SigningRequest,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<ClassicalSignature> {
        let mut invocation_diagnostics = crate::crypto::ClassicalDiagnostics::default();
        let diagnostics = &mut invocation_diagnostics;
        self.sign_classical_parts(key.inner.view(), request, parts, true, limits, diagnostics)
    }

    /// Explicit caller-prepared RSA digest with an introduced protected key.
    pub fn sign_introduced_rsa_digest(
        &self,
        key: &IntroducedSigningKey,
        profile: RsaSignatureProfile,
        digest: &super::super::PreparedDigest,
    ) -> Result<ClassicalSignature> {
        let mut invocation_diagnostics = crate::crypto::ClassicalDiagnostics::default();
        let diagnostics = &mut invocation_diagnostics;
        self.sign_rsa_digest_view(key.inner.view(), profile, digest, diagnostics)
    }

    /// Sign with an introduced protected key and a single-use contextual login.
    /// Authentication follows SignInit; refusal retains the active frame until
    /// successful session closure, as in Session::sign_pss_with_context.
    pub fn sign_introduced_with_context(
        &self,
        key: &IntroducedSigningKey,
        request: SigningRequest,
        message: &[u8],
        limits: InputLimits,
        authentication: crate::ContextAuthentication,
    ) -> Result<ClassicalSignature> {
        let mut invocation_diagnostics = crate::crypto::ClassicalDiagnostics::default();
        let diagnostics = &mut invocation_diagnostics;
        self.sign_classical_parts_with_context(
            key.inner.view(),
            request,
            &[message],
            false,
            limits,
            Some(authentication),
            diagnostics,
        )
    }
    /// Sign with an introduced protected key and a single-use contextual login.
    /// Authentication follows SignInit; refusal retains the active frame until
    /// successful session closure, as in Session::sign_pss_with_context.
    pub fn sign_introduced_multipart_with_context(
        &self,
        key: &IntroducedSigningKey,
        request: SigningRequest,
        parts: &[&[u8]],
        limits: InputLimits,
        authentication: crate::ContextAuthentication,
    ) -> Result<ClassicalSignature> {
        let mut invocation_diagnostics = crate::crypto::ClassicalDiagnostics::default();
        let diagnostics = &mut invocation_diagnostics;
        self.sign_classical_parts_with_context(
            key.inner.view(),
            request,
            parts,
            true,
            limits,
            Some(authentication),
            diagnostics,
        )
    }
    /// Sign a caller-prepared RSA digest with an introduced protected key,
    /// preserving its encoding/provenance and adding one explicit contextual login.
    pub fn sign_introduced_rsa_digest_with_context(
        &self,
        key: &IntroducedSigningKey,
        profile: RsaSignatureProfile,
        digest: &super::super::PreparedDigest,
        authentication: crate::ContextAuthentication,
    ) -> Result<ClassicalSignature> {
        let mut invocation_diagnostics = crate::crypto::ClassicalDiagnostics::default();
        let diagnostics = &mut invocation_diagnostics;
        self.sign_rsa_digest_view_with_context(
            key.inner.view(),
            profile,
            digest,
            Some(authentication),
            diagnostics,
        )
    }
}
