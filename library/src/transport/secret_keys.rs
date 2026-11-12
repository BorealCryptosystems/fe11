// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::{attributes::Template, bounds, managed, ManagedClass, SecretBytes, Session};
use fe11_sys::*;

pub(crate) fn report(
    protection: TransportProtection,
    origin: IntroductionOrigin,
) -> Result<IntroductionReport> {
    Ok(IntroductionReport {
        origin,
        protection,
        public_binding: None,
        edwards_encoding: None,
    })
}
pub(super) fn template(spec: &SymmetricIntroductionSpec, include_length: bool) -> Result<Template> {
    template_recipe(spec, include_length)
}

pub(super) fn template_size(
    spec: &SymmetricIntroductionSpec,
    length: bool,
) -> Result<crate::attributes::TemplateSize> {
    template_recipe(spec, length)
}

fn template_recipe<T: crate::attributes::TemplateSink>(
    spec: &SymmetricIntroductionSpec,
    include_length: bool,
) -> Result<T> {
    let key = &spec.key;
    let mut t = T::empty();
    t.integer(CKA_CLASS, CKO_SECRET_KEY);
    t.integer(CKA_KEY_TYPE, key.algorithm.key_type(key.hmac_key_type)?);
    if include_length {
        t.integer(
            CKA_VALUE_LEN,
            bounds::ck_length(key.algorithm.key_length())?,
        );
    }
    t.bytes(CKA_ID, &key.id);
    t.bytes(CKA_LABEL, key.label.as_bytes());
    for (kind, value) in [
        (CKA_TOKEN, key.persistent),
        (CKA_PRIVATE, key.visibility.is_private()),
        (CKA_SENSITIVE, spec.native_protection.sensitive),
        (CKA_EXTRACTABLE, spec.native_protection.extractable),
    ] {
        t.boolean(kind, value);
    }
    key.usages.apply(&mut t);
    Ok(t)
}
pub(super) fn finish(
    key: ManagedObjectRef,
    spec: &SymmetricIntroductionSpec,
    report: IntroductionReport,
    allowed: crate::MechanismObservationReport,
) -> IntroducedSymmetricKey {
    finish_from_parts(key, spec.key.algorithm, report, allowed)
}

pub(crate) fn finish_from_parts(
    key: ManagedObjectRef,
    algorithm: crate::SymmetricAlgorithm,

    report: IntroductionReport,
    allowed: crate::MechanismObservationReport,
) -> IntroducedSymmetricKey {
    let material = IntroducedKeyMaterial {
        managed: key,
        algorithm,
        allowed,
    };
    IntroducedSymmetricKey {
        key: material,
        report,
    }
}

impl Session {
    /// Introduce owned secret bytes with an exact profile, never reading CKA_VALUE back.
    /// All input storage owned by this call is erased on every return path.
    pub fn import_symmetric_key(
        &self,
        spec: SymmetricIntroductionSpec,
        material: SecretBytes,
    ) -> Result<crate::CreatedObjects<IntroducedSymmetricKey>> {
        let mut diagnostics = None;
        spec.validate()?;
        if material.as_slice().len() != spec.key.algorithm.key_length() {
            return Err(Error::Rejected(crate::RejectionReason::KeyTransport(
                crate::KeyTransportRejection::TransportSecretLength,
            )));
        }
        self.introduce_symmetric(spec, material, &mut diagnostics)
    }
    /// Generate a key with explicit native protection requests and history observations.
    pub fn generate_transport_symmetric_key(
        &self,
        spec: SymmetricIntroductionSpec,
    ) -> Result<crate::CreatedObjects<IntroducedSymmetricKey>> {
        let mut diagnostics = crate::advanced::PollDiagnostics::default();
        crate::advanced::introduced_symmetric_synchronous(self, spec, true, &mut diagnostics)
    }
    fn introduce_symmetric(
        &self,
        spec: SymmetricIntroductionSpec,
        material: SecretBytes,
        diagnostics: &mut crate::error::ObjectCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<IntroducedSymmetricKey>> {
        let epoch = self.snapshot.authentication_stamp();
        let reference_admission = self.reference_admission_at_epoch(
            crate::session::ReferenceMode::Synchronous,
            epoch,
            |state| {
                state.native.table.C_CreateObject.ok_or(Error::Rejected(
                    crate::RejectionReason::KeyTransport(
                        crate::KeyTransportRejection::NativeIntroductionUnavailable,
                    ),
                ))?;
                Ok(())
            },
        )?;
        let public = template_recipe::<crate::attributes::TemplateSize>(&spec, false)?;
        let identity = [
            (CKA_CLASS, CKO_SECRET_KEY),
            (
                CKA_KEY_TYPE,
                spec.key.algorithm.key_type(spec.key.hmac_key_type)?,
            ),
        ];
        let prepared = managed::prepare_private_creation(
            self,
            ManagedClass::SecretKey,
            &spec.key.id,
            spec.key.label.as_bytes(),
            &spec.key.admission,
            crate::crypto::key_evidence::Spec {
                order: crate::crypto::key_evidence::Order::MechanismsThenHistory,
                introduction: Some(crate::crypto::key_evidence::Introduction {
                    origin: IntroductionOrigin::Imported,
                }),
                identity: &identity,
                maximum: spec.key.admission.metadata.maximum_bytes,
                history: spec.history_observation,
                mechanisms: Some(&spec.key.mechanisms),
            },
            &public,
            &[(CKA_VALUE, material.as_slice())],
            &[],
            || template(&spec, false),
            &reference_admission,
            epoch,
            None,
            |access| reference_admission.check(access),
        )?;
        drop(material);
        prepared.finish(
            self,
            &spec.key.admission,
            reference_admission.progress(),
            diagnostics,
            |key, evidence, _public| {
                let observed = evidence.introduction.ok_or(Error::Rejected(
                    crate::RejectionReason::KeyTransport(
                        crate::KeyTransportRejection::ImportedSymmetricHistoryReportAbsent,
                    ),
                ))?;

                let mechanisms = evidence.mechanisms.ok_or(Error::Rejected(
                    crate::RejectionReason::KeyTransport(
                        crate::KeyTransportRejection::KeyMechanismReportAbsent,
                    ),
                ))?;

                Ok(finish(key, &spec, observed, mechanisms))
            },
        )
    }
    /// Select an existing symmetric object and record the requested native observations.
    /// The report does not invent its import/unwrap history after restart.
    pub fn find_introduced_symmetric_key(
        &self,
        spec: SymmetricIntroductionSpec,
    ) -> Result<IntroducedSymmetricKey> {
        let mut diagnostics = crate::advanced::PollDiagnostics::default();
        crate::advanced::introduced_symmetric_synchronous(self, spec, false, &mut diagnostics)
            .and_then(|outcome| outcome.observation)
    }

    /// One-part AEAD using an introduced key; the module enforces native permissions.
    pub fn encrypt_introduced_aead(
        &self,
        key: &IntroducedSymmetricKey,
        p: crate::AeadParameters<'_>,
        message: &[u8],
        limits: crate::InputLimits,
    ) -> Result<crate::AeadCiphertext> {
        let mut message_diagnostics = None;
        let mut retirement = crate::advanced::PollDiagnostics::default();
        self.symmetric_aead(
            key.key.view(),
            p,
            &[message],
            limits,
            false,
            false,
            &mut retirement,
            &mut message_diagnostics,
        )
    }
    /// AEAD decryption using an introduced operation key. A zero-bit GCM tag
    /// provides no authentication; the result exposes tag_bits().
    pub fn decrypt_introduced_aead(
        &self,
        key: &IntroducedSymmetricKey,
        p: crate::AeadParameters<'_>,
        ciphertext: &[u8],
        limits: crate::InputLimits,
    ) -> Result<crate::AeadPlaintext> {
        let mut message_diagnostics = None;
        let mut retirement = crate::advanced::PollDiagnostics::default();
        self.symmetric_aead(
            key.key.view(),
            p,
            &[ciphertext],
            limits,
            false,
            true,
            &mut retirement,
            &mut message_diagnostics,
        )
        .map(|x| x.into_plaintext())
    }
    /// Multipart AEAD using an introduced operation key.
    pub fn encrypt_introduced_aead_multipart(
        &self,
        key: &IntroducedSymmetricKey,
        p: crate::AeadParameters<'_>,
        parts: &[&[u8]],
        limits: crate::InputLimits,
    ) -> Result<crate::AeadCiphertext> {
        let mut message_diagnostics = None;
        let mut retirement = crate::advanced::PollDiagnostics::default();
        self.symmetric_aead(
            key.key.view(),
            p,
            parts,
            limits,
            true,
            false,
            &mut retirement,
            &mut message_diagnostics,
        )
    }
    /// Multipart authenticated decryption with no intermediate plaintext publication.
    pub fn decrypt_introduced_aead_multipart(
        &self,
        key: &IntroducedSymmetricKey,
        p: crate::AeadParameters<'_>,
        parts: &[&[u8]],
        limits: crate::InputLimits,
    ) -> Result<crate::AeadPlaintext> {
        let mut message_diagnostics = None;
        let mut retirement = crate::advanced::PollDiagnostics::default();
        self.symmetric_aead(
            key.key.view(),
            p,
            parts,
            limits,
            true,
            true,
            &mut retirement,
            &mut message_diagnostics,
        )
        .map(|x| x.into_plaintext())
    }
    /// Native full HMAC with an introduced operation key.
    pub fn compute_introduced_mac(
        &self,
        key: &IntroducedSymmetricKey,
        message: &[u8],
        limits: crate::InputLimits,
    ) -> Result<crate::MessageAuthenticationCode> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.symmetric_mac(
            key.key.view(),
            &[message],
            limits,
            false,
            None,
            &mut extension_diagnostics,
        )
        .and_then(|r| {
            r.0.ok_or(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::MacOutputUnavailable,
                ),
            ))
        })
    }
    /// Native multipart HMAC with an introduced operation key.
    pub fn compute_introduced_mac_multipart(
        &self,
        key: &IntroducedSymmetricKey,
        parts: &[&[u8]],
        limits: crate::InputLimits,
    ) -> Result<crate::MessageAuthenticationCode> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.symmetric_mac(
            key.key.view(),
            parts,
            limits,
            true,
            None,
            &mut extension_diagnostics,
        )
        .and_then(|r| {
            r.0.ok_or(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::MacOutputUnavailable,
                ),
            ))
        })
    }
    /// Native verification with an introduced HMAC operation key.
    pub fn verify_introduced_mac(
        &self,
        key: &IntroducedSymmetricKey,
        message: &[u8],
        mac: &[u8],
        limits: crate::InputLimits,
    ) -> Result<crate::Verification> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.symmetric_mac(
            key.key.view(),
            &[message],
            limits,
            false,
            Some(mac),
            &mut extension_diagnostics,
        )
        .map(|r| r.1)
    }
    /// Native multipart verification with an introduced HMAC operation key.
    pub fn verify_introduced_mac_multipart(
        &self,
        key: &IntroducedSymmetricKey,
        parts: &[&[u8]],
        mac: &[u8],
        limits: crate::InputLimits,
    ) -> Result<crate::Verification> {
        let mut extension_diagnostics =
            crate::mechanism_extension::operation::Invocation::default();
        self.symmetric_mac(
            key.key.view(),
            parts,
            limits,
            true,
            Some(mac),
            &mut extension_diagnostics,
        )
        .map(|r| r.1)
    }
}
