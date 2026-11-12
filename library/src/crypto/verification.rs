// SPDX-License-Identifier: Apache-2.0
//! Public-only import and verification references, sharing object revocation.
mod owned;
mod preparation;
mod publication;
use super::{public_key::EdwardsCurve, EdwardsOptions, HashAlgorithm, InputLimits};
use crate::{attributes, managed, Error, ManagedObjectRef, Result, Session, Verification};
use fe11_sys::*;
pub(crate) use owned::{
    PreparedVerification, VerificationOwnerStorage, VerificationPlan, VerificationStorage,
};
pub(crate) use publication::{
    VerificationPublication, VerificationPublicationPlan, VerificationPublicationStorage,
};
use sha2::{Digest, Sha256};

/// Typed verification parameters used by an optional caller membership comparison.
/// These selectors do not constitute or attest a standards compliance profile.
#[derive(Clone, Copy, Debug, Eq)]
pub enum VerificationProfile {
    /// Historical verification only; never a private signing permission.
    Historical(super::HistoricalProfile),
    /// RSA PKCS1v1.5 with an exact modern hash; verification permission only.
    RsaPkcs1(HashAlgorithm),
    /// Exact modern PSS parameters; no automatic salt or MGF.
    RsaPss(super::RsaPssParameters),
    /// ECDSA with an explicit modern hash; never a signing authorization.
    Ecdsa(HashAlgorithm),
    /// Pure Ed25519, exact message, no prehash or context.
    Ed25519,
    /// Pure Ed448, exact message, empty context, no prehash.
    Ed448,
    /// Exact EdDSA instance and context; pure aliases compare equally.
    EdDsa(super::EdDsaParameters),
}
impl VerificationProfile {
    fn canonical(self) -> Self {
        match self {
            Self::EdDsa(p) if p.pure_ed25519() => Self::Ed25519,
            Self::EdDsa(p) if p.pure_ed448() => Self::Ed448,
            _ => self,
        }
    }
}
impl PartialEq for VerificationProfile {
    fn eq(&self, other: &Self) -> bool {
        match (self.canonical(), other.canonical()) {
            (Self::Historical(a), Self::Historical(b)) => a == b,
            (Self::RsaPkcs1(a), Self::RsaPkcs1(b)) | (Self::Ecdsa(a), Self::Ecdsa(b)) => a == b,
            (Self::RsaPss(a), Self::RsaPss(b)) => a == b,
            (Self::Ed25519, Self::Ed25519) | (Self::Ed448, Self::Ed448) => true,
            (Self::EdDsa(a), Self::EdDsa(b)) => a == b,
            _ => false,
        }
    }
}
/// Session-bound public key, with canonical SPKI identity and explicit policy.
/// No private key, raw handle, or conversion to a signing/decryption key exists.
pub struct VerificationKey {
    pub(super) edwards_encoding: Option<crate::EdwardsEncodingReport>,
    pub(super) managed: ManagedObjectRef,
    pub(super) fingerprint: [u8; 32],
    pub(super) profiles: Vec<VerificationProfile>,
    pub(super) mechanism_report: crate::MechanismObservationReport,
    pub(super) curve: Option<super::curves::WeierstrassCurve>,
    pub(super) edwards: Option<EdwardsCurve>,
    pub(super) rsa: Option<RsaMetadata>,
    pub(super) dsa: Option<super::dsa::DsaMetadata>,
    // Fields drop in declaration order: keep the credit after the buffers it covers.
    pub(super) _import_credit: Option<crate::symmetric::memory::Credit>,
}
#[derive(Clone)]
pub(super) struct RsaMetadata {
    pub bits: usize,
    pub exponent_class: super::RsaExponentClass,
}
impl VerificationKey {
    /// Encodings actually decoded from this public object's native attributes.
    /// None means no encoding readback; a report may contain parameters only.
    pub fn edwards_encoding(&self) -> Option<crate::EdwardsEncodingReport> {
        self.edwards_encoding
    }

    /// Actual native mechanism observation and its explicit read selection.
    pub fn mechanism_report(&self) -> &crate::MechanismObservationReport {
        &self.mechanism_report
    }
    /// SHA-256 of the exact canonical public SubjectPublicKeyInfo.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
    /// Exact caller membership list; its selected comparison may be disabled.
    pub fn profiles(&self) -> &[VerificationProfile] {
        &self.profiles
    }
    /// Independent exponent classification for RSA; a modern hash never hides it.
    pub fn rsa_exponent_class(&self) -> Option<super::RsaExponentClass> {
        self.rsa.as_ref().map(|r| r.exponent_class)
    }
    /// Administrative operations share revocation with this cryptographic reference.
    pub fn management_reference(&self) -> &ManagedObjectRef {
        &self.managed
    }
    pub(crate) fn message_pss_bits(&self, _parameters: super::RsaPssParameters) -> Result<usize> {
        let rsa = self.rsa.as_ref().ok_or(Error::Rejected(
            crate::RejectionReason::PublicVerification(
                crate::PublicVerificationRejection::MessageRsaVerificationKeyRequired,
            ),
        ))?;

        Ok(rsa.bits)
    }
}

pub(super) fn public_algorithm_oid(spki: &[u8]) -> Result<x509_cert::der::asn1::ObjectIdentifier> {
    use x509_cert::{der::Decode, spki::SubjectPublicKeyInfoRef};
    Ok(SubjectPublicKeyInfoRef::from_der(spki)
        .map_err(|_| {
            Error::Rejected(crate::RejectionReason::PublicVerification(
                crate::PublicVerificationRejection::PublicSpkiDer,
            ))
        })?
        .algorithm
        .oid)
}
impl Session {
    /// Resolve one existing public key by exact ID and independently supplied
    /// canonical SPKI. No private counterpart, CKA_LOCAL or pair signature is
    /// required. Validation runs outside guards; native identity is checked
    /// under shared lifecycle and exclusive session access before exposing the reference.
    /// Edwards uses the explicitly configured native representation. This selector never creates an admission witness.
    pub fn find_classical_verification_key(
        &self,
        id: &[u8],
        expected_spki: &[u8],
        profiles: &[VerificationProfile],
        mechanisms: crate::MechanismObservationPlan,
        object_admission: crate::ObjectAdmission,
    ) -> Result<VerificationKey> {
        let mut diagnostics = crate::advanced::PollDiagnostics::default();
        let prepared = crate::crypto::VerificationPlan::selected(
            id,
            expected_spki,
            profiles,
            mechanisms,
            object_admission,
            self.inner.crypto_options.edwards,
        )?;
        crate::advanced::verification_synchronous(self, prepared, &mut diagnostics)
    }

    /// Validate and import a public SPKI with explicit metadata, storage and usage requests.
    /// Edwards witness checks are optional, separate interoperability evidence.
    /// This method never creates an admission witness or retries a missing proof.
    /// SPKI structure is checked before native effects; mathematical key validity is
    /// delegated to the module. EC/Edwards use their curve-specific preparation.
    /// No login or private counterpart is required. Destination observations and
    /// reactions follow options.admission.destination. Partial native failures may
    /// leave a session object; the session is withdrawn and the error reports it.
    pub fn create_verification_key(
        &self,
        spki_der: &[u8],
        profiles: &[VerificationProfile],
        mechanisms: crate::MechanismObservationPlan,
        options: crate::PublicKeyImportOptions,
    ) -> Result<crate::CreatedObjects<VerificationKey>> {
        let mut diagnostics = None;
        let public =
            preparation::VerificationInput::parse(spki_der, self.inner.crypto_options.edwards)?;
        let fingerprint: [u8; 32] = Sha256::digest(spki_der).into();
        let metadata = options.metadata.plan(spki_der)?;
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
        let kind = public.kind();
        let id = metadata.identifier()?;
        let label = metadata.label();
        let planned = public
            .template::<crate::attributes::TemplateSize>(id, label, &options)?
            .owned_bytes()?;
        let publication = VerificationPublicationPlan::new(&public, profiles, fingerprint);
        let identity = [(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_KEY_TYPE, kind)];
        managed::create_public_prepared(
            self,
            id,
            label,
            &options.admission,
            super::public_import::observation::Spec {
                identity: &identity,

                maximum: options.admission.metadata.maximum_bytes,
                mechanisms: &mechanisms,
            },
            Some(super::public_import::publication::Plan::Verification(
                publication,
            )),
            planned,
            || public.template(id, label, &options),
            &reference_admission,
            epoch,
            &mut diagnostics,
            |access| reference_admission.check(access),
            |reference, mechanism_report, publication| {
                let Some(super::public_import::publication::Prepared::Verification(publication)) =
                    publication
                else {
                    return Err(Error::Rejected(crate::RejectionReason::PublicVerification(
                        crate::PublicVerificationRejection::VerificationPublicationAbsent,
                    )));
                };
                Ok(publication.finish(reference, mechanism_report))
            },
        )
    }

    /// Verify a pure Edwards signature over the original message. Cryptographic
    /// validity conveys no owner identity, authorization, or certificate trust.
    /// No prior interoperability witness is required, including for pair.public.
    pub fn verify_pure_eddsa(
        &self,
        key: &VerificationKey,
        message: &[u8],
        signature: &[u8],
        limits: InputLimits,
    ) -> Result<Verification> {
        let mut invocation_diagnostics = crate::crypto::ClassicalDiagnostics::default();
        let diagnostics = &mut invocation_diagnostics;
        self.verify_pure_eddsa_parts(key, &[message], false, signature, limits, diagnostics)
    }
    /// Verify pure Edwards through real Update/Final. Native lack of multipart
    /// support is an operation error, never a request to concatenate or prehash.
    pub fn verify_pure_eddsa_multipart(
        &self,
        key: &VerificationKey,
        parts: &[&[u8]],
        signature: &[u8],
        limits: InputLimits,
    ) -> Result<Verification> {
        let mut invocation_diagnostics = crate::crypto::ClassicalDiagnostics::default();
        let diagnostics = &mut invocation_diagnostics;
        self.verify_pure_eddsa_parts(key, parts, true, signature, limits, diagnostics)
    }
    fn verify_pure_eddsa_parts(
        &self,
        key: &VerificationKey,
        parts: &[&[u8]],
        multipart: bool,
        signature: &[u8],
        limits: InputLimits,
        diagnostics: &mut crate::crypto::ClassicalDiagnostics,
    ) -> Result<Verification> {
        let variant = match key.edwards {
            Some(EdwardsCurve::Ed25519) => super::EdDsaVariant::Ed25519,
            Some(EdwardsCurve::Ed448) => super::EdDsaVariant::Ed448,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::PublicVerification(
                    crate::PublicVerificationRejection::NotAnEdwardsReference,
                )))
            }
        };
        self.verify_eddsa_parts(
            key,
            super::EdDsaParameters::new(variant, &[])?,
            parts,
            multipart,
            signature,
            limits,
            diagnostics,
        )
    }

    /// Verify the original message using an exact RFC 8032 instance/context.
    /// The module performs any instance-specific prehash. Cryptographic validity
    /// does not establish identity, authorization or trust in the public key.
    pub fn verify_eddsa(
        &self,
        key: &VerificationKey,
        parameters: super::EdDsaParameters,
        message: &[u8],
        signature: &[u8],
        limits: InputLimits,
    ) -> Result<Verification> {
        let mut invocation_diagnostics = crate::crypto::ClassicalDiagnostics::default();
        let diagnostics = &mut invocation_diagnostics;
        self.verify_eddsa_parts(
            key,
            parameters,
            &[message],
            false,
            signature,
            limits,
            diagnostics,
        )
    }

    /// Use native Update/Final with the same exact instance/context. A native
    /// multipart refusal propagates; no concatenation or alternate instance is tried.
    pub fn verify_eddsa_multipart(
        &self,
        key: &VerificationKey,
        parameters: super::EdDsaParameters,
        parts: &[&[u8]],
        signature: &[u8],
        limits: InputLimits,
    ) -> Result<Verification> {
        let mut invocation_diagnostics = crate::crypto::ClassicalDiagnostics::default();
        let diagnostics = &mut invocation_diagnostics;
        self.verify_eddsa_parts(key, parameters, parts, true, signature, limits, diagnostics)
    }

    fn verify_eddsa_parts(
        &self,
        key: &VerificationKey,
        parameters: super::EdDsaParameters,
        parts: &[&[u8]],
        multipart: bool,
        signature: &[u8],
        limits: InputLimits,
        diagnostics: &mut crate::crypto::ClassicalDiagnostics,
    ) -> Result<Verification> {
        limits.validate(self.inner.crypto_options.limits, parts)?;
        if key.edwards != Some(parameters.curve()) {
            return Err(Error::Rejected(crate::RejectionReason::PublicVerification(
                crate::PublicVerificationRejection::EddsaInstanceAndKeyCurveDiffer,
            )));
        }

        let width = match parameters.curve() {
            EdwardsCurve::Ed25519 => 64,
            EdwardsCurve::Ed448 => 114,
        };
        if signature.len() != width {
            // Preserve reference validation and result publication, without
            // allocating native buffers for a call that cannot be dispatched.
            let (s, mut readers) = self.managed_read_access([Some(&key.managed)], false)?;
            s.retain_prepared_reader(readers[0].take().expect("prepared key reader"))?;
            self.managed_handle(&s, &key.managed)?;
            return self.public_result(&s, Ok(Verification::Invalid));
        }
        let (_, prepared_signature, _, s) = self.prepare_verification_read_access(
            &key.managed,
            None,
            parts,
            multipart,
            parts.iter().map(|part| part.len()).max().unwrap_or(0),
            signature.len(),
            None,
            None,
            None,
        )?;
        let object = self.managed_handle(&s, &key.managed)?;
        let result = self.verify_native_mechanism(
            &s,
            object,
            CKM_EDDSA,
            parameters.native(),
            parts,
            multipart,
            signature,
            prepared_signature,
            diagnostics,
        );
        self.public_result(&s, result)
    }
}


