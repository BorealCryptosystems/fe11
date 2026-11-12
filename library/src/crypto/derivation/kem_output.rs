// SPDX-License-Identifier: Apache-2.0
//! Reuse existing secret owners without exporting their fields or raw handles.
use super::{keys::BaseSpec, *};
use crate::{
    attributes::Template,
    crypto::kem::{KemSharedKey, KemSharedKeySpec},
};

pub(crate) fn id(spec: &KemSharedKeySpec) -> &[u8] {
    match spec {
        KemSharedKeySpec::Symmetric(spec) => &spec.id,
        KemSharedKeySpec::Hkdf { key: spec, .. } => &spec.id,
    }
}

pub(crate) fn admission(spec: &KemSharedKeySpec) -> &crate::ObjectAdmission {
    match spec {
        KemSharedKeySpec::Symmetric(spec) => &spec.admission,
        KemSharedKeySpec::Hkdf { key: spec, .. } => &spec.admission,
    }
}
pub(crate) fn label(spec: &KemSharedKeySpec) -> &[u8] {
    match spec {
        KemSharedKeySpec::Symmetric(spec) => spec.label.as_bytes(),
        KemSharedKeySpec::Hkdf { key: spec, .. } => spec.label.as_bytes(),
    }
}

pub(crate) fn validate(spec: &KemSharedKeySpec) -> Result<()> {
    match spec {
        KemSharedKeySpec::Symmetric(spec) => validate_symmetric(spec),
        KemSharedKeySpec::Hkdf { key: spec, .. } => {
            identity(&spec.id, &spec.label)?;
            if spec.length != 32 {
                return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::MlKemSharedSecretLengthIs32Bytes,
                )));
            }
            Ok(())
        }
    }
}

pub(crate) fn validate_symmetric(spec: &crate::SymmetricKeySpec) -> Result<()> {
    spec.validate()?;
    // ML-KEM returns a 32-byte raw secret. A smaller/larger destination
    // requires an explicit subsequent KDF, never local truncation.
    if spec.algorithm.key_length() != 32 {
        return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
            crate::KeyDerivationRejection::MlKemSharedSecretLengthIs32Bytes,
        )));
    }
    Ok(())
}

pub(crate) fn template(spec: &KemSharedKeySpec) -> Result<Template> {
    template_as(spec)
}
pub(crate) fn template_as<T: crate::attributes::TemplateSink>(
    spec: &KemSharedKeySpec,
) -> Result<T> {
    match spec {
        KemSharedKeySpec::Symmetric(spec) => crate::symmetric::keys::generation_template_as(spec),
        KemSharedKeySpec::Hkdf {
            key: spec, current, ..
        } => BaseSpec::Hkdf(spec).template_as(*current),
    }
}

pub(crate) fn observation_spec(spec: &KemSharedKeySpec) -> super::output_observation::Spec<'_> {
    match spec {
        KemSharedKeySpec::Symmetric(spec) => super::output_observation::Spec::symmetric(spec),
        KemSharedKeySpec::Hkdf { key, history, .. } => {
            super::output_observation::Spec::hkdf(key, *history)
        }
    }
}

pub(crate) fn finish_observed(
    managed: crate::ManagedObjectRef,
    spec: KemSharedKeySpec,
    evidence: super::output_observation::Evidence,
) -> Result<KemSharedKey> {
    use super::output_observation::Evidence;
    match (spec, evidence) {
        (
            KemSharedKeySpec::Symmetric(spec),
            Evidence::Symmetric {
                protection,
                mechanisms,
            },
        ) => Ok(KemSharedKey::Symmetric(SymmetricKey {
            managed,
            algorithm: spec.algorithm,
            protection,
            allowed: mechanisms,
        })),
        (
            KemSharedKeySpec::Hkdf { key: spec, .. },
            Evidence::Hkdf {
                protection,
                mechanisms,
            },
        ) => Ok(KemSharedKey::Hkdf(HkdfKey {
            mechanism_report: mechanisms,
            managed,
            spec,
            protection,
        })),
        _ => Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
            crate::KeyDerivationRejection::KemOutputEvidenceFamilyMismatch,
        ))),
    }
}
