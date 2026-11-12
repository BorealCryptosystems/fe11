// SPDX-License-Identifier: Apache-2.0
//! Owned ML-DSA/ML-KEM private representations; no generic public attribute bytes.

use crate::{
    attributes::RequiredAttributes, bounds, symmetric::memory::Buffer, Error, ManagedClass,
    ManagedObjectRef, MlDsaParameterSet, MlKemParameterSet, Result, Session,
};
use fe11_sys::*;

mod export;

mod resident;
pub(crate) use resident::PqcExportOwner;

mod import;
pub use import::{PqcImportedPrivateKey, PqcPrivateImportSpec, PqcPrivateInput};

/// Families with CKA_SEED/CKA_VALUE representations in PKCS#11 3.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqcPrivateKeyAlgorithm {
    /// FIPS 204, 32-byte seed and expanded signing key.
    MlDsa(MlDsaParameterSet),
    /// FIPS 203, 64-byte d||z seed and expanded decapsulation key.
    MlKem(MlKemParameterSet),
}

impl PqcPrivateKeyAlgorithm {
    fn public_length(self) -> usize {
        match self {
            Self::MlDsa(MlDsaParameterSet::MlDsa44) => 1312,
            Self::MlDsa(MlDsaParameterSet::MlDsa65) => 1952,
            Self::MlDsa(MlDsaParameterSet::MlDsa87) => 2592,
            Self::MlKem(parameter) => parameter.public_key_length(),
        }
    }
    /// Exact normative seed length, not an entropy or security-strength claim.
    pub fn seed_length(self) -> usize {
        match self {
            Self::MlDsa(_) => 32,
            Self::MlKem(_) => 64,
        }
    }

    /// Exact FIPS expanded private-key encoding length.
    pub fn value_length(self) -> usize {
        match self {
            Self::MlDsa(MlDsaParameterSet::MlDsa44) => 2560,
            Self::MlDsa(MlDsaParameterSet::MlDsa65) => 4032,
            Self::MlDsa(MlDsaParameterSet::MlDsa87) => 4896,
            Self::MlKem(MlKemParameterSet::MlKem512) => 1632,
            Self::MlKem(MlKemParameterSet::MlKem768) => 2400,
            Self::MlKem(MlKemParameterSet::MlKem1024) => 3168,
        }
    }

    fn from_native(kind: CK_KEY_TYPE, parameter: CK_ULONG) -> Result<Self> {
        match (kind, parameter) {
            (CKK_ML_DSA, CKP_ML_DSA_44) => Ok(Self::MlDsa(MlDsaParameterSet::MlDsa44)),
            (CKK_ML_DSA, CKP_ML_DSA_65) => Ok(Self::MlDsa(MlDsaParameterSet::MlDsa65)),
            (CKK_ML_DSA, CKP_ML_DSA_87) => Ok(Self::MlDsa(MlDsaParameterSet::MlDsa87)),
            (CKK_ML_KEM, CKP_ML_KEM_512) => Ok(Self::MlKem(MlKemParameterSet::MlKem512)),
            (CKK_ML_KEM, CKP_ML_KEM_768) => Ok(Self::MlKem(MlKemParameterSet::MlKem768)),
            (CKK_ML_KEM, CKP_ML_KEM_1024) => Ok(Self::MlKem(MlKemParameterSet::MlKem1024)),
            _ => Err(Error::Unsupported(
                crate::UnsupportedReason::PostQuantumKeys(
                    crate::PostQuantumKeysUnsupported::PqcPrivateRepresentationFamilyOrParameter,
                ),
            )),
        }
    }
}

/// Explicit attributes to export. An unavailable form never selects another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqcPrivateEncoding {
    /// Read only CKA_SEED.
    Seed,
    /// Read only CKA_VALUE.
    Value,
    /// Read both in one native attribute call; never publish a partial result.
    SeedAndValue,
}

enum Components {
    Seed(Buffer),
    Value(Buffer),
    SeedAndValue { seed: Buffer, value: Buffer },
}

#[doc = include_str!("../../docs/api/crypto/pqc_material/PqcPrivateExport.md")]
pub struct PqcPrivateExport {
    property_reports: Option<(
        crate::ObjectObservationReport,
        crate::ObjectObservationReport,
    )>,
    algorithm: PqcPrivateKeyAlgorithm,
    components: Components,
}

impl PqcPrivateExport {
    /// Native property observations immediately before and after the private read.
    /// None denotes an internal allocation without completed native export evidence.
    pub fn property_reports(
        &self,
    ) -> Option<(
        &crate::ObjectObservationReport,
        &crate::ObjectObservationReport,
    )> {
        self.property_reports
            .as_ref()
            .map(|(before, after)| (before, after))
    }
    /// Algorithm and parameter set observed on the private object.
    pub fn algorithm(&self) -> PqcPrivateKeyAlgorithm {
        self.algorithm
    }

    /// The exact representation requested, without an implicit conversion.
    pub fn encoding(&self) -> PqcPrivateEncoding {
        match self.components {
            Components::Seed(_) => PqcPrivateEncoding::Seed,
            Components::Value(_) => PqcPrivateEncoding::Value,
            Components::SeedAndValue { .. } => PqcPrivateEncoding::SeedAndValue,
        }
    }

    /// Borrow seed bytes only when explicitly requested; do not log them.
    pub fn seed(&self) -> Option<&[u8]> {
        match &self.components {
            Components::Seed(seed) | Components::SeedAndValue { seed, .. } => Some(seed.as_slice()),
            Components::Value(_) => None,
        }
    }

    /// Borrow expanded private bytes only when explicitly requested.
    pub fn value(&self) -> Option<&[u8]> {
        match &self.components {
            Components::Value(value) | Components::SeedAndValue { value, .. } => {
                Some(value.as_slice())
            }
            Components::Seed(_) => None,
        }
    }

    // Heap buffers stay owned and cannot resize. The descriptors are internal
    // and move into the native frame with this owner before dispatch.
    fn descriptors(&mut self) -> Result<([CK_ATTRIBUTE; 2], usize)> {
        let descriptor = |kind, buffer: &mut Buffer| -> Result<CK_ATTRIBUTE> {
            Ok(CK_ATTRIBUTE {
                r#type: kind,
                pValue: buffer.as_mut().as_mut_ptr().cast(),
                ulValueLen: bounds::ck_length(buffer.capacity())?,
            })
        };
        let mut fields = std::array::from_fn(|_| crate::native::output::attribute());
        let count = match &mut self.components {
            Components::Seed(seed) => {
                fields[0] = descriptor(CKA_SEED, seed)?;
                1
            }
            Components::Value(value) => {
                fields[0] = descriptor(CKA_VALUE, value)?;
                1
            }
            Components::SeedAndValue { seed, value } => {
                fields[0] = descriptor(CKA_SEED, seed)?;
                fields[1] = descriptor(CKA_VALUE, value)?;
                2
            }
        };
        Ok((fields, count))
    }
}

fn validate_descriptors(actual: &[CK_ATTRIBUTE], expected: &[CK_ATTRIBUTE]) -> Result<()> {
    if actual.len() != expected.len()
        || actual.iter().zip(expected).any(|(value, original)| {
            value.r#type != original.r#type
                || value.pValue != original.pValue
                || value.ulValueLen != original.ulValueLen
        })
    {
        return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
            crate::PostQuantumKeysRejection::PqcPrivateAttributeDescriptorOrLength,
        )));
    }
    Ok(())
}

fn validate_exportable(attributes: &RequiredAttributes) -> Result<PqcPrivateKeyAlgorithm> {
    attributes.integer(CKA_CLASS, CKO_PRIVATE_KEY)?;
    // Decode the native family to size this explicitly requested representation.
    // Disclosure permissions and key validity remain the module's responsibility.
    let integer = |kind| -> Result<CK_ULONG> {
        Ok(CK_ULONG::from_ne_bytes(
            attributes.bytes(kind)?.try_into().map_err(|_| {
                Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                    crate::PostQuantumKeysRejection::PqcPrivateIdentityEncoding,
                ))
            })?,
        ))
    };
    PqcPrivateKeyAlgorithm::from_native(integer(CKA_KEY_TYPE)?, integer(CKA_PARAMETER_SET)?)
}

impl Session {
    /// Export the explicitly selected ML-DSA/ML-KEM private attributes.
    /// Requires a current private-key management reference and native acceptance.
    /// The supplied admission selects property observations before and after
    /// the private read; the module enforces native access permissions.
    /// No sizing call, representation fallback, signature or decapsulation is used.
    /// All requested components must be available at their exact FIPS lengths.
    /// The session retains any private result during resource waits for the final
    /// observations, together with the original reader and authentication epoch.
    /// An observation failure does not publish a partial export or repeat its read.
    pub fn export_pqc_private_key(
        &self,
        key: &ManagedObjectRef,
        encoding: PqcPrivateEncoding,
        admission: crate::ObjectAdmission,
    ) -> Result<PqcPrivateExport> {
        resident::export(self, key, encoding, admission)
    }
}
