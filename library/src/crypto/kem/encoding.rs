// SPDX-License-Identifier: Apache-2.0

use crate::{Error, Result};
use der::{
    asn1::{BitStringRef, ObjectIdentifier},
    Decode, Encode,
};
use fe11_sys::*;
use x509_cert::spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};

/// FIPS203 parameter set. No vendor alias or implicit variant selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlKemParameterSet {
    /// ML-KEM-512.
    MlKem512,
    /// ML-KEM-768.
    MlKem768,
    /// ML-KEM-1024.
    MlKem1024,
}

impl MlKemParameterSet {
    /// All three standardized variants in increasing parameter order.
    pub const ALL: [Self; 3] = [Self::MlKem512, Self::MlKem768, Self::MlKem1024];

    /// FIPS203 encapsulation key length in bytes.
    pub fn public_key_length(self) -> usize {
        match self {
            Self::MlKem512 => 800,
            Self::MlKem768 => 1184,
            Self::MlKem1024 => 1568,
        }
    }

    /// FIPS203 ciphertext length in bytes.
    pub fn ciphertext_length(self) -> usize {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
        }
    }

    pub(super) fn raw(self) -> CK_ML_KEM_PARAMETER_SET_TYPE {
        match self {
            Self::MlKem512 => CKP_ML_KEM_512,
            Self::MlKem768 => CKP_ML_KEM_768,
            Self::MlKem1024 => CKP_ML_KEM_1024,
        }
    }

    fn oid(self) -> ObjectIdentifier {
        match self {
            Self::MlKem512 => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.1"),
            Self::MlKem768 => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.2"),
            Self::MlKem1024 => ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.3"),
        }
    }
}

/// Canonical encapsulation key. Parsing does not authenticate the recipient.
pub struct KemPublicKey {
    parameter_set: MlKemParameterSet,
    raw: Vec<u8>,
}

impl KemPublicKey {
    /// Private, unpublished receive storage. The admission state permits no
    /// export until observe_raw has validated and replaced the complete value.
    pub(super) fn observation_storage(parameter_set: MlKemParameterSet) -> Result<Self> {
        let mut raw = Vec::new();
        raw.try_reserve_exact(parameter_set.public_key_length())
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                    crate::KeyEncapsulationRejection::MlKemPublicAllocation,
                ))
            })?;
        raw.resize(parameter_set.public_key_length(), 0);
        Ok(Self { parameter_set, raw })
    }

    pub(super) fn observe_raw(&mut self, bytes: &[u8]) -> Result<()> {
        Self::validate_raw(self.parameter_set, bytes)?;
        self.raw.copy_from_slice(bytes);
        Ok(())
    }

    pub(in crate::crypto) fn retained_bytes(&self) -> usize {
        self.raw.capacity()
    }
    /// Check exact FIPS203 width and canonical12-bit coefficient encoding.
    /// This is public input validation, not a private-key possession proof.
    pub fn from_raw(parameter_set: MlKemParameterSet, bytes: &[u8]) -> Result<Self> {
        Self::validate_raw(parameter_set, bytes)?;
        Self::copy_validated(parameter_set, bytes)
    }

    pub(crate) fn validate_raw(parameter_set: MlKemParameterSet, bytes: &[u8]) -> Result<()> {
        if bytes.len() != parameter_set.public_key_length() {
            return Err(Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                crate::KeyEncapsulationRejection::MlKemPublicKeyLength,
            )));
        }
        // FIPS203§7.2 modulus check: ByteDecode12 must produce coefficients<q.
        // The trailing32bytes are rho, not polynomial coefficients.
        for triple in bytes[..bytes.len() - 32].chunks_exact(3) {
            let first = u16::from(triple[0]) | (u16::from(triple[1] & 15) << 8);
            let second = u16::from(triple[1] >> 4) | (u16::from(triple[2]) << 4);
            if first >= 3329 || second >= 3329 {
                return Err(Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                    crate::KeyEncapsulationRejection::MlKemPublicCoefficientEncoding,
                )));
            }
        }
        Ok(())
    }

    pub(super) fn copy_validated(parameter_set: MlKemParameterSet, bytes: &[u8]) -> Result<Self> {
        let mut raw = Vec::new();
        raw.try_reserve_exact(bytes.len()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                crate::KeyEncapsulationRejection::MlKemPublicAllocation,
            ))
        })?;
        raw.extend_from_slice(bytes);
        Ok(Self { parameter_set, raw })
    }

    /// Decode canonical RFC9935 SPKI, with absent parameters and no trailing data.
    pub fn from_spki(bytes: &[u8]) -> Result<Self> {
        let (parameter_set, raw) = Self::borrow_spki(bytes)?;
        Self::copy_validated(parameter_set, raw)
    }

    pub(super) fn borrow_spki(bytes: &[u8]) -> Result<(MlKemParameterSet, &[u8])> {
        if bytes.is_empty() {
            return Err(Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                crate::KeyEncapsulationRejection::MlKemSpkiLength,
            )));
        }
        let spki = SubjectPublicKeyInfoRef::from_der(bytes).map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                crate::KeyEncapsulationRejection::MlKemSpkiDer,
            ))
        })?;
        if spki.algorithm.parameters.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                crate::KeyEncapsulationRejection::MlKemSpkiParametersMustBeAbsent,
            )));
        }
        let parameter_set = MlKemParameterSet::ALL
            .into_iter()
            .find(|value| value.oid() == spki.algorithm.oid)
            .ok_or(Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                crate::KeyEncapsulationRejection::MlKemSpkiAlgorithm,
            )))?;
        let raw = spki.subject_public_key.as_bytes().ok_or(Error::Rejected(
            crate::RejectionReason::KeyEncapsulation(
                crate::KeyEncapsulationRejection::MlKemSpkiUnusedBits,
            ),
        ))?;
        Self::validate_raw(parameter_set, raw)?;
        if spki.to_der().map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                crate::KeyEncapsulationRejection::MlKemSpkiEncoding,
            ))
        })? != bytes
        {
            return Err(Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                crate::KeyEncapsulationRejection::MlKemNoncanonicalSpki,
            )));
        }
        Ok((parameter_set, raw))
    }

    /// Encode canonical RFC9935 SPKI. AlgorithmIdentifier parameters are absent.
    pub fn to_spki(&self) -> Result<Vec<u8>> {
        self.spki()?.to_der().map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                crate::KeyEncapsulationRejection::MlKemSpkiEncoding,
            ))
        })
    }

    /// Use the export encoder directly so metadata has identical DER bytes,
    /// including absent algorithm parameters, without a temporary DER vector.
    pub(super) fn spki_fingerprint(&self) -> Result<[u8; 32]> {
        use sha2::Digest;
        struct Fingerprint(sha2::Sha256);
        impl der::Writer for Fingerprint {
            fn write(&mut self, bytes: &[u8]) -> der::Result<()> {
                self.0.update(bytes);
                Ok(())
            }
        }
        let mut fingerprint = Fingerprint(sha2::Sha256::new());
        self.spki()?.encode(&mut fingerprint).map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                crate::KeyEncapsulationRejection::MlKemSpkiEncoding,
            ))
        })?;
        Ok(fingerprint.0.finalize().into())
    }

    fn spki(&self) -> Result<SubjectPublicKeyInfoRef<'_>> {
        Ok(SubjectPublicKeyInfoRef {
            algorithm: AlgorithmIdentifierRef {
                oid: self.parameter_set.oid(),
                parameters: None,
            },
            subject_public_key: BitStringRef::from_bytes(&self.raw).map_err(|_| {
                Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                    crate::KeyEncapsulationRejection::MlKemPublicBitString,
                ))
            })?,
        })
    }

    /// Exact standardized parameter set.
    pub fn parameter_set(&self) -> MlKemParameterSet {
        self.parameter_set
    }

    /// Public FIPS203 encapsulation key bytes, never private key material.
    pub fn as_raw(&self) -> &[u8] {
        &self.raw
    }
}

enum CiphertextBytes {
    Supplied(Vec<u8>),
    Native(crate::symmetric::memory::Buffer),
}

/// Exact-width public ciphertext. Correct width is not cryptographic validity.
pub struct KemCiphertext {
    parameter_set: MlKemParameterSet,
    bytes: CiphertextBytes,
}

impl KemCiphertext {
    /// Accept an exact-width public input without testing secret-dependent validity.
    pub fn from_bytes(parameter_set: MlKemParameterSet, bytes: &[u8]) -> Result<Self> {
        if bytes.len() != parameter_set.ciphertext_length() {
            return Err(Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                crate::KeyEncapsulationRejection::MlKemCiphertextLength,
            )));
        }
        Ok(Self {
            parameter_set,
            bytes: CiphertextBytes::Supplied(bytes.to_vec()),
        })
    }

    pub(super) fn from_native(
        parameter_set: MlKemParameterSet,
        bytes: crate::symmetric::memory::Buffer,
    ) -> Self {
        Self {
            parameter_set,
            bytes: CiphertextBytes::Native(bytes),
        }
    }

    /// Exact standardized parameter set, without a validity assertion.
    pub fn parameter_set(&self) -> MlKemParameterSet {
        self.parameter_set
    }

    /// Public ciphertext. A native result retains its memory credit while held.
    pub fn as_bytes(&self) -> &[u8] {
        match &self.bytes {
            CiphertextBytes::Supplied(bytes) => bytes,
            CiphertextBytes::Native(bytes) => bytes.as_slice(),
        }
    }
}
