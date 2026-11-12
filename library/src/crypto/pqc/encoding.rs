// SPDX-License-Identifier: Apache-2.0
use super::PqcAlgorithm;

use crate::{Error, Result};
use der::{asn1::BitStringRef, Decode, Encode};
use x509_cert::spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};

/// Strictly decoded public representation. This does not prove private possession
/// or claim that the encoded public key is mathematically valid.
pub struct PqcPublicKey {
    algorithm: PqcAlgorithm,
    raw: Vec<u8>,
}

impl PqcPublicKey {
    /// Unpublished observation storage. Zero bytes are never a public result;
    /// the admission owner must validate and replace the entire raw value first.
    pub(super) fn observation_storage(algorithm: PqcAlgorithm) -> Result<Self> {
        let mut raw = Vec::new();
        raw.try_reserve_exact(algorithm.public_key_length())
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                    crate::PostQuantumKeysRejection::PqcPublicAllocation,
                ))
            })?;
        raw.resize(algorithm.public_key_length(), 0);
        Ok(Self { algorithm, raw })
    }

    pub(super) fn observe_raw(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() != self.algorithm.public_key_length() {
            return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcPublicKeyLength,
            )));
        }
        self.raw.copy_from_slice(bytes);
        Ok(())
    }

    /// Hash the canonical DER through the same encoder as `to_spki`, without
    /// retaining a second public-key allocation during native response handling.
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
            Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcPublicEncoding,
            ))
        })?;
        Ok(fingerprint.0.finalize().into())
    }

    pub(super) fn retained_bytes(&self) -> usize {
        self.raw.capacity()
    }
    /// Verify the selected message or prehash through the supplied verification engine.
    /// No PKCS#11 private operation, trust decision or provider fallback occurs.
    /// Input budgets apply to the message; operational engine failures are errors.
    pub fn verify(
        &self,
        engine: &crate::VerifyEngine,
        message: &[u8],
        signature: &PqcSignature,
        parameters: &super::PqcSignatureParameters,
        limits: crate::InputLimits,
    ) -> Result<crate::Verification> {
        super::parameters::validate_message(
            limits,
            crate::CryptoLimits {
                maximum_parts: limits.maximum_parts,
                maximum_total_bytes: limits.maximum_total_bytes,
            },
            message.len(),
        )?;
        parameters.validate_input(message.len())?;
        if signature.algorithm() != self.algorithm {
            return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcSignatureAlgorithmMismatch,
            )));
        }
        let context = crate::crypto::public_verifier::Context::selected(Some(engine))
            .map_err(Error::Rejected)?;
        let key =
            super::public_verifier::PublicKey::new(&context, self).map_err(Error::Rejected)?;
        let operation = key.prepare(parameters).map_err(Error::Rejected)?;
        Ok(
            if operation
                .verify(message, signature.as_bytes())
                .map_err(Error::Rejected)?
            {
                crate::Verification::Valid
            } else {
                crate::Verification::Invalid
            },
        )
    }

    /// Accept exactly the raw public width for the explicitly named variant.
    pub fn from_raw(algorithm: PqcAlgorithm, bytes: &[u8]) -> Result<Self> {
        if bytes.len() != algorithm.public_key_length() {
            return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcPublicKeyLength,
            )));
        }
        Self::copy_validated(algorithm, bytes)
    }

    pub(super) fn copy_validated(algorithm: PqcAlgorithm, bytes: &[u8]) -> Result<Self> {
        let mut raw = Vec::new();
        raw.try_reserve_exact(bytes.len()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcPublicAllocation,
            ))
        })?;
        raw.extend_from_slice(bytes);
        Ok(Self { algorithm, raw })
    }

    /// Decode canonical pure-signature SPKI, rejecting parameters including NULL,
    /// unknown OIDs, nonzero unused bits, wrong lengths and trailing bytes.
    pub fn from_spki(bytes: &[u8]) -> Result<Self> {
        let (algorithm, raw) = Self::borrow_spki(bytes)?;
        Self::copy_validated(algorithm, raw)
    }

    pub(super) fn borrow_spki(bytes: &[u8]) -> Result<(PqcAlgorithm, &[u8])> {
        if bytes.is_empty() {
            return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcPublicSpkiBound,
            )));
        }
        let spki = SubjectPublicKeyInfoRef::from_der(bytes).map_err(|_| {
            Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcPublicSpkiDer,
            ))
        })?;
        if spki.algorithm.parameters.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcPublicParametersMustBeAbsent,
            )));
        }
        let algorithm = PqcAlgorithm::ALL
            .into_iter()
            .find(|algorithm| algorithm.oid() == spki.algorithm.oid)
            .ok_or(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcPublicAlgorithm,
            )))?;
        let raw = spki.subject_public_key.as_bytes().ok_or(Error::Rejected(
            crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcPublicUnusedBits,
            ),
        ))?;
        if raw.len() != algorithm.public_key_length() {
            return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcPublicKeyLength,
            )));
        }
        // Preserve the canonical round-trip check. Its temporary public buffer
        // is released here; only borrowed input survives reference admission.
        if spki.to_der().map_err(|_| {
            Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcPublicEncoding,
            ))
        })? != bytes
        {
            return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcPublicNoncanonicalDer,
            )));
        }
        Ok((algorithm, raw))
    }

    /// Exact parameter set; no classical/PQC or pure/prehash inference.
    pub fn algorithm(&self) -> PqcAlgorithm {
        self.algorithm
    }

    /// Borrow the raw public key. The caller owns any copies it creates.
    pub fn as_raw(&self) -> &[u8] {
        &self.raw
    }

    /// Canonical RFC9881/RFC9909 SubjectPublicKeyInfo, parameters absent.
    pub fn to_spki(&self) -> Result<Vec<u8>> {
        self.spki()?.to_der().map_err(|_| {
            Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcPublicEncoding,
            ))
        })
    }

    fn spki(&self) -> Result<SubjectPublicKeyInfoRef<'_>> {
        Ok(SubjectPublicKeyInfoRef {
            algorithm: AlgorithmIdentifierRef {
                oid: self.algorithm.oid(),
                parameters: None,
            },
            subject_public_key: BitStringRef::from_bytes(&self.raw).map_err(|_| {
                Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                    crate::PostQuantumKeysRejection::PqcPublicBitString,
                ))
            })?,
        })
    }
}

/// Exact-width signature. Construction checks encoding, not validity or mode;
/// the verification parameters explicitly determine the signed domain.
pub struct PqcSignature {
    algorithm: PqcAlgorithm,
    bytes: SignatureBytes,
}

enum SignatureBytes {
    Supplied(Vec<u8>),
    Native(crate::symmetric::memory::Buffer),
}

impl PqcSignature {
    // Caller-owned bytes have no library credit. Native signatures retain
    // their allocation while verification prepares its independent copy.
    pub(super) fn retained_bytes(
        &self,
        budget: &std::sync::Arc<crate::symmetric::memory::Budget>,
    ) -> Result<crate::symmetric::memory::RetainedBytes> {
        crate::symmetric::memory::RetainedBytes::measure(budget, |retained| match &self.bytes {
            SignatureBytes::Native(bytes) => bytes.retain_credit(retained),
            SignatureBytes::Supplied(_) => Ok(()),
        })
    }

    pub(super) fn from_native(
        algorithm: PqcAlgorithm,
        bytes: crate::symmetric::memory::Buffer,
    ) -> Result<Self> {
        if bytes.as_slice().len() != algorithm.signature_length() {
            return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcSignatureLength,
            )));
        }
        Ok(Self {
            algorithm,
            bytes: SignatureBytes::Native(bytes),
        })
    }

    /// Accept exactly the signature width for the declared parameter set.
    pub fn from_bytes(algorithm: PqcAlgorithm, bytes: &[u8]) -> Result<Self> {
        if bytes.len() != algorithm.signature_length() {
            return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcSignatureLength,
            )));
        }
        Ok(Self {
            algorithm,
            bytes: SignatureBytes::Supplied(bytes.to_vec()),
        })
    }

    /// Declared exact algorithm. This is not a verification verdict.
    pub fn algorithm(&self) -> PqcAlgorithm {
        self.algorithm
    }

    /// Raw FIPS signature bytes, with no ASN.1 wrapping.
    pub fn as_bytes(&self) -> &[u8] {
        match &self.bytes {
            SignatureBytes::Supplied(bytes) => bytes,
            SignatureBytes::Native(bytes) => bytes.as_slice(),
        }
    }
}
