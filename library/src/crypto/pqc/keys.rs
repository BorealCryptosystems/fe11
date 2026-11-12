// SPDX-License-Identifier: Apache-2.0
use super::{PqcAlgorithm, PqcPublicKey};
use crate::{ManagedObjectRef, Result};

/// Native PQC generation selector. Private bytes are never supplied or returned.
pub struct PqcKeySpec {
    /// Exact native public-key usage requests, independent of observations.
    pub public_usages: crate::KeyUsageRequest,
    /// Exact native private-key usage requests, independent of observations.
    pub private_usages: crate::KeyUsageRequest,
    /// Exact CKA_PRIVATE request for the private native object.
    pub private_visibility: crate::ObjectVisibility,
    /// Independent observations for the public object, when produced.
    pub public_admission: crate::ObjectAdmission,
    /// Independent observations for the private object, when produced.
    pub private_admission: crate::ObjectAdmission,
    /// Exact standardized parameter set.
    pub algorithm: PqcAlgorithm,
    /// Native CKA_ID bytes; destination observations are selected independently.
    pub id: Vec<u8>,
    /// UTF-8 native label; no library-defined presentation policy.
    pub label: String,
    /// Token objects require an authorized read/write session. Session objects
    /// remain attached to the creating session and are not portable handles.
    pub persistent: bool,
}

impl PqcKeySpec {
    pub(super) fn validate(&self) -> Result<()> {
        crate::bounds::metadata_lengths(&self.id, self.label.as_bytes())?;
        validate_observation_budgets(
            self.algorithm,
            &self.public_admission,
            &self.private_admission,
        )
    }
}

pub(super) fn validate_observation_budgets(
    algorithm: PqcAlgorithm,
    public_admission: &crate::ObjectAdmission,
    private_admission: &crate::ObjectAdmission,
) -> Result<()> {
    let identity_bytes = 3 * std::mem::size_of::<fe11_sys::CK_ULONG>();
    if public_admission.metadata.maximum_bytes < identity_bytes.max(algorithm.public_key_length())
        || private_admission.metadata.maximum_bytes < identity_bytes
    {
        return Err(crate::Error::Rejected(
            crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcPairObservationBudget,
            ),
        ));
    }
    Ok(())
}

/// Private reference with selected native object and mechanism observations.
/// The retained observations neither attest possession nor authorize later operations.
pub struct PqcSigningKey {
    pub(super) managed: ManagedObjectRef,
    pub(super) algorithm: PqcAlgorithm,
    pub(super) fingerprint: [u8; 32],
    pub(super) policy: crate::MechanismObservationReport,
}

impl PqcSigningKey {
    /// Exact selected mechanism admission and its native evidence.
    pub fn mechanism_report(&self) -> &crate::MechanismObservationReport {
        &self.policy
    }
    /// Exact parameter set, independent of mechanism support on another session.
    pub fn algorithm(&self) -> PqcAlgorithm {
        self.algorithm
    }

    /// SHA256 of the canonical SPKI associated during admission; consult the witness report.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// Administrative operations share revocation with this signing reference.
    pub fn management_reference(&self) -> &ManagedObjectRef {
        &self.managed
    }
}

/// Session-bound public-only reference, sharing object revocation and ownership.
pub struct PqcVerificationKey {
    pub(super) managed: ManagedObjectRef,
    pub(super) algorithm: PqcAlgorithm,
    pub(super) fingerprint: [u8; 32],
    pub(super) policy: crate::MechanismObservationReport,
}

impl PqcVerificationKey {
    /// Exact selected mechanism admission and its native evidence.
    pub fn mechanism_report(&self) -> &crate::MechanismObservationReport {
        &self.policy
    }
    /// The native CKA_ALLOWED_MECHANISMS list observed during admission.
    /// None means that the attribute was unavailable or indeterminate, not that
    /// every mechanism is permitted. This does not add an operation-time gate.
    /// This is an admission observation, not a fresh native attribute query.
    pub fn allowed_mechanisms(&self) -> Option<Vec<u64>> {
        match self.policy.observation() {
            crate::Observation::Observed(values) => Some(values.clone()),
            _ => None,
        }
    }

    /// Exact signature parameter set.
    pub fn algorithm(&self) -> PqcAlgorithm {
        self.algorithm
    }

    /// SHA256 of the canonical public SPKI, not a certificate trust verdict.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// Administrative operations share revocation with this public reference.
    pub fn management_reference(&self) -> &ManagedObjectRef {
        &self.managed
    }
}

/// Generated or readmitted pair with the caller-selected possession observation.
pub struct PqcKeyPair {
    /// Public native verification capability.
    pub public: PqcVerificationKey,
    /// Opaque private signature capability.
    pub private: PqcSigningKey,
    /// Canonical public representation for other consumers and verifiers.
    pub public_key: PqcPublicKey,
}
