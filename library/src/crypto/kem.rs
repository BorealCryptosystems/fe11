// SPDX-License-Identifier: Apache-2.0
//! ML-KEM: explicit variants, owned ciphertexts and protected native results.

mod admission;
mod encoding;
mod operations;
pub(crate) use operations::{CompletedKem, KemCall};
mod owned;
pub(crate) use owned::{
    KemBoundOwnerStorage, KemOwnerPlan, KemOwnerStorage, KemPairInitial, KemPairPlan,
    KemPairStorage, PreparedKemPair,
};


pub use encoding::{KemCiphertext, KemPublicKey, MlKemParameterSet};

use crate::{HkdfKey, HkdfKeySpec, ManagedObjectRef, SymmetricKey, SymmetricKeySpec};

/// Identification of a generated native ML-KEM pair.
pub struct KemKeySpec {
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
    pub parameter_set: MlKemParameterSet,
    /// Native CKA_ID bytes; destination observations are selected independently.
    pub id: Vec<u8>,
    /// UTF-8 native label; no library-defined presentation policy.
    pub label: String,
    /// Token objects if true; otherwise creator-session objects.
    pub persistent: bool,
}

impl KemKeySpec {
    fn validate(&self) -> crate::Result<()> {
        identity(&self.id, &self.label)?;
        validate_observation_budgets(
            self.parameter_set,
            &self.public_admission,
            &self.private_admission,
        )
    }
}

fn validate_observation_budgets(
    parameter_set: MlKemParameterSet,
    public: &crate::ObjectAdmission,
    private: &crate::ObjectAdmission,
) -> crate::Result<()> {
    // Identity scalars and public value are separate reads. The known minimum
    // follows the ABI and parameter set, for both generation and selection.
    let identity_bytes = 3 * std::mem::size_of::<fe11_sys::CK_ULONG>();
    if public.metadata.maximum_bytes < identity_bytes.max(parameter_set.public_key_length())
        || private.metadata.maximum_bytes < identity_bytes
    {
        return Err(crate::Error::Rejected(
            crate::RejectionReason::KeyEncapsulation(
                crate::KeyEncapsulationRejection::MlKemPairObservationBudget,
            ),
        ));
    }
    Ok(())
}

fn identity(id: &[u8], label: &str) -> crate::Result<()> {
    crate::bounds::metadata_lengths(id, label.as_bytes())
}

/// Admitted public encapsulation capability, without a certificate trust claim.
pub struct KemEncapsulationKey {
    managed: ManagedObjectRef,
    public: KemPublicKey,
    allowed: crate::MechanismObservationReport,
}

impl KemEncapsulationKey {
    /// Exact mechanism observation and caller-requested observation.
    pub fn mechanism_report(&self) -> &crate::MechanismObservationReport {
        &self.allowed
    }
    /// Canonical public identity; the consumer authenticates the recipient.
    pub fn public_key(&self) -> &KemPublicKey {
        &self.public
    }

    /// Administrative reference sharing revocation with this capability.
    pub fn managed(&self) -> &ManagedObjectRef {
        &self.managed
    }
}

/// Admitted private decapsulation capability with explicitly requested protection.
pub struct KemDecapsulationKey {
    managed: ManagedObjectRef,
    parameter_set: MlKemParameterSet,
    allowed: crate::MechanismObservationReport,
}

impl KemDecapsulationKey {
    /// Exact mechanism observation and caller-requested observation.
    pub fn mechanism_report(&self) -> &crate::MechanismObservationReport {
        &self.allowed
    }
    /// Selected native protection observations; NotRequested is not the request.
    /// This getter performs no fresh read and makes no unconditional protection claim.
    pub fn protection(&self) -> crate::ObservedCurrentKeyProtection {
        let report = self.managed.object_observations();
        crate::ObservedCurrentKeyProtection {
            sensitive: report.observation(crate::ObjectBooleanAttribute::Sensitive),
            extractable: report.observation(crate::ObjectBooleanAttribute::Extractable),
        }
    }

    /// Exact standardized parameter set.
    pub fn parameter_set(&self) -> MlKemParameterSet {
        self.parameter_set
    }

    /// Administrative reference sharing revocation with this capability.
    pub fn managed(&self) -> &ManagedObjectRef {
        &self.managed
    }
}

/// Two admitted ML-KEM references from generation or explicit existing selection.
/// Generation records one native pair creation. Existing selection binds the
/// public SPKI and each object's identity; it does not prove that the private
/// key corresponds mathematically. Neither route authenticates a peer.
pub struct KemKeyPair {
    /// Public encapsulation capability and canonical public representation.
    pub public: KemEncapsulationKey,
    /// Opaque private decapsulation capability.
    pub private: KemDecapsulationKey,
}

/// Typed usage of the 32-byte native shared secret. No KDF is added implicitly.
/// For a caller-defined destination template, use [`crate::Session::encapsulate_native`]
/// or [`crate::Session::decapsulate_native`] with [`crate::NativeKemParameters::MlKem`]
/// and the same key's managed reference. That route accepts [`crate::GenerationTemplate`]
/// without converting its attributes into this convenience catalogue.
pub enum KemSharedKeySpec {
    /// Any symmetric selection requesting exactly 32 key bytes: AES256,
    /// ChaCha20 or an HMAC hash with an explicit 32-byte key. No KDF is added.
    Symmetric(SymmetricKeySpec),
    /// Derive-only32-byte base through the existing explicit HKDF operations.
    Hkdf {
        /// Native destination identity and key type.
        key: HkdfKeySpec,
        /// Native SENSITIVE/EXTRACTABLE request, separate from admission.
        current: crate::CurrentKeyProtection,
        /// Explicit native history and protection observations for the destination.
        history: crate::HistoryObservationPlan,
    },
}

/// Opaque native shared secret; protection is described by its observations.
pub enum KemSharedKey {
    /// Existing symmetric capability with its actual native protection history.
    Symmetric(SymmetricKey),
    /// Existing HKDF capability with its actual native protection history.
    Hkdf(HkdfKey),
}

impl KemSharedKey {
    /// Explicit destruction uses this reference; Drop alone does not destroy a
    /// token object. Creator-session objects disappear on successful session close.
    pub fn managed(&self) -> &ManagedObjectRef {
        match self {
            Self::Symmetric(key) => key.managed(),
            Self::Hkdf(key) => key.managed(),
        }
    }
}

/// Public ciphertext and protected secret created by one encapsulation call.
pub struct KemEncapsulation {
    /// Public bytes to transmit to the recipient; their integrity belongs to
    /// the consuming protocol.
    pub ciphertext: KemCiphertext,
    /// Protected local shared secret with the explicitly selected usage.
    pub shared_key: KemSharedKey,
}
