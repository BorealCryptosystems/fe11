// SPDX-License-Identifier: Apache-2.0
//! Native protected transport and explicit introduction of secret material.
mod authenticated;
mod kek;
mod oaep;
mod operations;
pub(crate) use operations::UnwrapCall;
mod rsa;
pub(crate) mod secret_keys;
pub(crate) mod secret_template;
use crate::{Error, ManagedObjectRef, Result, SymmetricKeySpec};
pub use kek::{
    AesKeyEncryptionKey, AesKeyEncryptionSpec, KeyTransportUsage, UnwrappingKey, WrappingKey,
};
pub use operations::{KeyWrapProfile, UnwrapParameters, WrapLimits, WrapParameters, WrappedKey};
pub use rsa::{
    RsaKeyEncryptionPair, RsaKeyEncryptionPrivate, RsaKeyEncryptionPublic, RsaKeyEncryptionSpec,
};

/// Origin established by this operation, separate from native history claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntroductionOrigin {
    /// A successful native generation was observed in this invocation.
    Generated,
    /// A successful C_CreateObject introduction was observed in this invocation.
    Imported,
    /// A successful native unwrap was observed in this invocation.
    Unwrapped,
    /// Existing object without an observed LOCAL value; origin is unknown.
    ObservedUnknown,
    /// Existing non-local object; its actual introduction operation is not known.
    ObservedNonLocal,
    /// Existing native-local object; no generation invocation is claimed here.
    ObservedLocal,
}
/// Historical observation, including absence of a caller-requested read.
pub type HistoricalBoolean = crate::Observation<bool>;
/// Historical attributes share the same observation representation as derivation.
pub type TransportHistoricalAttributes = crate::HistoricalAttributes;
/// Exact transport snapshot and the caller-selected plan that produced it.
pub type TransportProtection = crate::BaseProtection;
/// Actual protection attributes and observed origin, without inferred history.
#[derive(Clone, Debug)]
pub struct IntroductionReport {
    origin: IntroductionOrigin,
    protection: TransportProtection,

    public_binding: Option<crate::PrivateEncodingReport>,
    edwards_encoding: Option<crate::EdwardsEncodingReport>,
}
impl IntroductionReport {
    /// Native Edwards parameter representation actually read and decoded.
    /// Absent for other families or when the representation was not observed.
    /// A private-only object carries no public-point observation.
    pub fn edwards_encoding(&self) -> Option<crate::EdwardsEncodingReport> {
        self.edwards_encoding
    }
    pub(crate) fn with_edwards_encoding(
        mut self,
        encoding: Option<crate::EdwardsEncodingReport>,
    ) -> Self {
        self.edwards_encoding = encoding;
        self
    }

    /// Declarations decoded from the supplied PKCS#8 input.
    /// Absent for operations that did not decode a private PKCS#8 input.
    /// These declarations do not establish possession or public/private correspondence.
    pub fn private_encoding_report(&self) -> Option<&crate::PrivateEncodingReport> {
        self.public_binding.as_ref()
    }
    pub(crate) fn with_private_encoding(mut self, binding: crate::PrivateEncodingReport) -> Self {
        self.public_binding = Some(binding);
        self
    }

    /// Operation observed by the library; not an attestation by another authority.
    pub fn origin(&self) -> IntroductionOrigin {
        self.origin
    }
    /// Exact native current and historical values at admission.
    pub fn protection(&self) -> TransportProtection {
        self.protection
    }
    /// Both historical booleans were returned, independently of their truth or coherence.
    pub fn history_complete(&self) -> bool {
        matches!(
            self.protection.historical.always_sensitive,
            HistoricalBoolean::Observed(_)
        ) && matches!(
            self.protection.historical.never_extractable,
            HistoricalBoolean::Observed(_)
        )
    }
}
/// Native destination requests and observations for symmetric key introduction.
/// Import checks the supplied material length; it does not implicitly compare
/// the module's reported CKA_VALUE_LEN. Unwrap's length request depends on the
/// selected table; see [`crate::Session::unwrap_symmetric_key`]. Selected public
/// attributes remain observations, not automatic comparisons with a policy.
pub struct SymmetricIntroductionSpec {
    /// Native SENSITIVE/EXTRACTABLE request, independent of observations and routing.
    pub native_protection: crate::CurrentKeyProtection,
    /// Explicit native history/protection reads and their aggregate budget.
    pub history_observation: crate::HistoryObservationPlan,
    /// Requested algorithm, type, identity, usages and object observations at
    /// the destination. The selected size is not a native length observation;
    /// AES Unwrap on tables through 3.1 omits the length attribute.
    /// The outer native_protection and history_observation fields govern this
    /// introduction; key.protection_request and key.history are not used.
    pub key: SymmetricKeySpec,
}
impl SymmetricIntroductionSpec {
    pub(crate) fn validate(&self) -> Result<()> {
        self.key.validate()?;
        Ok(())
    }
}
struct IntroducedKeyMaterial {
    managed: ManagedObjectRef,
    algorithm: crate::SymmetricAlgorithm,
    allowed: crate::MechanismObservationReport,
}
impl IntroducedKeyMaterial {
    fn view(&self) -> crate::symmetric::SymmetricKeyView<'_> {
        crate::symmetric::SymmetricKeyView {
            managed: &self.managed,
            algorithm: self.algorithm,
        }
    }
}
/// Introduced operation key, with exact potentially incomplete native history.
/// It is an imported reference and exposes no fabricated SymmetricProtection.
pub struct IntroducedSymmetricKey {
    key: IntroducedKeyMaterial,
    report: IntroductionReport,
}
impl IntroducedSymmetricKey {
    /// Exact native mechanism observation and the read selection that produced it.
    pub fn mechanism_report(&self) -> &crate::MechanismObservationReport {
        &self.key.allowed
    }
    /// Bound native identity without exposing a handle or a secret value.
    pub fn managed(&self) -> &ManagedObjectRef {
        &self.key.managed
    }
    /// Selected current and historical observations, including missing reads.
    pub fn report(&self) -> IntroductionReport {
        self.report.clone()
    }
    /// Caller-selected algorithm retained for operation routing.
    /// Observing the native class and key type does not establish its length.
    /// In particular, AES Unwrap on tables through 3.1 does not transmit the
    /// selected size. Consult an explicit CKA_VALUE_LEN observation when needed;
    /// see [`crate::Session::unwrap_symmetric_key`].
    pub fn algorithm(&self) -> crate::SymmetricAlgorithm {
        self.key.algorithm
    }
}

