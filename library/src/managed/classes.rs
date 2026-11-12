// SPDX-License-Identifier: Apache-2.0
//! Standard object classes and their distinct metadata contracts.
use fe11_sys::*;

/// Native object class. Standard classes are usable for administrative references;
/// preserving an unknown identifier does not establish its vendor contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ManagedClass {
    /// CKO_DATA.
    Data,
    /// CKO_CERTIFICATE.
    Certificate,
    /// CKO_PUBLIC_KEY.
    PublicKey,
    /// CKO_PRIVATE_KEY.
    PrivateKey,
    /// CKO_SECRET_KEY.
    SecretKey,
    /// CKO_HW_FEATURE; CKA_HW_FEATURE_TYPE is a separate attribute.
    HardwareFeature,
    /// CKO_DOMAIN_PARAMETERS; CKA_KEY_TYPE identifies the applicable algorithm.
    DomainParameters,
    /// CKO_MECHANISM; CKA_MECHANISM_TYPE is not an object class.
    Mechanism,
    /// CKO_OTP_KEY, inheriting secret-key attributes under PKCS#11 section 6.53.5.1.
    OtpKey,
    /// CKO_PROFILE; profile identifiers are values of CKA_PROFILE_ID.
    Profile,
    /// CKO_VALIDATION.
    Validation,
    /// CKO_TRUST.
    Trust,
    /// An unknown native class, retained exactly for inventory. A standard
    /// administrative selector does not silently authorize a vendor extension.
    Other(u64),
}
impl ManagedClass {
    /// All standard classes from the pinned PKCS#11 3.2 header and specification.
    /// This catalogue does not imply that a module supports their creation.
    pub const ALL: &'static [Self] = &[
        Self::Data,
        Self::Certificate,
        Self::PublicKey,
        Self::PrivateKey,
        Self::SecretKey,
        Self::HardwareFeature,
        Self::DomainParameters,
        Self::Mechanism,
        Self::OtpKey,
        Self::Profile,
        Self::Validation,
        Self::Trust,
    ];

    /// Exact identifier, including an inventory value unknown to this edition.
    pub fn identifier(self) -> u64 {
        match self {
            Self::Other(value) => value,
            known => known.raw() as u64,
        }
    }

    /// Resolve a standard identifier; unknown or out-of-ABI-width values return None.
    pub fn from_identifier(value: u64) -> Option<Self> {
        let class = Self::from_raw(CK_OBJECT_CLASS::try_from(value).ok()?);
        (!matches!(class, Self::Other(_))).then_some(class)
    }

    // Callers must establish native width first: observed classes came from a
    // CK_OBJECT_CLASS; standard selectors reject Other. Extension destinations
    // check the full identifier before reserving it (DestinationRecipe::with_parts).
    // Do not use this conversion directly on an unchecked caller-supplied Other.
    pub(crate) fn raw(self) -> CK_OBJECT_CLASS {
        match self {
            Self::Data => CKO_DATA,
            Self::Certificate => CKO_CERTIFICATE,
            Self::PublicKey => CKO_PUBLIC_KEY,
            Self::PrivateKey => CKO_PRIVATE_KEY,
            Self::SecretKey => CKO_SECRET_KEY,
            Self::HardwareFeature => CKO_HW_FEATURE,
            Self::DomainParameters => CKO_DOMAIN_PARAMETERS,
            Self::Mechanism => CKO_MECHANISM,
            Self::OtpKey => CKO_OTP_KEY,
            Self::Profile => CKO_PROFILE,
            Self::Validation => CKO_VALIDATION,
            Self::Trust => CKO_TRUST,
            Self::Other(value) => value as _,
        }
    }
    pub(super) fn from_raw(value: CK_OBJECT_CLASS) -> Self {
        match value {
            CKO_DATA => Self::Data,
            CKO_CERTIFICATE => Self::Certificate,
            CKO_PUBLIC_KEY => Self::PublicKey,
            CKO_PRIVATE_KEY => Self::PrivateKey,
            CKO_SECRET_KEY => Self::SecretKey,
            CKO_HW_FEATURE => Self::HardwareFeature,
            CKO_DOMAIN_PARAMETERS => Self::DomainParameters,
            CKO_MECHANISM => Self::Mechanism,
            CKO_OTP_KEY => Self::OtpKey,
            CKO_PROFILE => Self::Profile,
            CKO_VALIDATION => Self::Validation,
            CKO_TRUST => Self::Trust,
            other => Self::Other(other as u64),
        }
    }
    pub(super) fn key(self) -> bool {
        matches!(
            self,
            Self::PublicKey | Self::PrivateKey | Self::SecretKey | Self::OtpKey
        )
    }
    pub(super) fn has_key_type(self) -> bool {
        self.key() || self == Self::DomainParameters
    }
}
