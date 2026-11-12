// SPDX-License-Identifier: Apache-2.0
//! One selection for native authentication, output shape and continuation records.

use super::{record, KeyLease, Mode, SymmetricAlgorithm};
use crate::advanced::record::profile;
use crate::{Error, Result};
use fe11_sys::{
    CKK_GENERIC_SECRET, CKK_SHA256_HMAC, CKK_SHA384_HMAC, CKK_SHA512_HMAC, CKM_SHA256,
    CKM_SHA256_HMAC, CKM_SHA384_HMAC, CKM_SHA512_HMAC, CK_KEY_TYPE, CK_MECHANISM_TYPE,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::advanced) enum HmacAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}
impl HmacAlgorithm {
    pub(super) fn from_key(algorithm: SymmetricAlgorithm) -> Result<Self> {
        match algorithm {
            SymmetricAlgorithm::HmacSha256 { .. } => Ok(Self::Sha256),
            SymmetricAlgorithm::HmacSha384 { .. } => Ok(Self::Sha384),
            SymmetricAlgorithm::HmacSha512 { .. } => Ok(Self::Sha512),
            _ => Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualHmacKeyRequired,
            ))),
        }
    }
    pub(in crate::advanced) fn hash(self) -> crate::HashAlgorithm {
        match self {
            Self::Sha256 => crate::HashAlgorithm::Sha256,
            Self::Sha384 => crate::HashAlgorithm::Sha384,
            Self::Sha512 => crate::HashAlgorithm::Sha512,
        }
    }
    pub(in crate::advanced) fn mechanism(self) -> CK_MECHANISM_TYPE {
        match self {
            Self::Sha256 => CKM_SHA256_HMAC,
            Self::Sha384 => CKM_SHA384_HMAC,
            Self::Sha512 => CKM_SHA512_HMAC,
        }
    }
    pub(in crate::advanced) fn key_type(self) -> CK_KEY_TYPE {
        match self {
            Self::Sha256 => CKK_SHA256_HMAC,
            Self::Sha384 => CKK_SHA384_HMAC,
            Self::Sha512 => CKK_SHA512_HMAC,
        }
    }
    pub(in crate::advanced) fn profile(self) -> u8 {
        match self {
            Self::Sha256 => profile::HMAC_SHA256,
            Self::Sha384 => profile::HMAC_SHA384,
            Self::Sha512 => profile::HMAC_SHA512,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::advanced) enum Authentication {
    LegacyDigestSha256,
    Digest(crate::HashAlgorithm),
    LegacyHmacSha256,
    Hmac(HmacAlgorithm),
}
impl Authentication {
    pub(super) fn legacy(mode: Mode) -> Self {
        if mode.mac() {
            Self::LegacyHmacSha256
        } else {
            Self::LegacyDigestSha256
        }
    }
    pub(in crate::advanced) fn mac(self) -> Option<HmacAlgorithm> {
        match self {
            Self::LegacyHmacSha256 => Some(HmacAlgorithm::Sha256),
            Self::Hmac(algorithm) => Some(algorithm),
            _ => None,
        }
    }
    pub(in crate::advanced) fn hash(self) -> crate::HashAlgorithm {
        match self {
            Self::LegacyDigestSha256 | Self::LegacyHmacSha256 => crate::HashAlgorithm::Sha256,
            Self::Digest(algorithm) => algorithm,
            Self::Hmac(algorithm) => algorithm.hash(),
        }
    }
    pub(in crate::advanced) fn length(self) -> usize {
        self.hash().output_length()
    }
    pub(in crate::advanced) fn mechanism(self) -> CK_MECHANISM_TYPE {
        self.mac()
            .map_or_else(|| self.hash().mechanism(), |mac| mac.mechanism())
    }
    pub(in crate::advanced) fn profile(self, cipher: u8) -> Result<u8> {
        if !(profile::AES128..=profile::AES256).contains(&cipher) {
            return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualAesProfile,
            )));
        }
        Ok(match self {
            Self::Digest(_) | Self::Hmac(_) => cipher + profile::DUAL_SELECTION_OFFSET,
            _ => cipher,
        })
    }
    pub(in crate::advanced) fn from_record(
        d: record::Descriptor,
        m: &record::Message<'_>,
    ) -> Result<Self> {
        if !d.family.is_dual() {
            return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualAuthenticationFamily,
            )));
        }
        cipher_profile(d)?;
        let hash =
            m.params
                .hash
                .ok_or(Error::Rejected(crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::DualHashAbsent,
                )))?;
        if (profile::AES128..=profile::AES256).contains(&d.profile) {
            if hash != CKM_SHA256 as u64 {
                return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::LegacyDualHash,
                )));
            }
            return Ok(if d.family.is_dual_mac() {
                Self::LegacyHmacSha256
            } else {
                Self::LegacyDigestSha256
            });
        }
        if d.family.is_dual_mac() {
            let algorithm = [
                HmacAlgorithm::Sha256,
                HmacAlgorithm::Sha384,
                HmacAlgorithm::Sha512,
            ]
            .into_iter()
            .find(|a| a.hash().mechanism_number() == hash)
            .ok_or(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualHmacHash,
            )))?;
            Ok(Self::Hmac(algorithm))
        } else {
            let algorithm = crate::HashAlgorithm::from_mechanism(hash).ok_or(Error::Rejected(
                crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::DualDigestHash,
                ),
            ))?;
            Ok(Self::Digest(algorithm))
        }
    }
}

/// A MAC selection cannot exist without its admitted key. Digest selections
/// cannot retain an unrelated MAC lease. Native encrypt/auth activities remain
/// independently represented by the owning dual operation.
pub(super) enum AuthenticationOwner {
    LegacyDigestSha256,
    Digest(crate::HashAlgorithm),
    LegacyHmacSha256 {
        key: KeyLease,
    },
    Hmac {
        algorithm: HmacAlgorithm,
        key: KeyLease,
    },
}
impl AuthenticationOwner {
    pub(super) fn check_binding(
        mode: Mode,
        selection: Authentication,
        key: Option<&KeyLease>,
    ) -> Result<()> {
        if mode.mac() != selection.mac().is_some() {
            return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualAuthenticationOwner,
            )));
        }
        match (selection, key) {
            (Authentication::LegacyDigestSha256 | Authentication::Digest(_), None)
            | (Authentication::LegacyHmacSha256 | Authentication::Hmac(_), Some(_)) => Ok(()),
            _ => Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualAuthenticationOwner,
            ))),
        }
    }
    /// Transfer after check_binding; selection and key presence are unchanged.
    pub(super) fn bind_checked(selection: Authentication, key: Option<KeyLease>) -> Self {
        match (selection, key) {
            (Authentication::LegacyDigestSha256, None) => Self::LegacyDigestSha256,
            (Authentication::Digest(algorithm), None) => Self::Digest(algorithm),
            (Authentication::LegacyHmacSha256, Some(key)) => Self::LegacyHmacSha256 { key },
            (Authentication::Hmac(algorithm), Some(key)) => Self::Hmac { algorithm, key },
            _ => unreachable!("validated dual authentication binding"),
        }
    }

    pub(super) fn selection(&self) -> Authentication {
        match self {
            Self::LegacyDigestSha256 => Authentication::LegacyDigestSha256,
            Self::Digest(algorithm) => Authentication::Digest(*algorithm),
            Self::LegacyHmacSha256 { .. } => Authentication::LegacyHmacSha256,
            Self::Hmac { algorithm, .. } => Authentication::Hmac(*algorithm),
        }
    }

    pub(super) fn key(&self) -> Option<&KeyLease> {
        match self {
            Self::LegacyDigestSha256 | Self::Digest(_) => None,
            Self::LegacyHmacSha256 { key } | Self::Hmac { key, .. } => Some(key),
        }
    }

    // Called only after restore_keys validated the exact roles and native Set
    // committed. Keep this commit allocation-free and preserve the selection.
    /// Keep the old lease alive until the restoration caller leaves its guards.
    pub(super) fn replace_key(&mut self, replacement: Option<KeyLease>) -> Option<KeyLease> {
        match self {
            Self::LegacyDigestSha256 | Self::Digest(_) => {
                debug_assert!(replacement.is_none());
                replacement
            }
            Self::LegacyHmacSha256 { key } | Self::Hmac { key, .. } => Some(std::mem::replace(
                key,
                replacement.expect("validated restoration authentication key"),
            )),
        }
    }
}

pub(in crate::advanced) fn cipher_profile(d: record::Descriptor) -> Result<u8> {
    if d.family.is_cipher() {
        return super::super::cipher::checkpoint::key_profile(d.profile);
    }
    if !d.family.is_dual() {
        return Ok(d.profile);
    }
    match d.profile {
        profile::AES128..=profile::AES256 => Ok(d.profile),
        profile::DUAL_AES128_SELECTED..=profile::DUAL_AES256_SELECTED => {
            Ok(d.profile - profile::DUAL_SELECTION_OFFSET)
        }
        _ => Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
            crate::CombinedOperationsRejection::DualCipherProfile,
        ))),
    }
}
pub(in crate::advanced) fn record_selection(
    d: record::Descriptor,
    messages: &record::Messages<'_>,
) -> Result<Option<Authentication>> {
    if !d.family.is_dual() {
        return Ok(None);
    }
    if messages.len() != 1 {
        return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
            crate::CombinedOperationsRejection::DualMessageCount,
        )));
    }
    let m = messages.iter().next().ok_or(Error::Rejected(
        crate::RejectionReason::CombinedOperations(
            crate::CombinedOperationsRejection::DualMessageAbsent,
        ),
    ))??;
    Ok(Some(Authentication::from_record(d, &m)?))
}
pub(in crate::advanced) fn check_record_key(
    selection: Authentication,
    keys: &record::KeyBindings<'_>,
) -> Result<()> {
    if let Some(mac) = selection.mac() {
        let key = keys.authentication.ok_or(Error::Rejected(
            crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualMacKeyAbsent,
            ),
        ))?;
        if key.key_type != Some(CKK_GENERIC_SECRET as u64)
            && key.key_type != Some(mac.key_type() as u64)
        {
            return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualMacKeyType,
            )));
        }
    }
    Ok(())
}

impl crate::symmetric::memory::RetainedStorage for AuthenticationOwner {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        match self {
            Self::LegacyHmacSha256 { key } | Self::Hmac { key, .. } => key.retain_credits(retained),
            Self::LegacyDigestSha256 | Self::Digest(_) => Ok(()),
        }
    }
}
