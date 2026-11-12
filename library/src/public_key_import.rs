// SPDX-License-Identifier: Apache-2.0
use crate::ObjectVisibility;

/// Exact metadata request for a public-key import. This is not a uniqueness
/// policy or an authorization claim; destination controls remain independent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicImportMetadata {
    /// Emit the exact caller-supplied CKA_ID and CKA_LABEL bytes.
    Exact {
        /// Exact application identifier, including an empty value if selected.
        id: Vec<u8>,
        /// Exact label bytes, without a presentation restriction.
        label: Vec<u8>,
    },
    /// Append the SHA-256 digest of the supplied canonical SPKI to this prefix.
    SpkiSha256 {
        /// Exact prefix. Fe11 adds no counter, random value or separator.
        prefix: Vec<u8>,
        /// Exact CKA_LABEL bytes.
        label: Vec<u8>,
    },
}
impl PublicImportMetadata {
    pub(crate) fn plan(&self, spki: &[u8]) -> crate::Result<ImportMetadataPlan<'_>> {
        use sha2::{Digest, Sha256};
        self.plan_with_fingerprint(|| Ok(Sha256::digest(spki).into()))
    }

    /// Evaluate the canonical SPKI digest only when requested. Callers with a
    /// structured key can stream DER into the digest without allocating a copy.
    pub(crate) fn plan_with_fingerprint(
        &self,
        fingerprint: impl FnOnce() -> crate::Result<[u8; 32]>,
    ) -> crate::Result<ImportMetadataPlan<'_>> {
        let (prefix, label, suffix) = match self {
            Self::Exact { id, label } => (id.as_slice(), label.as_slice(), None),
            Self::SpkiSha256 { prefix, label } => {
                (prefix.as_slice(), label.as_slice(), Some(fingerprint()?))
            }
        };
        let length = prefix
            .len()
            .checked_add(if suffix.is_some() { 32 } else { 0 })
            .ok_or(crate::Error::Rejected(crate::RejectionReason::KeyEncoding(
                crate::KeyEncodingRejection::PublicImportMetadataLength,
            )))?;
        crate::bounds::ck_length(length)?;
        crate::bounds::ck_length(label.len())?;
        Ok(ImportMetadataPlan {
            prefix,
            label,
            suffix,
        })
    }
}

/// Borrowed validated metadata plus an inline digest. No retained allocation or
/// Budget credit crosses reference admission; the same measurement builds it.
pub(crate) struct ImportMetadataPlan<'a> {
    prefix: &'a [u8],
    label: &'a [u8],
    suffix: Option<[u8; 32]>,
}

impl<'a> ImportMetadataPlan<'a> {
    pub(crate) fn identifier(&self) -> crate::Result<crate::attributes::ByteParts<'_>> {
        crate::attributes::ByteParts::joined(
            self.prefix,
            self.suffix.as_ref().map_or(&[], |s| s.as_slice()),
        )
    }
    pub(crate) fn label(&self) -> &'a [u8] {
        self.label
    }
}

#[doc = include_str!("../docs/api/public_key_import/PublicKeyImportOptions.md")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKeyImportOptions {
    /// Native identifier and label requests; no hidden uniqueness policy.
    pub metadata: PublicImportMetadata,
    /// Exact native usage requests, independent of admission observations.
    pub usages: crate::KeyUsageRequest,
    /// Exact CKA_TOKEN request. Native storage authorization remains authoritative.
    pub persistent: bool,
    /// Exact CKA_DESTROYABLE request.
    pub destroyable: bool,
    /// Independent read and comparison selection; no request implies a read.
    pub admission: crate::ObjectAdmission,
    /// Exact CKA_PRIVATE request; native authorization remains authoritative.
    pub visibility: ObjectVisibility,
    /// Exact CKA_MODIFIABLE value, independent of visibility and copy permission.
    pub modifiable: bool,
    /// Exact CKA_COPYABLE value, independent of modification permission.
    pub copyable: bool,
}
