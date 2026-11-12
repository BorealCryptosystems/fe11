// SPDX-License-Identifier: Apache-2.0
//! One logical byte string described without concatenating its borrowed inputs.
use crate::{bounds, Error, Result};

/// Segments are an allocation detail, never separate identity components.
/// In particular `a || b` compares equal to a contiguous copy of those bytes.
#[derive(Clone, Copy)]
pub(crate) struct ByteParts<'a> {
    prefix: &'a [u8],
    suffix: &'a [u8],
    length: usize,
}
impl<'a> ByteParts<'a> {
    pub(crate) fn joined(prefix: &'a [u8], suffix: &'a [u8]) -> Result<Self> {
        let length = prefix
            .len()
            .checked_add(suffix.len())
            .ok_or(Error::Rejected(crate::RejectionReason::KeyEncoding(
                crate::KeyEncodingRejection::PublicImportMetadataLength,
            )))?;
        bounds::ck_length(length)?;
        Ok(Self {
            prefix,
            suffix,
            length,
        })
    }
    pub(crate) fn len(self) -> usize {
        self.length
    }
    pub(crate) fn segments(self) -> [&'a [u8]; 2] {
        [self.prefix, self.suffix]
    }
    pub(crate) fn contiguous(self) -> Option<&'a [u8]> {
        self.suffix.is_empty().then_some(self.prefix)
    }
    pub(crate) fn copy_to(self, output: &mut [u8]) {
        // The owner allocates exactly this validated logical length before bind.
        let (prefix, suffix) = output.split_at_mut(self.prefix.len());
        prefix.copy_from_slice(self.prefix);
        suffix.copy_from_slice(self.suffix);
    }
}
impl<'a> From<&'a [u8]> for ByteParts<'a> {
    fn from(prefix: &'a [u8]) -> Self {
        Self {
            prefix,
            suffix: &[],
            length: prefix.len(),
        }
    }
}
impl PartialEq for ByteParts<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.length == other.length
            && self
                .prefix
                .iter()
                .chain(self.suffix)
                .eq(other.prefix.iter().chain(other.suffix))
    }
}
impl Eq for ByteParts<'_> {}
