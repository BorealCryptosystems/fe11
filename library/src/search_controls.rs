// SPDX-License-Identifier: Apache-2.0
//! Explicit selection from a completed native enumeration.
use crate::{Error, Result};
use fe11_sys::CK_OBJECT_HANDLE;

/// Choose one result by its explicit position in the completed enumeration.
/// Native enumeration order is not stable or an identity guarantee.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectSearchSelection {
    /// Zero-based position in the complete native-order result. No default.
    pub index: usize,
}

/// Evidence for one initial selection, not an ongoing uniqueness guarantee.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectSearchReport {
    selection: ObjectSearchSelection,
    count: u64,
}
impl ObjectSearchReport {
    /// Exact owned selection, without native handles or object contents.
    pub fn selection(&self) -> &ObjectSearchSelection {
        &self.selection
    }
    /// Complete count observed in this session's visibility.
    pub fn cardinality(&self) -> u64 {
        self.count
    }
}

impl ObjectSearchSelection {
    pub(crate) fn select(
        &self,
        handles: &[CK_OBJECT_HANDLE],
    ) -> Result<(CK_OBJECT_HANDLE, ObjectSearchReport)> {
        let count = u64::try_from(handles.len()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchCardinalityWidth,
            ))
        })?;
        let handle = handles.get(self.index).copied().ok_or(Error::Rejected(
            crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SelectedSearchResultAbsent,
            ),
        ))?;
        Ok((
            handle,
            ObjectSearchReport {
                selection: self.clone(),
                count,
            },
        ))
    }

    pub(crate) fn retained_bytes(&self) -> Result<usize> {
        Ok(std::mem::size_of::<Self>())
    }
}
