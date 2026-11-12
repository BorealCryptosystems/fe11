// SPDX-License-Identifier: Apache-2.0
//! Prepared CLASS/ID search storage, including the later private-key search.
use crate::{
    attributes::{KeySelectorStorage, Template},
    symmetric::memory::Credit,
    Result,
};
use fe11_sys::{CK_ATTRIBUTE, CK_ULONG};

pub(super) struct Selector {
    pub(super) template: Box<Template>,
    pub(super) attrs: Vec<CK_ATTRIBUTE>,
    pub(super) credit: Credit,
}
// SAFETY: descriptors reference only the boxed template and its unchanged Vec
// allocations. Preparation publishes no pointer; dispatch remains serialized by
// the owning Admission/session. Transfers preserve every pointed-to allocation.
unsafe impl Send for Selector {}

impl Selector {
    pub(super) fn bind(
        storage: KeySelectorStorage,
        class: CK_ULONG,
        id: &[u8],
        prepaid: &mut Credit,
    ) -> Result<Self> {
        let bytes = storage.allocated_bytes()?;
        let (template, attrs) = storage.bind(class, id)?;
        let credit = prepaid.split(bytes)?;
        Ok(Self {
            template,
            attrs,
            credit,
        })
    }
}
