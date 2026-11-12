// SPDX-License-Identifier: Apache-2.0
//! Stable storage for a complete synchronous object search.
//!
//! Init, each batch and Final share one access owner. The native count and
//! template never point into a returning stack frame. Result collection has its
//! own lifetime and budget; the module receives no pointer into that collection.
use super::{CollectionError, SearchCollection, SearchPlan};
use crate::attributes::{OwnedTemplate, Template};

use crate::session::SessionAccess;
use crate::symmetric::memory::Credit;
use crate::{bounds, Error, Result, Session};
use fe11_sys::*;

pub(crate) mod resident;

enum SearchTemplate {
    Descriptive(OwnedTemplate),
    Native(crate::attribute_values::InputTemplate),
}
impl SearchTemplate {
    fn count(&self) -> Result<CK_ULONG> {
        match self {
            Self::Descriptive(value) => value.count(),
            Self::Native(value) => Ok(value.count()),
        }
    }
    fn as_mut_ptr(&mut self) -> CK_ATTRIBUTE_PTR {
        match self {
            Self::Descriptive(value) => value.as_mut_ptr(),
            Self::Native(value) => value.as_mut_ptr(),
        }
    }
    fn unchanged(&mut self) -> bool {
        match self {
            Self::Descriptive(value) => value.unchanged(),
            Self::Native(value) => value.unchanged(),
        }
    }
}

struct SearchCall {
    template: SearchTemplate,
    batch: Vec<CK_OBJECT_HANDLE>,
    count: CK_ULONG,
    diagnostic: Option<crate::error::CompletionStorage>,
    _credit: Credit,
}
