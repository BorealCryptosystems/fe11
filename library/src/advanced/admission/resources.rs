// SPDX-License-Identifier: Apache-2.0
//! Resource requests carry immutable sizing metadata, never native ownership.
use super::read::{PreparedRead, ReadCandidate, ReadNeed};
use crate::{
    crypto::integer_key::{PublicDerCandidate, PublicDerNeed, PublicDerPreparation},
    managed::search::{SearchCandidate, SearchNeed, SearchPreparation},
    symmetric::memory::Budget,
    ResourceAdmission, Result,
};
use std::sync::Arc;

#[derive(Clone)]
pub(in crate::advanced) enum ResourceNeed {
    Read(ReadNeed),
    Search(SearchNeed),
    PublicEncoding(PublicDerNeed),
}
impl ResourceNeed {
    pub(in crate::advanced) fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Read(a), Self::Read(b)) => a.same(b),
            (Self::Search(a), Self::Search(b)) => a == b,
            (Self::PublicEncoding(a), Self::PublicEncoding(b)) => a == b,
            _ => false,
        }
    }
}
pub(in crate::advanced) enum ResourceCandidate {
    Read(ReadCandidate),
    Search(SearchCandidate),
    PublicEncoding(PublicDerCandidate),
}
pub(in crate::advanced) enum PreparedResource<T> {
    Ready(ResourceCandidate),
    Redirect(T),
}
impl ResourceCandidate {
    pub(in crate::advanced) fn need(&self) -> ResourceNeed {
        match self {
            Self::Read(candidate) => ResourceNeed::Read(candidate.need().clone()),
            Self::Search(candidate) => ResourceNeed::Search(candidate.need()),
            Self::PublicEncoding(candidate) => ResourceNeed::PublicEncoding(candidate.need()),
        }
    }
    pub(in crate::advanced) fn prepare<T>(
        need: ResourceNeed,
        budget: &Arc<Budget>,
        retained_bytes: usize,
        admission: &ResourceAdmission,
        before: impl FnMut() -> Result<Option<T>>,
    ) -> Result<PreparedResource<T>> {
        Ok(match need {
            ResourceNeed::PublicEncoding(length) => {
                match PublicDerCandidate::prepare_retaining(
                    length,
                    budget,
                    retained_bytes,
                    admission,
                    before,
                )? {
                    PublicDerPreparation::Ready(candidate) => {
                        PreparedResource::Ready(Self::PublicEncoding(candidate))
                    }
                    PublicDerPreparation::Redirect(route) => PreparedResource::Redirect(route),
                }
            }
            ResourceNeed::Read(need) => {
                match ReadCandidate::prepare(need, budget, retained_bytes, admission, before)? {
                    PreparedRead::Ready(candidate) => {
                        PreparedResource::Ready(Self::Read(candidate))
                    }
                    PreparedRead::Redirect(route) => PreparedResource::Redirect(route),
                }
            }
            ResourceNeed::Search(need) => {
                match SearchCandidate::prepare_retaining(
                    need,
                    budget,
                    retained_bytes,
                    admission,
                    before,
                )? {
                    SearchPreparation::Ready(candidate) => {
                        PreparedResource::Ready(Self::Search(candidate))
                    }
                    SearchPreparation::Redirect(route) => PreparedResource::Redirect(route),
                }
            }
        })
    }
}
