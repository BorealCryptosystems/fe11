// SPDX-License-Identifier: Apache-2.0
//! Aggregate publication storage for one completed native search.
use super::*;

pub(super) struct AllMatches {
    pub(super) identities: Vec<Arc<NativeIdentity>>,
    pub(super) permit: crate::registry::Reservation<NativeIdentity>,
    pub(super) published: usize,
    // Always empty while resident: an Inner Arc here would create a cycle.
    objects: Vec<NativeObjectRef>,
    credit: Credit,
}
impl AllMatches {
    pub(super) fn prepare(
        session: &Session,
        epoch: u64,
        count: usize,
        waiter: &Waiting<'_>,
        mut reserve: impl FnMut(usize) -> Result<(crate::registry::Reservation<NativeIdentity>, Credit)>,
    ) -> Result<Self> {
        let identity_bytes = count
            .checked_mul(NativeIdentity::allocation_bytes())
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchIdentityStorageAccounting,
            )))?;
        let width = std::mem::size_of::<Arc<NativeIdentity>>()
            .checked_add(std::mem::size_of::<NativeObjectRef>())
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchResultStorageAccounting,
            )))?;
        let mut required = count
            .checked_mul(width)
            .and_then(|n| n.checked_add(identity_bytes))
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchResultStorageAccounting,
            )))?;
        loop {
            waiter.check()?;
            let (mut permit, mut credit) = reserve(required)?;
            waiter.check()?;
            let mut identities = Vec::<Arc<NativeIdentity>>::new();
            let mut objects = Vec::<NativeObjectRef>::new();
            identities.try_reserve_exact(count).map_err(|_| {
                Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::SearchIdentityAllocation,
                ))
            })?;
            objects.try_reserve_exact(count).map_err(|_| {
                Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::SearchResultAllocation,
                ))
            })?;
            let actual = identities
                .capacity()
                .checked_mul(std::mem::size_of::<Arc<NativeIdentity>>())
                .and_then(|n| {
                    objects
                        .capacity()
                        .checked_mul(std::mem::size_of::<NativeObjectRef>())
                        .and_then(|m| n.checked_add(m))
                })
                .and_then(|n| n.checked_add(identity_bytes))
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::SearchResultStorageAccounting,
                )))?;
            if actual > required {
                // Never wait while retaining a rejected private allocation/quota.
                drop((identities, objects, credit, permit));
                required = actual;
                continue;
            }
            credit.release(required - actual);
            for _ in 0..count {
                identities.push(NativeIdentity::prepare_discovery(
                    session,
                    epoch,
                    &mut permit,
                    &mut credit,
                )?);
            }
            return Ok(Self {
                identities,
                permit,
                published: 0,
                objects,
                credit,
            });
        }
    }

    pub(super) fn result(mut self, session: &Session, count: usize) -> Result<NativeObjectMatches> {
        if self.published != count
            || self.identities.len() != count
            || self.objects.capacity() < count
        {
            return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchPublicationIncomplete,
            )));
        }
        // The resident owner has been consumed. Moving identities into already
        // allocated output storage introduces neither allocation nor native work.
        for identity in self.identities.drain(..) {
            self.objects.push(NativeObjectRef {
                inner: session.inner.clone(),
                identity,
                output_slot: None,
            });
        }
        let identity_storage = self
            .identities
            .capacity()
            .checked_mul(std::mem::size_of::<Arc<NativeIdentity>>())
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::SearchResultStorageAccounting,
            )))?;
        drop(self.identities);
        self.credit.release(identity_storage);
        Ok(NativeObjectMatches {
            objects: self.objects,
            _credit: self.credit,
        })
    }
}
