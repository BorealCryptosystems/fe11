// SPDX-License-Identifier: Apache-2.0
//! Revocation references are allocated and credited before native possession.
use super::RevocationTargets;
use crate::managed::{NativeIdentity, ResourceIdentity};
use crate::{Error, Result, Session};
use std::sync::Arc;

pub(crate) struct PreparedRevocations {
    resource: ResourceIdentity,
    targets: Option<RevocationTargets>,
    rejected: Option<Box<RevocationRetention>>,
}

// Unrelated identities can lose their last external owner during a snapshot.
// This prepaid node transfers their lifetime to the access that upgraded them.
pub(crate) struct RevocationRetention {
    objects: Vec<Arc<NativeIdentity>>,
    managed: Vec<Arc<NativeIdentity>>,
    next: Option<Box<RevocationRetention>>,
    _credit: Option<crate::symmetric::memory::Credit>,
}

#[derive(Default)]
pub(crate) struct RevocationRetentions(Option<Box<RevocationRetention>>);
impl RevocationRetentions {
    pub(crate) fn retain(&mut self, candidate: &mut Option<Box<RevocationRetention>>) {
        if let Some(mut node) = candidate.take() {
            node.next = self.0.take();
            self.0 = Some(node);
        }
    }
}
impl Drop for RevocationRetentions {
    fn drop(&mut self) {
        // The number of operands is caller-controlled: release iteratively.
        while let Some(mut node) = self.0.take() {
            self.0 = node.next.take();
        }
    }
}
impl PreparedRevocations {
    /// Populate borrowed storage without arming a revocation. On growth or
    /// error the caller still owns all snapshots and their credits; it must
    /// release access before discarding or replacing this preparation.
    pub(crate) fn bind(
        &mut self,
        state: &crate::session::SessionAccess<'_>,
    ) -> Result<Option<RevocationTargets>> {
        if !self.populate(state)? {
            return Ok(None);
        }
        Ok(Some(self.take_targets()))
    }

    // Composed requests populate every operand before transferring any target.
    // A later operand's refusal therefore cannot destroy earlier snapshots.
    pub(super) fn populate(&mut self, state: &crate::session::SessionAccess<'_>) -> Result<bool> {
        let resource = self.resource.native();
        let targets = self.targets.as_mut().ok_or(Error::Rejected(
            crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::RevocationPreparationAlreadyConsumed,
            ),
        ))?;
        let rejected = self.rejected.as_mut().ok_or(Error::Rejected(
            crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::RevocationRetentionAlreadyConsumed,
            ),
        ))?;
        if !state.objects.copy_live_matching(
            &mut targets.objects,
            &mut rejected.objects,
            |alias| alias.resource().native() == resource,
        )? || !state.managed.copy_live_matching(
            &mut targets.managed,
            &mut rejected.managed,
            |alias| alias.resource().native() == resource,
        )? {
            return Ok(false);
        }
        state.retain_revocation_references(&mut self.rejected)?;
        Ok(true)
    }

    /// Called only after populate succeeded for every selected operand.
    pub(super) fn take_targets(&mut self) -> RevocationTargets {
        self.targets.take().expect("populated revocation targets")
    }
}

/// Counts only; safe to retain while aggregate credit admission waits.
#[derive(Clone, Copy)]
pub(crate) struct RevocationShape {
    resource: ResourceIdentity,
    objects: usize,
    managed: usize,
}
pub(crate) struct RevocationStorage {
    resource: ResourceIdentity,
    objects: Vec<Arc<NativeIdentity>>,
    managed: Vec<Arc<NativeIdentity>>,
    rejected: Box<RevocationRetention>,
}
fn bytes(objects: usize, managed: usize) -> Result<usize> {
    objects
        .checked_add(managed)
        .and_then(|n| n.checked_mul(std::mem::size_of::<Arc<NativeIdentity>>()))
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
            crate::ObjectReferencesRejection::RevocationReferenceStorageAccounting,
        )))
}
impl RevocationShape {
    pub(crate) fn discover(
        session: &Session,
        resource: ResourceIdentity,
        authentication: u64,
    ) -> Result<Self> {
        let (objects, managed) = {
            // The enclosing request supplies its original epoch. Reuse the
            // existing context-aware wait without recapturing authentication.
            let state = session.read_at_epoch(authentication)?;
            (state.objects.clone(), state.managed.clone())
        };
        Ok(Self {
            resource,
            objects: objects.live_storage_capacity()?,
            managed: managed.live_storage_capacity()?,
        })
    }
    pub(crate) fn allocation_bytes(&self) -> Result<usize> {
        bytes(self.objects, self.managed)?
            .checked_mul(2)
            .and_then(|n| n.checked_add(std::mem::size_of::<RevocationRetention>()))
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::RevocationRetentionAccounting,
            )))
    }
    pub(crate) fn allocate(self) -> Result<RevocationStorage> {
        let mut objects = Vec::new();
        let mut managed = Vec::new();
        objects.try_reserve_exact(self.objects).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::RevocationReferenceAllocation,
            ))
        })?;
        managed.try_reserve_exact(self.managed).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::RevocationReferenceAllocation,
            ))
        })?;
        let mut rejected = Box::new(RevocationRetention {
            objects: Vec::new(),
            managed: Vec::new(),
            next: None,
            _credit: None,
        });
        rejected
            .objects
            .try_reserve_exact(self.objects)
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::RevocationRetentionAllocation,
                ))
            })?;
        rejected
            .managed
            .try_reserve_exact(self.managed)
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::RevocationRetentionAllocation,
                ))
            })?;
        Ok(RevocationStorage {
            resource: self.resource,
            objects,
            managed,
            rejected,
        })
    }
}
impl RevocationStorage {
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        bytes(self.objects.capacity(), self.managed.capacity())?
            .checked_add(bytes(
                self.rejected.objects.capacity(),
                self.rejected.managed.capacity(),
            )?)
            .and_then(|n| n.checked_add(std::mem::size_of::<RevocationRetention>()))
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::RevocationRetentionAccounting,
            )))
    }
    pub(crate) fn bind(
        mut self,
        prepaid: &mut crate::symmetric::memory::Credit,
    ) -> Result<PreparedRevocations> {
        let mut credit = prepaid.split(self.allocated_bytes()?)?;
        let target_credit =
            credit.split(bytes(self.objects.capacity(), self.managed.capacity())?)?;
        self.rejected._credit = Some(credit);
        Ok(PreparedRevocations {
            resource: self.resource,
            rejected: Some(self.rejected),
            targets: Some(RevocationTargets {
                objects: self.objects,
                managed: self.managed,
                _storage_credit: Some(target_credit),
            }),
        })
    }
}
