// SPDX-License-Identifier: Apache-2.0
//! Positional alias snapshots share one admission with their enclosing request.
use super::{prepared::RevocationStorage, PreparedRevocations, RevocationShape, RevocationTargets};
use crate::{managed::ResourceIdentity, symmetric::memory::Credit, Error, Result, Session};

/// Counts only. An absent operand occupies no private snapshot allocation.
pub(crate) struct RevocationSetPlan<const N: usize> {
    shapes: [Option<RevocationShape>; N],
}

pub(crate) struct RevocationSetStorage<const N: usize> {
    values: [Option<RevocationStorage>; N],
}

pub(crate) struct PreparedRevocationSet<const N: usize> {
    values: [Option<PreparedRevocations>; N],
}

fn sum<const N: usize, T>(
    values: &[Option<T>; N],
    measure: impl Fn(&T) -> Result<usize>,
) -> Result<usize> {
    values.iter().flatten().try_fold(0usize, |total, value| {
        total.checked_add(measure(value)?).ok_or(Error::Rejected(
            crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::RevocationSetStorageAccounting,
            ),
        ))
    })
}

impl<const N: usize> RevocationSetPlan<N> {
    pub(crate) fn discover(
        session: &Session,
        resources: [Option<ResourceIdentity>; N],
        authentication: u64,
    ) -> Result<Self> {
        let mut shapes = [None; N];
        for (shape, resource) in shapes.iter_mut().zip(resources) {
            *shape = resource
                .map(|resource| RevocationShape::discover(session, resource, authentication))
                .transpose()?;
        }
        Ok(Self { shapes })
    }

    pub(crate) fn allocation_bytes(&self) -> Result<usize> {
        sum(&self.shapes, RevocationShape::allocation_bytes)
    }

    pub(crate) fn allocate(&self) -> Result<RevocationSetStorage<N>> {
        let mut values = std::array::from_fn(|_| None);
        for (value, shape) in values.iter_mut().zip(self.shapes) {
            *value = shape.map(RevocationShape::allocate).transpose()?;
        }
        Ok(RevocationSetStorage { values })
    }
}

impl<const N: usize> RevocationSetStorage<N> {
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        sum(&self.values, RevocationStorage::allocated_bytes)
    }

    pub(crate) fn bind(self, credit: &mut Credit) -> Result<PreparedRevocationSet<N>> {
        let mut values = std::array::from_fn(|_| None);
        for (value, storage) in values.iter_mut().zip(self.values) {
            *value = storage.map(|storage| storage.bind(credit)).transpose()?;
        }
        Ok(PreparedRevocationSet { values })
    }
}

impl<const N: usize> PreparedRevocationSet<N> {
    /// Fill every passive snapshot before transferring any of them. A growth
    /// race or error leaves the whole set with the caller's access-first owner.
    pub(crate) fn bind(
        &mut self,
        state: &crate::session::SessionAccess<'_>,
    ) -> Result<Option<[Option<RevocationTargets>; N]>> {
        for prepared in self.values.iter_mut().flatten() {
            if !prepared.populate(state)? {
                return Ok(None);
            }
        }
        Ok(Some(std::array::from_fn(|index| {
            self.values[index]
                .as_mut()
                .map(PreparedRevocations::take_targets)
        })))
    }
}
