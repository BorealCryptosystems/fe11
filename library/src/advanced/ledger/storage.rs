// SPDX-License-Identifier: Apache-2.0
//! Private operation storage allocated before the common admission probes access.
use super::Operation;
use crate::{symmetric::memory::Credit, Error, Result};
use std::{
    ops::Deref,
    sync::{Arc, Mutex, OnceLock},
};

/// Only initialized cells leave this module. Callers continue to lock the same
/// standard mutex; poisoning, guard lifetimes and operation access are unchanged.
pub(in crate::advanced) struct OperationCell {
    operation: OnceLock<Mutex<Operation>>,
    // Drop the operation and its resources before releasing storage credit.
    _credit: Option<Credit>,
}
impl Deref for OperationCell {
    type Target = Mutex<Operation>;

    fn deref(&self) -> &Self::Target {
        self.operation
            .get()
            .expect("published operation is initialized")
    }
}
impl OperationCell {
    // Called while this exact installed cell is locked and retained by its
    // ledger. Count only storage here; the locked operation visits its payload.
    pub(in crate::advanced) fn retain_storage(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> Result<()> {
        crate::symmetric::memory::RetainedStorage::retain_credits(&self._credit, retained)
    }

    /// Existing installation routes retain their previous allocation boundary.
    /// Grouped common-start uses PreparedOperation instead, without this call.
    pub(super) fn ready(operation: Operation) -> Arc<Self> {
        Arc::new(Self {
            operation: OnceLock::from(Mutex::new(operation)),
            _credit: None,
        })
    }
}

/// The Arc is neither cloned nor exposed while empty. Abandoning preparation
/// releases only storage; no native operation or token lease has entered it.
pub(in crate::advanced) struct PreparedOperation(Arc<OperationCell>);
impl PreparedOperation {
    /// Admission already charges its own inline representation and its children.
    /// Charge only the remaining cell payload and Arc counters here, as for the
    /// other prepared Arc owners. This is not an allocator/RSS upper bound.
    pub(in crate::advanced) fn allocation_bytes() -> Result<usize> {
        std::mem::size_of::<OperationCell>()
            .checked_add(2 * std::mem::size_of::<usize>())
            .and_then(|bytes| {
                bytes.checked_sub(std::mem::size_of::<super::super::admission::Admission>())
            })
            .ok_or(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::OperationPublicationStorageSize,
            )))
    }

    pub(in crate::advanced) fn from_prepaid(prepaid: &mut Credit) -> Result<Self> {
        let credit = prepaid.split(Self::allocation_bytes()?)?;
        Ok(Self(Arc::new(OperationCell {
            operation: OnceLock::new(),
            _credit: Some(credit),
        })))
    }

    pub(super) fn check(&mut self) -> Result<()> {
        let cell = Arc::get_mut(&mut self.0).ok_or(Error::Rejected(
            crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::SharedUnboundOperationStorage,
            ),
        ))?;
        if cell.operation.get().is_some() {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::OperationStorageAlreadyInitialized,
            )));
        }
        Ok(())
    }

    /// Ledger calls this only after check and all fallible publication checks.
    /// The sole private Arc excludes a concurrent initializer, so set cannot
    /// block or refuse. OnceLock stores the mutex inline without allocation.
    pub(super) fn finish(self, operation: Operation) -> Arc<OperationCell> {
        if self.0.operation.set(Mutex::new(operation)).is_err() {
            unreachable!("checked private operation storage is empty");
        }
        self.0
    }
}
