// SPDX-License-Identifier: Apache-2.0
//! Credited retirement nodes shared by digest and cipher fragment owners.
//!
//! Complete-input facades may finish several calls while holding the same guards.
//! Each input has a node prepared before Init. Cipher additionally requests a
//! shadow node. Native returns only link these existing owners.

use crate::symmetric::memory::{Buffer, Credit};
use crate::{Error, Result};
use std::mem::size_of;

struct Node {
    bytes: Option<Buffer>,
    next: Option<Box<Node>>,
    _credit: Credit,
}

#[derive(Default)]
pub(in crate::advanced) struct ReturnedOperands {
    head: Option<Box<Node>>,
}

impl ReturnedOperands {
    pub(in crate::advanced) fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    fn retain(&mut self, mut node: Box<Node>, bytes: Buffer) {
        node.bytes = Some(bytes);
        node.next = self.head.take();
        self.head = Some(node);
    }
}

impl Drop for ReturnedOperands {
    fn drop(&mut self) {
        // Avoid recursive destruction proportional to the caller's batch size.
        // Poll/eager callers hold this chain outside all possession guards.
        while let Some(mut node) = self.head.take() {
            self.head = node.next.take();
            drop(node);
        }
    }
}

pub(in crate::advanced) struct Storage {
    inputs: Vec<Option<Box<Node>>>,
    // A partial bind must drop the vector and its constructed nodes before
    // releasing the vector's charge, including an error from a later split.
    metadata_credit: Option<Credit>,
    shadow: bool,
}

pub(in crate::advanced) struct Pool {
    inputs: Vec<Option<Box<Node>>>,
    next_input: usize,
    shadow: Option<Box<Node>>,
    _credit: Credit,
}

fn vector_bytes(count: usize) -> Result<usize> {
    count
        .checked_mul(size_of::<Option<Box<Node>>>())
        .ok_or(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::FragmentRetirementMetadataOverflow,
        )))
}

impl Storage {
    pub(in crate::advanced) fn required_bytes(count: usize, shadow: bool) -> Result<usize> {
        count
            .checked_add(usize::from(shadow))
            .and_then(|nodes| nodes.checked_mul(size_of::<Node>()))
            .and_then(|bytes| bytes.checked_add(vector_bytes(count).ok()?))
            .ok_or(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::FragmentRetirementAccounting,
            )))
    }

    pub(in crate::advanced) fn allocate(count: usize, shadow: bool) -> Result<Self> {
        let mut inputs = Vec::new();
        inputs.try_reserve_exact(count).map_err(|_| {
            Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::FragmentRetirementAllocation,
            ))
        })?;
        inputs.resize_with(count, || None);
        Ok(Self {
            inputs,
            metadata_credit: None,
            shadow,
        })
    }

    pub(in crate::advanced) fn allocated_bytes(&self) -> Result<usize> {
        self.inputs
            .len()
            .checked_add(usize::from(self.shadow))
            .and_then(|nodes| nodes.checked_mul(size_of::<Node>()))
            .and_then(|bytes| bytes.checked_add(vector_bytes(self.inputs.capacity()).ok()?))
            .ok_or(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::FragmentRetirementAccounting,
            )))
    }

    /// Actual capacities are admitted before binding, outside possession.
    pub(in crate::advanced) fn bind(mut self, prepaid: &mut Credit) -> Result<Pool> {
        self.metadata_credit = Some(prepaid.split(vector_bytes(self.inputs.capacity())?)?);
        let mut node = || -> Result<Box<Node>> {
            Ok(Box::new(Node {
                bytes: None,
                next: None,
                _credit: prepaid.split(size_of::<Node>())?,
            }))
        };
        for slot in &mut self.inputs {
            *slot = Some(node()?);
        }
        let shadow = self.shadow.then(&mut node).transpose()?;
        Ok(Pool {
            inputs: self.inputs,
            next_input: 0,
            shadow,
            _credit: self
                .metadata_credit
                .take()
                .expect("bound retirement metadata"),
        })
    }
}

impl Pool {
    pub(in crate::advanced) fn check(&self, count: usize, shadow_bytes: usize) -> Result<()> {
        let end = self.next_input.checked_add(count).ok_or(Error::Rejected(
            crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::FragmentRetirementCursor,
            ),
        ))?;
        if self
            .inputs
            .get(self.next_input..end)
            .map_or(true, |slots| slots.iter().any(Option::is_none))
            || shadow_bytes != 0 && self.shadow.is_none()
        {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::FragmentRetirementSlotAbsent,
            )));
        }
        Ok(())
    }

    pub(in crate::advanced) fn input(&mut self, bytes: Buffer, returned: &mut ReturnedOperands) {
        let node = self.inputs[self.next_input]
            .take()
            .expect("preflighted fragment retirement slot");
        self.next_input += 1;
        returned.retain(node, bytes);
    }

    pub(in crate::advanced) fn shadow(
        &mut self,
        bytes: impl FnOnce() -> Buffer,
        returned: &mut ReturnedOperands,
    ) {
        if let Some(node) = self.shadow.take() {
            returned.retain(node, bytes());
        }
    }
}

fn retain_chain(
    mut node: Option<&Node>,
    retained: &mut crate::symmetric::memory::RetainedBytes,
) -> crate::Result<()> {
    use crate::symmetric::memory::RetainedStorage;
    while let Some(current) = node {
        current.bytes.retain_credits(retained)?;
        retained.add_credit(&current._credit)?;
        node = current.next.as_deref();
    }
    Ok(())
}

impl crate::symmetric::memory::RetainedStorage for ReturnedOperands {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        retain_chain(self.head.as_deref(), retained)
    }
}

impl crate::symmetric::memory::RetainedStorage for Pool {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        retained.add_credit(&self._credit)?;
        for node in &self.inputs {
            retain_chain(node.as_deref(), retained)?;
        }
        retain_chain(self.shadow.as_deref(), retained)?;
        Ok(())
    }
}
