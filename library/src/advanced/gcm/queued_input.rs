// SPDX-License-Identifier: Apache-2.0
//! Lifetime of bytes supplied through a complete-message/list facade.
//!
//! A successful encryption call retires its consumed input. Decryption keeps
//! the current message's ciphertext for explicitly authorized fresh decryption recovery
//! until that message completes. Future messages remain owned by the facade.
//! Retirement nodes are admitted and allocated before native possession: a
//! returned call only transfers ownership, even under eager batch execution.
use super::{AeadMessageOperation, AeadStep, PreparedAead};
use crate::advanced::{record, MessageRoute};
use crate::symmetric::memory::{Buffer, Credit};
use crate::{Error, Result};
use std::mem::size_of;

struct Node {
    bytes: Option<Buffer>,
    next: Option<Box<Node>>,
    _credit: Credit,
}

#[derive(Default)]
pub(super) struct Retired {
    head: Option<Box<Node>>,
}

impl Retired {
    pub(super) fn is_empty(&self) -> bool {
        self.head.is_none()
    }
}

impl Drop for Retired {
    fn drop(&mut self) {
        // Iterative destruction bounds stack use independently of list length.
        // The containing release owner is dropped only outside possession.
        while let Some(mut node) = self.head.take() {
            self.head = node.next.take();
            drop(node);
        }
    }
}

pub(super) struct Storage {
    slots: Vec<Option<Box<Node>>>,
    // Keep the vector charged through partial binding. Its populated nodes
    // and allocation must be destroyed before this last field releases credit.
    metadata_credit: Option<Credit>,
}

pub(super) struct Pool {
    slots: Vec<Option<Box<Node>>>,
    _credit: Credit,
}

fn metadata(count: usize) -> Result<usize> {
    count
        .checked_mul(size_of::<Option<Box<Node>>>())
        .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
            crate::AeadMessagesRejection::AeadRetirementMetadataOverflow,
        )))
}

impl Storage {
    pub(super) fn required_bytes(count: usize) -> Result<usize> {
        count
            .checked_mul(size_of::<Node>())
            .and_then(|bytes| bytes.checked_add(metadata(count).ok()?))
            .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadRetirementStorageOverflow,
            )))
    }

    pub(super) fn allocate(count: usize) -> Result<Self> {
        let mut slots = Vec::new();
        slots.try_reserve_exact(count).map_err(|_| {
            Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadRetirementAllocation,
            ))
        })?;
        slots.resize_with(count, || None);
        Ok(Self {
            slots,
            metadata_credit: None,
        })
    }

    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        self.slots
            .len()
            .checked_mul(size_of::<Node>())
            .and_then(|bytes| bytes.checked_add(metadata(self.slots.capacity()).ok()?))
            .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadRetirementStorageOverflow,
            )))
    }

    /// Called after actual capacities have been admitted, outside all guards.
    pub(super) fn bind(mut self, prepaid: &mut Credit) -> Result<Pool> {
        self.metadata_credit = Some(prepaid.split(metadata(self.slots.capacity())?)?);
        for slot in &mut self.slots {
            *slot = Some(Box::new(Node {
                bytes: None,
                next: None,
                _credit: prepaid.split(size_of::<Node>())?,
            }));
        }
        Ok(Pool {
            slots: self.slots,
            _credit: self
                .metadata_credit
                .take()
                .expect("bound AEAD retirement metadata"),
        })
    }
}

impl Pool {
    fn check(&self, index: usize) -> Result<()> {
        if self.slots.get(index).is_some_and(Option::is_some) {
            Ok(())
        } else {
            Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadRetirementSlotAbsent,
            )))
        }
    }

    fn take(&mut self, index: usize, bytes: &mut Buffer, retired: &mut Retired) {
        let mut node = self.slots[index]
            .take()
            .expect("preflighted AEAD retirement slot");
        node.bytes = Some(bytes.take());
        node.next = retired.head.take();
        retired.head = Some(node);
    }

    /// Imported historical records may retain already consumed input. Their
    /// unpublished owner is prepared outside possession, so discard it directly
    /// instead of making a new destination retain obsolete history.
    fn discard_before_binding(&mut self, index: usize, bytes: &mut Buffer) {
        drop(bytes.take());
        drop(self.slots[index].take());
    }
}

fn consumed_parts(step: AeadStep, restart: usize, index: usize, count: usize) -> usize {
    match step {
        AeadStep::Init if index < restart => count,
        AeadStep::Single(current) | AeadStep::Begin(current) | AeadStep::Next(current, _)
            if index < current =>
        {
            count
        }
        AeadStep::Next(current, part) if index == current => part,
        AeadStep::Finish | AeadStep::Done => count,
        _ => 0,
    }
}

impl AeadMessageOperation {
    pub(super) fn queued_fragments(&self, index: usize) -> Result<record::Fragments<'_>> {
        let frame =
            self.frames
                .get(index)
                .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadQueuedRowAbsent,
                )))?;
        let consumed = consumed_parts(
            self.dispatch_step(),
            self.restart_at,
            index,
            frame.inputs.len(),
        );
        if consumed == frame.inputs.len() && consumed != 0 {
            return Ok(record::Fragments::Slices(&[]));
        }
        if self.route == MessageRoute::Single || frame.layout.lengths().is_empty() {
            return frame.layout.fragments(&frame.inputs, self.route);
        }
        if frame.inputs.len() != frame.layout.lengths().len() {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadQueuedFragmentCount,
            )));
        }
        for (part, (bytes, expected)) in frame.inputs.iter().zip(frame.layout.lengths()).enumerate()
        {
            if bytes.as_slice().len() != *expected
                && !(part < consumed && bytes.as_slice().is_empty())
            {
                return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadQueuedFragmentWidth,
                )));
            }
        }
        Ok(record::Fragments::Buffers(&frame.inputs))
    }

    pub(super) fn check_queued_retirement(&self) -> Result<()> {
        if self.input.is_some() {
            return Ok(());
        }
        let (index, part) = match self.dispatch_step() {
            AeadStep::Single(index) => (index, 0),
            AeadStep::Next(index, part) => (index, part),
            _ => return Ok(()),
        };
        let frame =
            self.frames
                .get(index)
                .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadQueuedRowAbsent,
                )))?;
        let pool = frame.retirement.as_ref().ok_or(Error::Rejected(
            crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadRetirementPoolAbsent,
            ),
        ))?;
        if self.decrypt {
            if self.last() {
                for part in 0..frame.inputs.len() {
                    pool.check(part)?;
                }
            }
        } else {
            pool.check(part)?;
        }
        Ok(())
    }

    pub(super) fn retire_queued_success(&mut self, last: bool) {
        if self.input.is_some() {
            return;
        }
        let (index, part) = match self.step {
            AeadStep::Single(index) => (index, 0),
            AeadStep::Next(index, part) => (index, part),
            _ => return,
        };
        let frame = &mut self.frames[index];
        let pool = frame
            .retirement
            .as_mut()
            .expect("preflighted queued retirement");
        if self.decrypt {
            if last {
                for (part, bytes) in frame.inputs.iter_mut().enumerate() {
                    pool.take(part, bytes, &mut self.retired_queued);
                }
            }
        } else {
            pool.take(part, &mut frame.inputs[part], &mut self.retired_queued);
        }
    }
}

impl PreparedAead {
    pub(super) fn discard_restored_history(&mut self) {
        let step = match self.step {
            AeadStep::Output(pending) => pending.step(),
            step => step,
        };
        for (index, frame) in self.frames.iter_mut().enumerate() {
            let consumed = consumed_parts(step, self.restart_at, index, frame.inputs.len());
            // Current ciphertext remains necessary for recovery until its complete
            // message belongs to the finished prefix. Encryption has no fresh-decryption recovery.
            let count = if self.decrypt && consumed < frame.inputs.len() {
                0
            } else {
                consumed
            };
            if let Some(pool) = frame.retirement.as_mut() {
                for part in 0..count {
                    pool.discard_before_binding(part, &mut frame.inputs[part]);
                }
            }
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

impl crate::symmetric::memory::RetainedStorage for Retired {
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
        for node in &self.slots {
            retain_chain(node.as_deref(), retained)?;
        }
        Ok(())
    }
}
