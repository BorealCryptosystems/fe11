// SPDX-License-Identifier: Apache-2.0
//! Bounded registry traversal without a private vector or last-owner drop in Entries.
use super::{Arc, Error, Registry, Result, Weak};
use crate::managed::NativeIdentity;

impl Registry<NativeIdentity> {
    /// Visit native identities through the last live entry present at entry.
    ///
    /// NativeIdentity publication inserts each Arc once per registry; typed
    /// views reuse that lifetime without reinsertion. This specialization is
    /// essential: a generic Registry may register the same Arc more than once,
    /// so pointer identity alone would not identify its cursor or end boundary.
    ///
    /// The callback must perform only local, nonwaiting bookkeeping: no native
    /// call, admission wait or registry mutation. It runs outside Entries.
    /// Expired entries may be pruned concurrently; new appended entries are not
    /// part of this visit. No reference is removed while a strong owner pins it.
    pub(crate) fn visit_native_identities(
        &self,
        mut visit: impl FnMut(&NativeIdentity),
    ) -> Result<()> {
        let (first, last) = {
            let entries = self.0.lock().map_err(|_| Error::Poisoned)?;
            if entries.broken {
                return Err(Error::Poisoned);
            }
            // Move both upgraded owners out before releasing either. In
            // particular, never drop a last Arc while holding Entries: its
            // ReferenceLifetime can notify a Wake that locks this same registry.
            let last = entries.items.iter().rev().find_map(Weak::upgrade);
            let first = entries
                .items
                .iter()
                .enumerate()
                .find_map(|(index, value)| value.upgrade().map(|value| (index, value)));
            (first, last)
        };
        let (Some((mut index, mut current)), Some(last)) = (first, last) else {
            return Ok(());
        };
        loop {
            visit(&current);
            if Arc::ptr_eq(&current, &last) {
                return Ok(());
            }
            let cursor = Arc::downgrade(&current);
            let next = {
                let entries = self.0.lock().map_err(|_| Error::Poisoned)?;
                if entries.broken {
                    return Err(Error::Poisoned);
                }
                // Pruning may move the pinned cursor, but cannot remove it.
                // Reuse its index unless compaction actually changed the slot.
                let position = if entries
                    .items
                    .get(index)
                    .is_some_and(|value| Weak::ptr_eq(value, &cursor))
                {
                    index
                } else {
                    entries
                        .items
                        .iter()
                        .position(|value| Weak::ptr_eq(value, &cursor))
                        .ok_or(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                            crate::ReferenceRegistryRejection::LiveRegistryCursorAbsent,
                        )))?
                };
                entries
                    .items
                    .iter()
                    .enumerate()
                    .skip(position + 1)
                    .find_map(|(index, value)| value.upgrade().map(|value| (index, value)))
            };
            // The pinned last owner remains after current in registry order,
            // so a successor must exist. All owner replacement/drop happens
            // outside Entries, including this internal-corruption error exit.
            let (next_index, next) =
                next.ok_or(Error::Rejected(crate::RejectionReason::ReferenceRegistry(
                    crate::ReferenceRegistryRejection::LiveRegistryBoundaryAbsent,
                )))?;
            index = next_index;
            current = next;
        }
    }
}
