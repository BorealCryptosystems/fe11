// SPDX-License-Identifier: Apache-2.0
//! Durable scope of a close receipt. Local publication failure retains a signal
//! before token possession ends, without acquiring a writer or replaying C.

use crate::advanced::{
    CloseFailureProgress, CloseFailureRetention, ClosePhase, ClosePublication, CloseState,
};
use crate::module::{SessionEntry, SlotClose};
use std::ops::{Deref, DerefMut};
use std::sync::MutexGuard;

pub(crate) enum CloseScope {
    Local { signal: Option<SlotClose> },
    Protected { reservation: Option<crate::managed::CloseReservation> },
}

impl CloseScope {
    /// Transfer barriers for destruction after coordination guards. An empty
    /// protected reservation must never be mistaken for a local-close proof.
    pub(crate) fn release(&mut self) -> Self {
        match self {
            Self::Local { signal } => Self::Local {
                signal: signal.take(),
            },
            Self::Protected { reservation } => Self::Protected {
                reservation: reservation.take(),
            },
        }
    }

    pub(super) fn is_local(&self) -> bool {
        matches!(self, Self::Local { .. })
    }
}

/// Owns the control mutex inside all possession guards. Its Drop also runs on
/// unwind; the receipt, not this stack frame, retains the eventual SlotClose.
pub(super) struct CloseReceipt<'a> {
    control: MutexGuard<'a, Option<CloseState>>,
    entry: &'a SessionEntry,
    native: &'a crate::native::Native,
}

impl<'a> CloseReceipt<'a> {
    pub(super) fn new(entry: &'a SessionEntry, native: &'a crate::native::Native) -> Self {
        Self {
            control: entry
                .close_control
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()),
            entry,
            native,
        }
    }
}

impl Deref for CloseReceipt<'_> {
    type Target = Option<CloseState>;
    fn deref(&self) -> &Self::Target {
        &self.control
    }
}
impl DerefMut for CloseReceipt<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.control
    }
}

impl Drop for CloseReceipt<'_> {
    fn drop(&mut self) {
        let Some(close) = self.control.as_mut() else {
            return;
        };
        let terminal = matches!(close.phase, ClosePhase::Returned {
            publication: ClosePublication::Complete | ClosePublication::Failure {
                progress: CloseFailureProgress::Complete,
                retention: CloseFailureRetention::Ordinary,
            }, ..
        });
        if terminal {
            return;
        }
        if let CloseScope::Local { signal } = &mut close.scope {
            if matches!(close.phase, ClosePhase::Issued) {
                self.native.mark_uncertain();
            }
            if signal.is_none() {
                match SlotClose::new(&self.entry.snapshot.domain) {
                    Ok(held) => *signal = Some(held),
                    // Overflow must not leave consumers relying on a missing
                    // token signal. Preserve all resources and retire admission.
                    Err(_) => self.native.mark_unscoped_pending(),
                }
            }
        }
    }
}
