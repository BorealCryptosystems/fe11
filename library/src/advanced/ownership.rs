// SPDX-License-Identifier: Apache-2.0
//! Local owner alternatives. Native buffers remain in their stable allocations.
//! Cancellation and continuation are independent of the retained work/control.

use super::{
    detachment, rejoin, restoration, restoration_transfer, saved_state, state_io, Operation,
};
use crate::{Error, Result};
use fe11_sys::CK_FLAGS;

pub(super) enum StateOwner {
    Capture(saved_state::CaptureOwner),
    Restore(restoration::RestoreOwner),
}
pub(super) struct StateControl {
    pub(super) io: state_io::StateIo,
    pub(super) owner: StateOwner,
}
pub(super) enum TransferOwner {
    Detaching(detachment::DetachControl),
    Rejoining(rejoin::RejoinControl),
    Restoring(restoration_transfer::RestoreTransfer),
}
/// Admit an empty slot before a factory may consume its caller's capability.
/// Factories prepare local owners only; they never dispatch native work.
pub(super) struct OwnerSlot<T> {
    value: Option<T>,
}
impl<T> Default for OwnerSlot<T> {
    fn default() -> Self {
        Self { value: None }
    }
}
impl<T> OwnerSlot<T> {
    fn install_with(&mut self, busy: crate::BusyReason, prepare: impl FnOnce() -> T) -> Result<()> {
        if self.value.is_some() {
            return Err(Error::Busy(busy));
        }
        self.value = Some(prepare());
        Ok(())
    }
    pub(super) fn is_some(&self) -> bool {
        self.value.is_some()
    }
    pub(super) fn as_ref(&self) -> Option<&T> {
        self.value.as_ref()
    }
    pub(super) fn as_mut(&mut self) -> Option<&mut T> {
        self.value.as_mut()
    }
    pub(super) fn take(&mut self) -> Option<T> {
        self.value.take()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CancellationState {
    Uncancelled,
    Withdrawn { remaining: CK_FLAGS },
}
impl CancellationState {
    pub(super) fn is_withdrawn(self) -> bool {
        matches!(self, Self::Withdrawn { .. })
    }
    pub(super) fn remaining(self) -> Option<CK_FLAGS> {
        match self {
            Self::Uncancelled => None,
            Self::Withdrawn { remaining } => Some(remaining),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FreezeReason {
    // Diagnostic reasons; each enforces the same continuation barrier.
    CapturedEncryption,
    NativeDetachment,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ContinuationStatus {
    Runnable,
    Frozen(FreezeReason),
}
impl ContinuationStatus {
    pub(super) fn is_frozen(self) -> bool {
        matches!(self, Self::Frozen(_))
    }
}
impl Operation {
    fn begin_state(&mut self, prepare: impl FnOnce() -> StateControl) -> Result<()> {
        self.state.install_with(
            crate::BusyReason::OperationOwnership(
                crate::OperationOwnershipBusy::OperationStateControl,
            ),
            prepare,
        )
    }
    pub(super) fn begin_capture(
        &mut self,
        prepare: impl FnOnce() -> (state_io::StateIo, saved_state::CaptureOwner),
    ) -> Result<()> {
        self.begin_state(|| {
            let (io, owner) = prepare();
            StateControl {
                io,
                owner: StateOwner::Capture(owner),
            }
        })
    }
    pub(super) fn begin_restore(
        &mut self,
        prepare: impl FnOnce() -> (state_io::StateIo, restoration::RestoreOwner),
    ) -> Result<()> {
        self.begin_state(|| {
            let (io, owner) = prepare();
            StateControl {
                io,
                owner: StateOwner::Restore(owner),
            }
        })
    }
    pub(super) fn state_io(&self) -> Option<&state_io::StateIo> {
        self.state.as_ref().map(|state| &state.io)
    }
    pub(super) fn state_io_mut(&mut self) -> Option<&mut state_io::StateIo> {
        self.state.as_mut().map(|state| &mut state.io)
    }
    pub(super) fn drive_restoration(
        &mut self,
        state: &crate::module::State,
        entry: &crate::module::SessionEntry,
        remaining: &mut usize,
    ) -> Result<()> {
        let control = self.state.as_mut().ok_or(Error::Rejected(
            crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::RestorationIoAbsent,
            ),
        ))?;
        let StateOwner::Restore(owner) = &mut control.owner else {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::RestorationOwnerAbsent,
            )));
        };
        owner.check_keys(entry)?;
        control
            .io
            .drive_before_restore(state, entry, true, remaining, &mut || {
                owner.check_keys(entry)?;
                owner.keys.arm_native_keys();
                Ok(())
            })
    }
    pub(super) fn capture_owner(&self) -> Option<&saved_state::CaptureOwner> {
        match &self.state.as_ref()?.owner {
            StateOwner::Capture(owner) => Some(owner),
            _ => None,
        }
    }
    pub(super) fn capture_owner_mut(&mut self) -> Option<&mut saved_state::CaptureOwner> {
        match &mut self.state.as_mut()?.owner {
            StateOwner::Capture(owner) => Some(owner),
            _ => None,
        }
    }
    pub(super) fn restore_owner(&self) -> Option<&restoration::RestoreOwner> {
        match &self.state.as_ref()?.owner {
            StateOwner::Restore(owner) => Some(owner),
            _ => None,
        }
    }
    pub(super) fn restore_owner_mut(&mut self) -> Option<&mut restoration::RestoreOwner> {
        match &mut self.state.as_mut()?.owner {
            StateOwner::Restore(owner) => Some(owner),
            _ => None,
        }
    }
    pub(super) fn take_capture(
        &mut self,
    ) -> Option<(state_io::StateIo, saved_state::CaptureOwner)> {
        self.capture_owner()?;
        let StateControl {
            io,
            owner: StateOwner::Capture(owner),
        } = self.state.take()?
        else {
            unreachable!()
        };
        Some((io, owner))
    }
    pub(super) fn take_restore(
        &mut self,
    ) -> Option<(state_io::StateIo, restoration::RestoreOwner)> {
        self.restore_owner()?;
        let StateControl {
            io,
            owner: StateOwner::Restore(owner),
        } = self.state.take()?
        else {
            unreachable!()
        };
        Some((io, owner))
    }
    pub(super) fn detachment(&self) -> Option<&detachment::DetachControl> {
        self.transfer.detachment()
    }
    pub(super) fn detachment_mut(&mut self) -> Option<&mut detachment::DetachControl> {
        self.transfer.detachment_mut()
    }
    pub(super) fn rejoin(&self) -> Option<&rejoin::RejoinControl> {
        self.transfer.rejoin()
    }
    pub(super) fn rejoin_mut(&mut self) -> Option<&mut rejoin::RejoinControl> {
        self.transfer.rejoin_mut()
    }
    pub(super) fn restore_transfer(&self) -> Option<&restoration_transfer::RestoreTransfer> {
        self.transfer.restore_transfer()
    }
    pub(super) fn restore_transfer_mut(
        &mut self,
    ) -> Option<&mut restoration_transfer::RestoreTransfer> {
        self.transfer.restore_transfer_mut()
    }
    pub(super) fn begin_detachment(
        &mut self,
        prepare: impl FnOnce() -> detachment::DetachControl,
    ) -> Result<()> {
        if self.restore_owner().is_some() {
            return Err(Error::Busy(crate::BusyReason::Detachment(
                crate::DetachmentBusy::RestorationRequiresItsTransferTicket,
            )));
        }
        self.transfer.begin_detachment(prepare)
    }
    pub(super) fn begin_rejoin(
        &mut self,
        prepare: impl FnOnce() -> rejoin::RejoinControl,
    ) -> Result<()> {
        self.transfer.begin_rejoin(prepare)
    }
    pub(super) fn begin_restore_transfer(
        &mut self,
        prepare: impl FnOnce() -> restoration_transfer::RestoreTransfer,
    ) -> Result<()> {
        if self.restore_owner().is_none() {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::RestorationAbsent,
            )));
        }
        self.transfer.begin_restore_transfer(prepare)
    }
    pub(super) fn take_detachment(&mut self) -> Option<detachment::DetachControl> {
        self.transfer.take_detachment()
    }
    pub(super) fn take_rejoin(&mut self) -> Option<rejoin::RejoinControl> {
        self.transfer.take_rejoin()
    }
    pub(super) fn take_restore_transfer(
        &mut self,
    ) -> Option<restoration_transfer::RestoreTransfer> {
        self.transfer.take_restore_transfer()
    }
}

impl OwnerSlot<TransferOwner> {
    fn detachment(&self) -> Option<&detachment::DetachControl> {
        match self.as_ref()? {
            TransferOwner::Detaching(owner) => Some(owner),
            _ => None,
        }
    }
    fn detachment_mut(&mut self) -> Option<&mut detachment::DetachControl> {
        match self.as_mut()? {
            TransferOwner::Detaching(owner) => Some(owner),
            _ => None,
        }
    }
    fn rejoin(&self) -> Option<&rejoin::RejoinControl> {
        match self.as_ref()? {
            TransferOwner::Rejoining(owner) => Some(owner),
            _ => None,
        }
    }
    fn rejoin_mut(&mut self) -> Option<&mut rejoin::RejoinControl> {
        match self.as_mut()? {
            TransferOwner::Rejoining(owner) => Some(owner),
            _ => None,
        }
    }
    fn restore_transfer(&self) -> Option<&restoration_transfer::RestoreTransfer> {
        match self.as_ref()? {
            TransferOwner::Restoring(owner) => Some(owner),
            _ => None,
        }
    }
    fn restore_transfer_mut(&mut self) -> Option<&mut restoration_transfer::RestoreTransfer> {
        match self.as_mut()? {
            TransferOwner::Restoring(owner) => Some(owner),
            _ => None,
        }
    }
    fn begin_detachment(
        &mut self,
        prepare: impl FnOnce() -> detachment::DetachControl,
    ) -> Result<()> {
        self.install_with(
            crate::BusyReason::AsynchronousExecution(
                crate::AsynchronousExecutionBusy::OperationTransferActive,
            ),
            || TransferOwner::Detaching(prepare()),
        )
    }
    fn begin_rejoin(&mut self, prepare: impl FnOnce() -> rejoin::RejoinControl) -> Result<()> {
        self.install_with(
            crate::BusyReason::AsynchronousExecution(
                crate::AsynchronousExecutionBusy::OperationTransferActive,
            ),
            || TransferOwner::Rejoining(prepare()),
        )
    }
    fn begin_restore_transfer(
        &mut self,
        prepare: impl FnOnce() -> restoration_transfer::RestoreTransfer,
    ) -> Result<()> {
        self.install_with(
            crate::BusyReason::AsynchronousExecution(
                crate::AsynchronousExecutionBusy::OperationTransferActive,
            ),
            || TransferOwner::Restoring(prepare()),
        )
    }
    fn take_detachment(&mut self) -> Option<detachment::DetachControl> {
        self.detachment()?;
        let TransferOwner::Detaching(owner) = self.take()? else {
            unreachable!()
        };
        Some(owner)
    }
    fn take_rejoin(&mut self) -> Option<rejoin::RejoinControl> {
        self.rejoin()?;
        let TransferOwner::Rejoining(owner) = self.take()? else {
            unreachable!()
        };
        Some(owner)
    }
    fn take_restore_transfer(&mut self) -> Option<restoration_transfer::RestoreTransfer> {
        self.restore_transfer()?;
        let TransferOwner::Restoring(owner) = self.take()? else {
            unreachable!()
        };
        Some(owner)
    }
}
