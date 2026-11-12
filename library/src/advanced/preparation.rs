// SPDX-License-Identifier: Apache-2.0
//! Resource admission before session/operation guards are acquired.
use crate::{
    symmetric::memory::{ControlledReservation, Credit},
    Error, Result, Session,
};
use std::sync::atomic::Ordering;

/// A complete, unpublished shell. Its identity cannot be shared until an
/// ordinary session admission binds it; cancellation needs no later allocation.
pub(super) struct Shell {
    control: PreparedControl,
    identity: Option<super::lease::PreparedIdentity>,
}
/// Common native control storage is admitted with the operation, before any
/// dispatch. Cancellation's resident frame and terminal-retirement diagnostics
/// have separate owners; neither is borrowed from a family-specific cleanup.
pub(super) struct PreparedControl {
    pub(super) cancellation: super::cancellation::CancellationSlot,
    pub(super) retirement: crate::error::PreparedCleanupDiagnostic,
}

impl Shell {
    /// A replacement keeps the resident lease and population admission. Return
    /// the unused identity as well: the caller retires it outside possession.
    pub(super) fn into_replacement_parts(
        self,
    ) -> (PreparedControl, Option<super::lease::PreparedIdentity>) {
        (self.control, self.identity)
    }

    pub(super) fn allocation_bytes() -> usize {
        super::cancellation::CancellationSlot::allocation_bytes()
            + crate::error::PreparedCleanupDiagnostic::allocation_bytes()
            + super::lease::PreparedIdentity::allocation_bytes()
    }

    pub(super) fn from_prepaid(prepaid: &mut Credit) -> Result<Self> {
        Ok(Self {
            control: PreparedControl {
                cancellation: super::cancellation::CancellationSlot::from_prepaid(prepaid)?,
                retirement: crate::error::PreparedCleanupDiagnostic::prepare(prepaid)?,
            },
            identity: Some(super::lease::PreparedIdentity::from_prepaid(prepaid)?),
        })
    }

    pub(super) fn bind(
        self,
        admission: &crate::session::LeaseAdmission<'_, '_>,
    ) -> Result<(super::lease::TokenLease, PreparedControl)> {
        Self::bind_retained(&mut Some(self), admission)
    }

    /// On error the shell still owns its cancellation slot and identity. The
    /// access-first admission envelope controls when their credit is released.
    pub(super) fn bind_retained(
        shell: &mut Option<Self>,
        admission: &crate::session::LeaseAdmission<'_, '_>,
    ) -> Result<(super::lease::TokenLease, PreparedControl)> {
        let candidate =
            shell
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::OperationShellAbsent,
                )))?;
        let lease = super::lease::TokenLease::new_retained(admission, &mut candidate.identity)?;
        let shell = shell
            .take()
            .expect("shell checked before identity transfer");
        Ok((lease, shell.control))
    }
}

// These checks must remain atomic/pure: Budget invokes them under its Wake.
// They are routing observations, not authority to use a handle. Every caller
// must acquire ordinary access and validate again before installation/dispatch.
pub(crate) fn context(session: &Session) -> Result<()> {
    crate::session::activity::context(session)
}

/// A new owner tries its credit first. Only a wait would depend on resources
/// held by its own session's existing operation; installation settles races.
pub(crate) fn reserve_new_with_progress(
    session: &Session,
    bytes: usize,
    progress: &crate::session::AdmissionProgress,
) -> Result<Credit> {
    reserve_new_while(session, bytes, progress, || Ok(true))?.ok_or(Error::Rejected(
        crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::UnchangingPreparationWasInvalidated,
        ),
    ))
}

/// Keep the initiating authentication context through every capacity wait.
/// The predicate is atomic-only and also runs after a maintenance redirect;
/// possession still revalidates the same epoch before native dispatch.
pub(crate) fn reserve_new_at_epoch(
    session: &Session,
    bytes: usize,
    progress: &crate::session::AdmissionProgress,
    epoch: u64,
) -> Result<Credit> {
    reserve_new_while(session, bytes, progress, || {
        crate::session::recovery::observations::context(session, Some(epoch), epoch)?;
        Ok(true)
    })?
    .ok_or(Error::Rejected(crate::RejectionReason::OperationOwnership(
        crate::OperationOwnershipRejection::UnchangingPreparationWasInvalidated,
    )))
}

/// Admit a complete local recipe only while its atomic sizing assumptions hold.
/// None requests guard-free replanning, not a retry of a native operation. The
/// predicate runs under Wake: no blocking lock, allocation, owner destruction
/// or notification. A metadata-only try_lock may inspect without side effects
/// and redirect on contention; its guard must leave before returning. Reclaim
/// any discarded preparation only after the redirect has released Wake.
pub(crate) fn reserve_new_while(
    session: &Session,
    bytes: usize,
    progress: &crate::session::AdmissionProgress,
    current: impl Fn() -> Result<bool>,
) -> Result<Option<Credit>> {
    reserve_new_while_in(
        session,
        &session.inner.symmetric_budget,
        bytes,
        progress,
        current,
    )
}

/// Preserve the common admission and maintenance protocol while attributing
/// private continuation storage to its existing child account.
pub(crate) fn reserve_new_while_in(
    session: &Session,
    budget: &std::sync::Arc<crate::symmetric::memory::Budget>,
    bytes: usize,
    progress: &crate::session::AdmissionProgress,
    current: impl Fn() -> Result<bool>,
) -> Result<Option<Credit>> {
    if !budget.same_account(&session.inner.symmetric_budget) {
        return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
            crate::OperationOwnershipRejection::ForeignPreparationBudget,
        )));
    }
    enum Route {
        Replan,
        Maintain,
    }
    let admission = crate::admission_wait::current();
    loop {
        if !current()? {
            context(session)?;
            admission.check_available()?;
            return Ok(None);
        }
        // A consumed source cannot release its bytes during this wait. Check
        // its complete overlap after every sizing retry, without reserving it twice.
        let reserved = progress.check_retained(session, bytes).and_then(|()| {
            budget.reserve_controlled_retaining(
                bytes,
                crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
                &admission,
                || {
                    context(session)?;
                    Ok((!current()?).then_some(Route::Replan))
                },
                || {
                    if session.entry.advanced_operation.load(Ordering::Acquire) == 0 {
                        return Ok(None);
                    }
                    if progress.can_maintain() && session.entry.advanced_progress.cleanup_hint() {
                        return Ok(Some(Route::Maintain));
                    }
                    if matches!(admission, crate::ResourceAdmission::WaitUntil { .. }) {
                        return Err(Error::Busy(crate::BusyReason::OperationOwnership(
                            crate::OperationOwnershipBusy::AdvancedOperation,
                        )));
                    }
                    Ok(None)
                },
            )
        });
        // If the ceiling refused an obsolete size before entering Wake, discard
        // that recipe instead of reporting the old footprint as a current need.
        let reserved = match reserved {
            Err(Error::ResourceLimitExceeded { .. }) if !current()? => {
                context(session)?;
                admission.check_available()?;
                return Ok(None);
            }
            result => result?,
        };
        match reserved {
            ControlledReservation::Acquired(credit) => return Ok(Some(credit)),
            ControlledReservation::Redirect(Route::Replan) => return Ok(None),
            ControlledReservation::Redirect(Route::Maintain) => {
                // Wake is released before any gate or Operation is touched.
                // Keep the same deadline and allow only this one local pass.
                progress.maintain_local(session)?;
            }
        }
    }
}

pub(super) enum CancellationPreparation {
    New(Credit),
    UseCurrent,
}

/// A cancellation encountering an installed owner uses that owner's prepaid
/// slot, even if the module budget cannot admit another slot. The caller loops
/// under session access if the observed owner disappeared before acquisition.
pub(super) fn reserve_cancellation(
    session: &Session,
    bytes: usize,
) -> Result<CancellationPreparation> {
    let reserved = session.inner.symmetric_budget.reserve_controlled(
        bytes,
        &crate::admission_wait::current(),
        || {
            context(session)?;
            if session.entry.advanced_operation.load(Ordering::Acquire) != 0 {
                return Ok(Some(()));
            }
            session.inner.symmetric_budget.check_request(
                crate::session::lifecycle_diagnostics::Store::including(bytes)?,
            )?;
            Ok(None)
        },
        || Ok(None),
    )?;
    Ok(match reserved {
        ControlledReservation::Acquired(credit) => CancellationPreparation::New(credit),
        ControlledReservation::Redirect(()) => CancellationPreparation::UseCurrent,
    })
}


