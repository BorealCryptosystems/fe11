// SPDX-License-Identifier: Apache-2.0
//! Scalar native control frames admitted before taking session possession.
use super::{AdmissionProgress, CleanupAdmission, Session, SessionAccess};
use crate::{
    native::frame::SessionFrame,
    symmetric::memory::{ControlledReservation, Credit},
    Error, ResourceAdmission, Result,
};

pub(super) struct ControlCall<T> {
    pub value: T,
    // Uncertain native completion retains this credit with the scalar frame.
    _credit: Credit,
}

impl Session {
    /// The private factory initializes only fixed inline output. It must not
    /// allocate, reserve resources or dispatch native work.
    pub(super) fn prepare_control<T: Send + 'static>(
        &self,
        initialize: impl FnMut() -> T,
    ) -> Result<(ControlCall<T>, SessionAccess<'_>)> {
        let (data, _, access) = self.prepare_control_candidate(initialize, false)?;
        Ok((data, access))
    }

    pub(super) fn prepare_control_with_completion<T: Send + 'static>(
        &self,
        initialize: impl FnMut() -> T,
    ) -> Result<(
        ControlCall<T>,
        crate::error::PreparedCompletionCell,
        SessionAccess<'_>,
    )> {
        let (data, diagnostic, access) = self.prepare_control_candidate(initialize, true)?;
        Ok((data, diagnostic.expect("requested completion leaf"), access))
    }

    fn prepare_control_candidate<T: Send + 'static>(
        &self,
        mut initialize: impl FnMut() -> T,
        with_completion: bool,
    ) -> Result<(
        ControlCall<T>,
        Option<crate::error::PreparedCompletionCell>,
        SessionAccess<'_>,
    )> {
        let policy = crate::admission_wait::current();
        let session_policy = self.admission();
        let progress = AdmissionProgress::default();
        let diagnostic_bytes = if with_completion {
            crate::error::CompletionStorage::allocation_bytes()
        } else {
            0
        };
        let bytes = std::mem::size_of::<ControlCall<T>>()
            .checked_add(SessionFrame::<'_, ControlCall<T>>::allocation_bytes())
            .and_then(|bytes| bytes.checked_add(diagnostic_bytes))
            .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ControlFrameAccounting,
            )))?;
        loop {
            policy.check_available()?;
            session_policy.check_available()?;
            let mut credit = loop {
                let reserved =
                    self.inner.symmetric_budget.reserve_controlled_retaining(
                        bytes,
                        crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
                        &policy,
                        || {
                            super::activity::context(self)?;
                            Ok(None::<()>)
                        },
                        || {
                            Ok((progress.can_maintain()
                                && self.entry.advanced_progress.cleanup_hint())
                            .then_some(()))
                        },
                    )?;
                match reserved {
                    ControlledReservation::Acquired(credit) => break credit,
                    ControlledReservation::Redirect(()) => progress.maintain_local(self)?,
                }
            };
            let diagnostic = if with_completion {
                Some(crate::error::PreparedCompletionCell::prepare(&mut credit)?)
            } else {
                None
            };
            let candidate = ControlCall {
                value: initialize(),
                _credit: credit,
            };
            let attempt = self.try_advanced_access_progress(&progress);
            match attempt {
                Ok(access) => return Ok((candidate, diagnostic, access)),
                Err(error @ Error::Busy(_)) => {
                    drop(candidate);
                    drop(diagnostic);
                    if matches!(policy, ResourceAdmission::Immediate)
                        && matches!(session_policy, crate::SessionAdmission::Immediate)
                    {
                        return Err(error);
                    }
                }
                Err(error) => return Err(error),
            }
            // No copied candidate or credit survives a possession wait. Scalar
            // control remains allowed alongside a parked owner: that owner is
            // neither consumed nor treated as a reason to replace WaitUntil.
            drop(self.advanced_access_progress(CleanupAdmission::Ordinary, &progress)?);
        }
    }
}
