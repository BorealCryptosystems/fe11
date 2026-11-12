// SPDX-License-Identifier: Apache-2.0
//! Authentication storage joins the caller's complete pre-possession recipe.
use super::{ContextAuthentication, ContextDiagnostics, ContextLoginInput};
use crate::{
    pin::{LoginFrame, PinWitness},
    symmetric::memory::Credit,
    Error, Result, SecretBytes, Session,
};
use std::mem::size_of;

/// Borrowed sizing information only. Original credentials are not consumed by
/// a discarded candidate or copied into a second native input.
pub(crate) struct ContextLoginPlan<'a> {
    request: Option<&'a ContextAuthentication>,
    fixed_bytes: usize,
    required: usize,
    authentication: u64,
}

struct Witnesses {
    pin: PinWitness,
    name: Option<SecretBytes>,
}

/// The fields are destroyed in this order on error and unwind. Credit covers
/// the witnesses and the future native frame, including transferred inputs.
pub(crate) struct ContextLoginStorage {
    witnesses: Witnesses,
    diagnostics: ContextDiagnostics,
    authentication: u64,
    credit: Credit,
}

fn accounting() -> Error {
    Error::Rejected(crate::RejectionReason::SessionLifecycle(
        crate::SessionLifecycleRejection::ContextAuthenticationStorageAccounting,
    ))
}

impl<'a> ContextLoginPlan<'a> {
    pub(crate) fn new(
        session: &Session,
        request: Option<&'a ContextAuthentication>,
    ) -> Result<Self> {
        Self::with_epoch(request, session.snapshot.authentication_stamp())
    }

    /// Bind the login recipe to the context captured before the operation's
    /// first wait. This must not adopt a later login/logout during preparation.
    pub(crate) fn at_epoch(
        session: &Session,
        request: Option<&'a ContextAuthentication>,
        authentication: u64,
    ) -> Result<Self> {
        crate::session::recovery::observations::context(
            session,
            Some(authentication),
            authentication,
        )?;
        Self::with_epoch(request, authentication)
    }

    fn with_epoch(request: Option<&'a ContextAuthentication>, authentication: u64) -> Result<Self> {
        let Some(request) = request else {
            return Ok(Self {
                request: None,
                fixed_bytes: 0,
                required: 0,
                authentication,
            });
        };
        let (pin_capacity, pin_length) = request.input.pin.storage_sizes();
        let (name_capacity, name_length) = request
            .input
            .user_name
            .as_ref()
            .map_or((0, 0), |name| (name.capacity(), name.len()));
        crate::bounds::ck_length(pin_length)?;
        crate::bounds::ck_length(name_length)?;
        let fixed_bytes = size_of::<ContextLoginInput>()
            .checked_add(
                crate::native::frame::SessionFrame::<ContextLoginInput>::allocation_bytes(),
            )
            .and_then(|n| n.checked_add(pin_capacity))
            .and_then(|n| n.checked_add(name_capacity))
            .and_then(|n| n.checked_add(ContextDiagnostics::allocation_bytes()))
            .ok_or_else(accounting)?;
        let required = fixed_bytes
            .checked_add(pin_length)
            .and_then(|n| n.checked_add(name_length))
            .ok_or_else(accounting)?;
        Ok(Self {
            request: Some(request),
            fixed_bytes,
            required,
            authentication,
        })
    }

    /// Include authentication in the factory's reservation. The returned
    /// residual credit belongs solely to its original coordination overhead.
    /// This method never reserves independently or holds guards while waiting.
    pub(crate) fn prepare<T>(
        &mut self,
        session: &Session,
        overhead: usize,
        mut prepare: impl FnMut(usize) -> Result<(T, Credit)>,
    ) -> Result<((T, Option<ContextLoginStorage>), Credit)> {
        let Some(request) = self.request else {
            let (candidate, credit) = prepare(overhead)?;
            return Ok(((candidate, None), credit));
        };
        loop {
            session
                .snapshot
                .check_authentication_unchanged(self.authentication)?;
            let combined = overhead.checked_add(self.required).ok_or_else(accounting)?;
            // Keep the tuple intact until success: its candidate always drops
            // before residual credit on every subsequent allocation/error path.
            let mut candidate = prepare(combined)?;
            let witnesses = Witnesses {
                pin: request.input.pin.witness()?,
                name: request.input.name_witness()?,
            };
            let pin_bytes = match &witnesses.pin {
                PinWitness::Protected => 0,
                PinWitness::Provided(bytes) => bytes.allocated_bytes(),
            };
            let actual = self
                .fixed_bytes
                .checked_add(pin_bytes)
                .and_then(|n| {
                    n.checked_add(
                        witnesses
                            .name
                            .as_ref()
                            .map_or(0, SecretBytes::allocated_bytes),
                    )
                })
                .ok_or_else(accounting)?;
            if actual > self.required {
                drop(witnesses);
                drop(candidate);
                self.required = actual;
                continue;
            }
            candidate.1.release(self.required - actual);
            let mut credit = candidate.1.split(actual)?;
            let storage = ContextLoginStorage {
                witnesses,
                // Moving witnesses into the partial constructor first ensures
                // allocation failure drops them before the remaining credit.
                diagnostics: ContextDiagnostics::prepare(&mut credit)?,
                authentication: self.authentication,
                credit,
            };
            return Ok(((candidate.0, Some(storage)), candidate.1));
        }
    }
}

impl ContextLoginStorage {
    pub(super) fn check_context(&self, session: &Session) -> Result<()> {
        session
            .snapshot
            .check_authentication_unchanged(self.authentication)
    }

    /// The enclosing frame factory checked context and completed its fallible
    /// preparation while this storage and the original input were still owned.
    pub(super) fn into_input(self, input: LoginFrame) -> (ContextLoginInput, ContextDiagnostics) {
        (
            ContextLoginInput {
                input,
                pin_witness: self.witnesses.pin,
                name_witness: self.witnesses.name,
                _credit: self.credit,
            },
            self.diagnostics,
        )
    }
}

impl ContextLoginPlan<'_> {
    /// Compose another native owner with authentication before possession.
    /// A busy permission/session attempt discards both owners before waiting.
    /// Readers must be prepared at the original epoch with the context notifier.
    pub(crate) fn prepare_readers_with<'s, T, const N: usize>(
        &mut self,
        session: &'s Session,
        readers: &crate::session::activity::Readers<N>,
        mut prepare: impl FnMut(usize) -> Result<(T, Credit)>,
        mut grant: impl FnMut(
            crate::session::activity::PossessionAttempt,
        ) -> Result<crate::session::SessionAccess<'s>>,
    ) -> Result<(
        T,
        Option<ContextLoginStorage>,
        crate::session::SessionAccess<'s>,
        [Option<crate::registry::ReadPermit>; N],
    )> {
        use crate::session::activity::PossessionAttempt;
        let policy = crate::admission_wait::current();
        let session_policy = session.admission();
        loop {
            let ((candidate, storage), residual) = self.prepare(session, 0, &mut prepare)?;
            drop(residual);
            let attempt = policy.try_once(|| {
                session_policy.try_once(|| {
                    readers.try_acquire(session, || grant(PossessionAttempt::Nonwaiting))
                })
            });
            match attempt {
                Ok((access, permits)) => return Ok((candidate, storage, access, permits)),
                Err(error @ Error::Busy(_)) => {
                    drop(candidate);
                    drop(storage);
                    if matches!(policy, crate::ResourceAdmission::Immediate)
                        && matches!(session_policy, crate::SessionAdmission::Immediate)
                    {
                        return Err(error);
                    }
                }
                Err(error) => return Err(error),
            }
            drop(readers.acquire_in_context(session, || grant(PossessionAttempt::Admitted))?);
        }
    }

    /// An already initialized owner is not a partial candidate. It remains in
    /// the ledger while a separate login recipe waits outside all guards.
    /// Unlike new-operation admission, this path must not convert WaitUntil
    /// into Busy merely because the parent operation exists.
    pub(crate) fn prepare_retained<'s>(
        &mut self,
        session: &'s Session,
        ticket: u64,
        progress: &crate::session::AdmissionProgress,
        budget: &std::sync::Arc<crate::symmetric::memory::Budget>,
        mut validate: impl FnMut(
            &crate::session::SessionAccess<'s>,
            usize,
        ) -> Result<crate::advanced::progress::Stamp>,
    ) -> Result<(
        Option<ContextLoginStorage>,
        crate::session::SessionAccess<'s>,
    )> {
        use crate::symmetric::memory::ControlledReservation;
        use std::sync::atomic::Ordering;
        let access = session.context_authentication_access_progress(progress)?;
        validate(&access, 0)?;
        drop(access);
        let policy = crate::admission_wait::current();
        let session_policy = session.admission();
        let authentication = self.authentication;
        loop {
            let ((revision, storage), residual) = self.prepare(session, 0, |bytes| {
                let intrinsic = bytes
                    .checked_add(crate::session::lifecycle_diagnostics::Store::allocation_bytes())
                    .ok_or(Error::Rejected(crate::RejectionReason::MemoryAccounting(
                        crate::MemoryAccountingRejection::RetainedSourceCreditOverflow,
                    )))?;
                loop {
                    let revision = {
                        let access = session.context_authentication_access_progress(progress)?;
                        validate(&access, intrinsic)?
                    };

                    // A concurrent resize changes the retained footprint. Replan
                    // outside Wake and all possession guards before waiting again.
                    let reserved = budget.reserve_controlled_retaining::<()>(
                        bytes,
                        crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
                        &policy,
                        || {
                            // Pure observations only: Budget holds its Wake here.
                            crate::session::activity::context(session)?;
                            session
                                .snapshot
                                .observe_authentication_unchanged(authentication)?;
                            if session.entry.advanced_operation.load(Ordering::Acquire) != ticket {
                                return Err(Error::Rejected(
                                    crate::RejectionReason::OperationOwnership(
                                        crate::OperationOwnershipRejection::StaleOperationTicket,
                                    ),
                                ));
                            }
                            Ok(session
                                .entry
                                .advanced_progress
                                .changed(revision)
                                .then_some(()))
                        },
                        || Ok(None),
                    )?;
                    match reserved {
                        ControlledReservation::Acquired(credit) => return Ok((revision, credit)),
                        ControlledReservation::Redirect(()) => continue,
                    }
                }
            })?;
            drop(residual);
            let attempt = policy.try_once(|| {
                session_policy.try_once(|| {
                    crate::with_resource_admission(crate::ResourceAdmission::Immediate, || {
                        let access = session.context_authentication_access_with_policy(
                            progress,
                            &crate::SessionAdmission::Immediate,
                        )?;
                        validate(&access, 0)?;
                        if session.entry.advanced_progress.changed(revision) {
                            return Ok(None);
                        }
                        Ok(Some(access))
                    })
                })
            });
            match attempt {
                Ok(Some(access)) => return Ok((storage, access)),
                Ok(None) => {
                    drop(storage);
                    continue;
                }
                Err(error @ Error::Busy(_)) => {
                    drop(storage);
                    if matches!(policy, crate::ResourceAdmission::Immediate)
                        && matches!(session_policy, crate::SessionAdmission::Immediate)
                    {
                        return Err(error);
                    }
                }
                Err(error) => return Err(error),
            }
            let access = session.context_authentication_access_progress(progress)?;
            validate(&access, 0)?;
            drop(access);
        }
    }
}
