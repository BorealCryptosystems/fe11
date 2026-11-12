// SPDX-License-Identifier: Apache-2.0
//! Known-resource destruction prepays its aliases before taking possession.
use super::{RevocationShape, RevocationTargets};
use crate::{
    managed::{mutations::DestinationRetirement, DestinationRecipe, Reservation},
    session::{activity::AccessMode, AdmissionProgress, SessionAccess},
    Error, NativeObjectRef, Result, Session,
};
use std::sync::Arc;

/// Retained by the public destruction call, separately from any resident
/// observation. Removing that observation must not release a returned error's
/// storage while the root is still finishing its search/cleanup protocol.
pub(crate) struct DestructionDiagnostic {
    completion: Option<crate::error::CompletionStorage>,
    _credit: crate::symmetric::memory::Credit,
}
impl DestructionDiagnostic {
    pub(crate) fn allocation_bytes() -> usize {
        crate::error::CompletionStorage::allocation_bytes()
    }

    pub(crate) fn prepare(prepaid: &mut crate::symmetric::memory::Credit) -> Result<Self> {
        let credit = prepaid.split(Self::allocation_bytes())?;
        Ok(Self {
            completion: Some(crate::error::CompletionStorage::allocate()?),
            _credit: credit,
        })
    }

    pub(crate) fn take(&mut self) -> Result<crate::error::CompletionDiagnostic> {
        self.completion
            .take()
            .map(|storage| storage.bind("C_DestroyObject"))
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::DestructionDiagnosticAlreadyConsumed,
            )))
    }
}

pub(crate) fn prepare_destruction<'s>(
    session: &'s Session,
    recipes: &[DestinationRecipe<'_>],
    object: &NativeObjectRef,
    progress: &AdmissionProgress,
    authentication: u64,
    mut check: impl FnMut(&SessionAccess<'s>) -> Result<()>,
) -> Result<(
    DestructionDiagnostic,
    RevocationTargets,
    Arc<Reservation>,
    SessionAccess<'s>,
)> {
    let mut required = 0usize;
    loop {
        let retirement = DestinationRetirement::new(session);
        retirement.retire();
        let (((diagnostic, mut prepared), reservation), access) =
            Reservation::prepare_mutation_prepaid(
                session,
                recipes,
                0,
                None,
                [(Some(object), AccessMode::Write)],
                false,
                authentication,
                progress,
                |overhead, current| loop {
                    session
                        .snapshot
                        .check_authentication_unchanged(authentication)?;
                    let shape = RevocationShape::discover(
                        session,
                        object.identity.resource(),
                        authentication,
                    )?;
                    required = required.max(shape.allocation_bytes()?);
                    let admitted = required
                        .checked_add(overhead)
                        .and_then(|n| n.checked_add(DestructionDiagnostic::allocation_bytes()))
                        .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                            crate::ObjectReferencesRejection::DestructionPreparationAccounting,
                        )))?;
                    let Some(mut credit) = crate::advanced::reserve_preparation_while(
                        session,
                        admitted,
                        progress,
                        || {
                            crate::session::recovery::observations::context(
                                session,
                                Some(authentication),
                                authentication,
                            )?;
                            current()
                        },
                    )?
                    else {
                        return Ok(None);
                    };
                    let storage = shape.allocate()?;
                    let actual = storage.allocated_bytes()?;
                    if actual > required {
                        drop(storage);
                        drop(credit);
                        required = actual;
                        continue;
                    }
                    credit.release(required - actual);
                    let diagnostic = DestructionDiagnostic::prepare(&mut credit)?;
                    return Ok(Some(((diagnostic, storage.bind(&mut credit)?), credit)));
                },
                |access| {
                    session
                        .snapshot
                        .check_authentication_unchanged(authentication)?;
                    check(access)
                },
            )?;
        match prepared.bind(&access)? {
            Some(targets) => return Ok((diagnostic, targets, reservation, access)),
            None => {
                // No observation or Destroy has occurred; replan without guards
                // or private snapshot credit after concurrent registry growth.
                drop(access);
                drop(reservation);
            }
        }
    }
}
