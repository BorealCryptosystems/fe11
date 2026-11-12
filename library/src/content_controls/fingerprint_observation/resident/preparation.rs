// SPDX-License-Identifier: Apache-2.0
//! Metadata and value candidates for a completed fingerprint stage.
use super::*;
use crate::{
    attributes::{
        owned::resident::ValueCandidate,
        owned::resident::{self as public, ReadStorage},
    },
    symmetric::memory::ControlledReservation,
};

pub(crate) enum Candidate {
    Metadata(ReadStorage, Option<ProtectedFingerprintHash>, Credit),
    PublicValue(ValueCandidate),
    ProtectedCall(Credit),
    SecretValue(SecretBytes),
}
pub(crate) fn prepare(
    need: Need,
    read: AttributeReadPlan,
    budget: &std::sync::Arc<crate::symmetric::memory::Budget>,
    policy: &crate::ResourceAdmission,
    mut check: impl FnMut() -> Result<()>,
) -> Result<Candidate> {
    match need {
        Need::PublicValue(need) => {
            public::prepare_value(need, budget, policy, check).map(Candidate::PublicValue)
        }
        Need::SecretValue { length } => {
            crate::content_controls::owned::resident::prepare_value(length, budget, policy, check)
                .map(Candidate::SecretValue)
        }
        Need::ProtectedCall { .. } => {
            let credit = match budget.reserve_controlled_retaining(
                ContentOwner::fixed_bytes(),
                crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
                policy,
                || {
                    check()?;
                    Ok(None::<()>)
                },
                || Ok(None),
            )? {
                ControlledReservation::Acquired(credit) => credit,
                ControlledReservation::Redirect(()) => unreachable!("no redirect requested"),
            };
            Ok(Candidate::ProtectedCall(credit))
        }
        Need::Metadata { .. } => {
            let recipe = need.recipe(read.clarification)?;
            recipe.validate()?;
            let with_digest = matches!(
                need,
                Need::Metadata {
                    phase: Metadata::Material(_),
                    ..
                }
            );
            let mut required = ReadStorage::requested(recipe)?
                .checked_add(if with_digest {
                    ProtectedFingerprintHash::requested_bytes()
                } else {
                    0
                })
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectContent(
                    crate::ObjectContentRejection::FingerprintPreparationAccounting,
                )))?;
            loop {
                let mut credit = match budget.reserve_controlled_retaining(
                    required,
                    crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
                    policy,
                    || {
                        check()?;
                        Ok(None::<()>)
                    },
                    || Ok(None),
                )? {
                    ControlledReservation::Acquired(credit) => credit,
                    ControlledReservation::Redirect(()) => unreachable!("no redirect requested"),
                };
                let storage = ReadStorage::allocate(recipe)?;
                let digest = with_digest
                    .then(ProtectedFingerprintHash::new)
                    .transpose()?;
                let actual = storage
                    .allocated_bytes()?
                    .checked_add(
                        digest
                            .as_ref()
                            .map(ProtectedFingerprintHash::allocated_bytes)
                            .transpose()?
                            .unwrap_or(0),
                    )
                    .ok_or(Error::Rejected(crate::RejectionReason::ObjectContent(
                        crate::ObjectContentRejection::FingerprintPreparationAccounting,
                    )))?;
                if actual > required {
                    drop(digest);
                    drop(storage);
                    drop(credit);
                    required = actual;
                    continue;
                }
                credit.release(required - actual);
                let digest = digest.map(|digest| digest.bind(&mut credit)).transpose()?;
                return Ok(Candidate::Metadata(storage, digest, credit));
            }
        }
    }
}
