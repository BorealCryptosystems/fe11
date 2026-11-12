// SPDX-License-Identifier: Apache-2.0
//! Borrowed creation queries and their complete unpublished storage.
use super::{report_storage, CreationDestinations, Slot};
use crate::crypto::KeyGenerationDescription;
use crate::{
    destination_controls::{DestinationIdentity, DestinationQuery, PreparedDestination},
    symmetric::memory::Credit,
    DestinationSearchPlan, DestinationUserObservation, Error, ManagedClass, ObjectAdmission,
    Result, Session,
};
use fe11_sys::CK_ATTRIBUTE;
use std::mem::size_of;

pub(in crate::advanced::admission) struct Plan<'a> {
    id: &'a [u8],
    label: &'a [u8],
    selections: [Option<(ManagedClass, &'a ObjectAdmission)>; 2],
    count: usize,
    requested: usize,
    maximum_batch: usize,
}
pub(in crate::advanced::admission) struct Storage {
    slots: Vec<Slot>,
    maximum_batch: usize,
}
fn sum(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b)
        .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
            crate::KeyAdmissionRejection::DestinationOwnerSize,
        )))
}
impl<'a> Plan<'a> {
    pub(in crate::advanced::admission) fn new(
        policy: &'a impl KeyGenerationDescription,
    ) -> Result<Self> {
        let identity = policy.generation_identity()?;
        let id = identity.id;
        let label = identity.label.as_bytes();
        let selections = if policy.is_pair() {
            [
                Some((ManagedClass::PublicKey, policy.object_observation(false))),
                Some((ManagedClass::PrivateKey, policy.object_observation(true))),
            ]
        } else {
            [
                Some((policy.admission_class(), policy.object_observation(false))),
                None,
            ]
        };
        let count = selections.iter().flatten().count();
        let mut requested = sum(
            size_of::<CreationDestinations>(),
            count.checked_mul(size_of::<Slot>()).ok_or(Error::Rejected(
                crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::DestinationOwnerSize,
                ),
            ))?,
        )?;
        let mut maximum_batch = 0;
        for &(class, admission) in selections.iter().flatten() {
            let query = DestinationIdentity::KeyOrCertificate { class, id, label }
                .query_allocation_bytes(&admission.destination)?;
            requested = sum(
                sum(requested, query)?,
                report_storage(admission.destination.retained_bytes()?)?,
            )?;
            if query != 0 {
                if let DestinationSearchPlan::Observe { resources, .. } =
                    &admission.destination.search
                {
                    maximum_batch = maximum_batch.max(resources.batch_size.get());
                }
            }
        }
        Ok(Self {
            id,
            label,
            selections,
            count,
            requested,
            maximum_batch,
        })
    }
    pub(in crate::advanced::admission) fn requested_bytes(&self) -> usize {
        self.requested
    }
    pub(in crate::advanced::admission) fn maximum_batch(&self) -> usize {
        self.maximum_batch
    }
    pub(in crate::advanced::admission) fn allocate(&self, session: &Session) -> Result<Storage> {
        let mut slots = Vec::new();
        slots.try_reserve_exact(self.count).map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::DestinationOwnerAllocation,
            ))
        })?;
        for &(class, admission) in self.selections.iter().flatten() {
            let (evaluation, query) = PreparedDestination::new(
                admission.destination.clone(),
                || session.snapshot.recorded_user(),
                (!matches!(
                    &admission.destination.search,
                    DestinationSearchPlan::NotRequested
                ) || !matches!(
                    &admission.destination.user,
                    DestinationUserObservation::NotRequested
                ))
                .then(|| session.snapshot.authentication_stamp()),
                DestinationIdentity::KeyOrCertificate {
                    class,
                    id: self.id,
                    label: self.label,
                },
            )?;
            slots.push(match query {
                DestinationQuery::Ready(count) => Slot::Observed(evaluation.finish(count)?),
                DestinationQuery::Enumerate {
                    template,
                    resources,
                    ..
                } => {
                    let mut template = Box::new(template);
                    let attrs = template.descriptors()?;
                    Slot::Prepared {
                        evaluation,
                        template,
                        attrs,
                        resources,
                    }
                }
            });
        }
        Ok(Storage {
            slots,
            maximum_batch: self.maximum_batch,
        })
    }
}
impl Storage {
    pub(in crate::advanced::admission) fn allocated_bytes(&self) -> Result<usize> {
        let mut actual = sum(
            size_of::<CreationDestinations>(),
            self.slots
                .capacity()
                .checked_mul(size_of::<Slot>())
                .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::DestinationOwnerSize,
                )))?,
        )?;
        for slot in &self.slots {
            let (selection, query) = match slot {
                Slot::Observed(report) => (report.selection().retained_bytes()?, 0),
                Slot::Prepared {
                    evaluation,
                    template,
                    attrs,
                    ..
                } => {
                    let query = sum(
                        template.retained_bytes()?,
                        attrs
                            .capacity()
                            .checked_mul(size_of::<CK_ATTRIBUTE>())
                            .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                                crate::KeyAdmissionRejection::DestinationOwnerSize,
                            )))?,
                    )?;
                    (evaluation.retained_selection_bytes()?, query)
                }
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::DestinationPreparationState,
                    )))
                }
            };
            actual = sum(sum(actual, report_storage(selection)?)?, query)?;
        }
        Ok(actual)
    }
    pub(in crate::advanced::admission) fn bind(
        self,
        prepaid: &mut Credit,
    ) -> Result<CreationDestinations> {
        let credit = prepaid.split(self.allocated_bytes()?)?;
        Ok(CreationDestinations {
            slots: self.slots,
            current: 0,
            maximum_batch: self.maximum_batch,
            _credit: credit,
        })
    }
}
