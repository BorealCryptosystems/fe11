// SPDX-License-Identifier: Apache-2.0
//! The initial search/read graph is materialized before session possession.
use super::{read::PlansStorage, ReadPlans, Selector};
use crate::crypto::KeyAdmissionDescription;
use crate::{
    attributes::{KeySelectorStorage, Template},
    managed::search::SearchCollection,
    symmetric::memory::{Budget, Credit},
    Error, Result,
};
use fe11_sys::{
    CKO_PRIVATE_KEY, CK_ASYNC_DATA, CK_INVALID_HANDLE, CK_OBJECT_HANDLE, CK_ULONG,
    CK_UNAVAILABLE_INFORMATION,
};
use std::mem::size_of;

pub(super) struct InitialResources {
    pub handles: Vec<CK_OBJECT_HANDLE>,
    pub found: Vec<CK_OBJECT_HANDLE>,
    pub primary: Option<Selector>,
    pub empty_template: Option<Box<Template>>,
    pub count: Box<CK_ULONG>,
    pub completion: Box<CK_ASYNC_DATA>,
    pub search_diagnostic: crate::error::CleanupDiagnostic,
    pub return_diagnostic: crate::error::CompletionStorage,
    pub retirement_diagnostic: Option<crate::error::CleanupDiagnostic>,
    pub resource_diagnostics: crate::advanced::progress::FailureDiagnostics,
    pub pending_diagnostic: Option<crate::error::PreparedCompletionStorage>,
    pub private: Option<Selector>,
    pub read_plans: ReadPlans,
    pub collection: SearchCollection,
    pub metadata: Credit,
}
pub(super) struct Storage {
    handles: Vec<CK_OBJECT_HANDLE>,
    found: Vec<CK_OBJECT_HANDLE>,
    selectors: [Option<KeySelectorStorage>; 2],
    empty_template: Option<Box<Template>>,
    count: Box<CK_ULONG>,
    completion: Box<CK_ASYNC_DATA>,
    search_diagnostic: crate::error::CleanupDiagnostic,
    return_diagnostic: crate::error::CompletionStorage,
    retirement_diagnostic: Option<crate::error::CleanupDiagnostic>,
    plans: PlansStorage,
}
fn reserve<T>(count: usize) -> Result<Vec<T>> {
    let mut values = Vec::new();
    values.try_reserve_exact(count).map_err(|_| {
        Error::Rejected(crate::RejectionReason::KeyAdmission(
            crate::KeyAdmissionRejection::AdmissionMetadataAllocation,
        ))
    })?;
    Ok(values)
}
fn handle_bytes(count: usize) -> Result<usize> {
    count
        .checked_mul(size_of::<CK_OBJECT_HANDLE>())
        .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
            crate::KeyAdmissionRejection::AdmissionMetadataByteCount,
        )))
}
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b)
        .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
            crate::KeyAdmissionRejection::AdmissionMetadataByteCount,
        )))
}
pub(super) struct Plan<'a> {
    policy: &'a dyn KeyAdmissionDescription,
    generation: bool,
    batch: usize,
    fixed: usize,
    selectors: usize,
    requested: usize,
}
impl<'a> Plan<'a> {
    pub(super) fn new(
        policy: &'a dyn KeyAdmissionDescription,
        generation: bool,
        batch: usize,
        fixed: usize,
    ) -> Result<Self> {
        crate::bounds::ck_length(batch)?;
        let selectors = if generation {
            0usize
        } else if policy.is_pair() {
            2
        } else {
            1
        };
        let selector_bytes = if selectors == 0 {
            0
        } else {
            KeySelectorStorage::requested_bytes(policy.admission_id().len())?
                .checked_mul(selectors)
                .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::AdmissionMetadataByteCount,
                )))?
        };
        // `fixed` already includes the two selected-handle slots, independently
        // of the caller-selected native search batch and observation vectors.
        let known = add(
            add(
                add(
                    add(fixed, handle_bytes(batch)?)?,
                    Budget::observation_bytes(),
                )?,
                selector_bytes,
            )?,
            ReadPlans::requested_bytes(policy)?,
        )?;
        Ok(Self {
            policy,
            generation,
            batch,
            fixed,
            selectors,
            requested: known,
        })
    }
    pub(super) fn requested_bytes(&self) -> usize {
        self.requested
    }
    pub(super) fn allocate(&self) -> Result<Storage> {
        Ok(Storage {
            handles: reserve(self.batch)?,
            found: reserve(2)?,
            selectors: [
                if self.selectors > 0 {
                    Some(KeySelectorStorage::allocate(
                        self.policy.admission_id().len(),
                    )?)
                } else {
                    None
                },
                if self.selectors > 1 {
                    Some(KeySelectorStorage::allocate(
                        self.policy.admission_id().len(),
                    )?)
                } else {
                    None
                },
            ],
            plans: PlansStorage::allocate(self.policy)?,
            empty_template: (self.selectors == 0)
                .then(|| crate::allocation::boxed(Template::new()))
                .transpose()?,
            count: crate::allocation::boxed(CK_UNAVAILABLE_INFORMATION)?,
            completion: crate::allocation::boxed(crate::native::output::async_data())?,
            search_diagnostic: crate::error::CleanupDiagnostic::prepare_sequence()?,
            return_diagnostic: crate::error::CompletionStorage::allocate()?,
            retirement_diagnostic: self
                .generation
                .then(crate::error::CleanupDiagnostic::prepare_sequence)
                .transpose()?,
        })
    }
    pub(super) fn allocated_bytes(&self, storage: &Storage) -> Result<usize> {
        storage.allocated_bytes(self.fixed)
    }
    pub(super) fn bind(
        &self,
        storage: Storage,
        prepaid: &mut Credit,
        resource_diagnostics: crate::advanced::progress::FailureDiagnostics,
        pending_diagnostic: Option<crate::error::PreparedCompletionStorage>,
    ) -> Result<InitialResources> {
        storage.bind(
            self.policy,
            self.generation,
            self.fixed,
            prepaid,
            resource_diagnostics,
            pending_diagnostic,
        )
    }
}

impl Storage {
    fn allocated_bytes(&self, fixed: usize) -> Result<usize> {
        let fixed = fixed.checked_sub(handle_bytes(2)?).ok_or(Error::Rejected(
            crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AdmissionMetadataByteCount,
            ),
        ))?;
        let mut actual = add(
            add(
                add(fixed, handle_bytes(self.handles.capacity())?)?,
                handle_bytes(self.found.capacity())?,
            )?,
            Budget::observation_bytes(),
        )?;
        for selector in self.selectors.iter().flatten() {
            actual = add(actual, selector.allocated_bytes()?)?;
        }
        add(actual, self.plans.allocated_bytes()?)
    }
    fn bind(
        mut self,
        policy: &dyn KeyAdmissionDescription,
        generation: bool,
        fixed: usize,
        credit: &mut Credit,
        resource_diagnostics: crate::advanced::progress::FailureDiagnostics,
        pending_diagnostic: Option<crate::error::PreparedCompletionStorage>,
    ) -> Result<InitialResources> {
        let metadata_bytes = add(
            add(
                fixed.checked_sub(handle_bytes(2)?).ok_or(Error::Rejected(
                    crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::AdmissionMetadataByteCount,
                    ),
                ))?,
                handle_bytes(self.found.capacity())?,
            )?,
            handle_bytes(self.handles.capacity())?,
        )?;
        let primary = self.selectors[0]
            .take()
            .map(|storage| {
                Selector::bind(
                    storage,
                    policy.admission_class().raw(),
                    policy.admission_id(),
                    credit,
                )
            })
            .transpose()?;
        let private = self.selectors[1]
            .take()
            .map(|storage| Selector::bind(storage, CKO_PRIVATE_KEY, policy.admission_id(), credit))
            .transpose()?;
        let read_plans = self.plans.bind(credit)?;
        let plan = policy.object_observation(false).search;
        let collection = SearchCollection::from_prepaid(plan, credit)?;
        if !generation {
            self.handles
                .resize(plan.batch_size.get(), CK_INVALID_HANDLE);
        }
        // The initial aggregate already detached the poll envelope's global
        // credit before establishing the operation's private account.
        let metadata_bytes = metadata_bytes
            .checked_sub(crate::advanced::progress::FailureDiagnostics::allocation_bytes())
            .and_then(|bytes| {
                bytes.checked_sub(
                    usize::from(pending_diagnostic.is_some())
                        * crate::error::PreparedCompletionStorage::allocation_bytes(),
                )
            })
            .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AdmissionDiagnosticByteCount,
            )))?;
        let metadata = credit.split(metadata_bytes)?;
        Ok(InitialResources {
            handles: self.handles,
            found: self.found,
            primary,
            empty_template: self.empty_template,
            count: self.count,
            completion: self.completion,
            search_diagnostic: self.search_diagnostic,
            return_diagnostic: self.return_diagnostic,
            retirement_diagnostic: self.retirement_diagnostic,
            resource_diagnostics,
            pending_diagnostic,
            private,
            read_plans,
            collection,
            metadata,
        })
    }
}
