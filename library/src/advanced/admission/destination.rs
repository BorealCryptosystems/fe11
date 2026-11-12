// SPDX-License-Identifier: Apache-2.0
//! Creation-only destination queries, prepared before the first native call.
use super::FindFrame;
use crate::{
    attributes::Template, destination_controls::PreparedDestination, managed,
    symmetric::memory::Credit, Error, Result,
};
use fe11_sys::{CK_ATTRIBUTE, CK_INVALID_HANDLE};
pub(super) mod preparation;

enum Slot {
    Prepared {
        evaluation: PreparedDestination,
        template: Box<Template>,
        attrs: Vec<CK_ATTRIBUTE>,
        resources: crate::SearchPlan,
    },
    Searching(PreparedDestination),
    Observed(crate::DestinationReport),
    Transferred,
}

pub(super) struct CreationDestinations {
    slots: Vec<Slot>,
    current: usize,
    maximum_batch: usize,
    // Storage precedes its credit, including on preparation failure/unwind.
    _credit: Credit,
}
// SAFETY: descriptors point only into boxed templates owned by a slot or the
// admission FindFrame. A slot transfers these allocations before dispatch and
// never edits them while native work is pending.
unsafe impl Send for CreationDestinations {}

impl CreationDestinations {
    pub(super) fn maximum_batch(&self) -> usize {
        self.maximum_batch
    }

    // All allocations and descriptor creation happened in new. Switching from
    // public to private never introduces a local allocation after Final.
    pub(super) fn activate(
        &mut self,
        frame: &mut FindFrame,
        collection: &mut managed::search::SearchCollection,
    ) -> Result<bool> {
        while self.current < self.slots.len() {
            match &self.slots[self.current] {
                Slot::Observed(_) => {
                    self.current += 1;
                    continue;
                }
                Slot::Prepared { .. } => {}
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::DestinationTransition,
                    )))
                }
            }
            let slot = std::mem::replace(&mut self.slots[self.current], Slot::Transferred);
            let Slot::Prepared {
                evaluation,
                template,
                attrs,
                resources,
            } = slot
            else {
                unreachable!()
            };
            frame._template = template;
            frame.attrs = attrs;
            frame
                .handles
                .resize(resources.batch_size.get(), CK_INVALID_HANDLE);
            collection.reset(resources);
            self.slots[self.current] = Slot::Searching(evaluation);
            return Ok(true);
        }
        Ok(false)
    }

    pub(super) fn finish(&mut self, count: usize) -> Result<()> {
        let count = u64::try_from(count).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectDestination(
                crate::ObjectDestinationRejection::DestinationCardinalityWidth,
            ))
        })?;
        let slot = self.slots.get_mut(self.current).ok_or(Error::Rejected(
            crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::DestinationOwnerAbsent,
            ),
        ))?;
        let Slot::Searching(evaluation) = std::mem::replace(slot, Slot::Transferred) else {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::DestinationTransition,
            )));
        };
        *slot = Slot::Observed(evaluation.finish(crate::Observation::Observed(count))?);
        self.current += 1;
        Ok(())
    }

    pub(super) fn take(&mut self, index: usize) -> Result<crate::DestinationReport> {
        let slot = self.slots.get_mut(index).ok_or(Error::Rejected(
            crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::DestinationReportAbsent,
            ),
        ))?;
        let Slot::Observed(report) = slot else {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::DestinationReportIncomplete,
            )));
        };
        let credit = self
            ._credit
            .split(report_storage(report.selection().retained_bytes()?)?)?;
        match std::mem::replace(slot, Slot::Transferred) {
            Slot::Observed(report) => Ok(report.with_prepaid(credit)),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::DestinationReportIncomplete,
            ))),
        }
    }
}

fn report_storage(retained: usize) -> Result<usize> {
    retained
        .checked_sub(std::mem::size_of::<crate::DestinationPlan>())
        .and_then(|n| n.checked_add(std::mem::size_of::<crate::DestinationReport>()))
        .ok_or(Error::Rejected(
            crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::DestinationSelectionSize,
            ),
        ))
}
