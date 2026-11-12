// SPDX-License-Identifier: Apache-2.0
//! Report growth without moving the stable native observation frame.
use super::{Capture, ValidationObservation, ValidationReport};
use crate::symmetric::memory::Credit;
use crate::{Error, Result};
use std::mem::size_of;

/// Unbound metadata prepared with the other resources of one input transition.
pub(in crate::advanced) struct ReportStorage {
    observations: Vec<ValidationObservation>,
    maximum: usize,
}

pub(in crate::advanced) struct PreparedReport {
    pub(super) report: ValidationReport,
    pub(super) maximum: usize,
}

impl ReportStorage {
    pub(in crate::advanced) fn allocation_bytes(maximum: usize) -> Result<usize> {
        if maximum == 0 {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::EmptyValidationReport,
            )));
        }
        maximum
            .checked_mul(size_of::<ValidationObservation>())
            .and_then(|bytes| bytes.checked_add(size_of::<ValidationReport>()))
            .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::ValidationReportLength,
            )))
    }

    pub(in crate::advanced) fn allocate(maximum: usize) -> Result<Self> {
        Self::allocation_bytes(maximum)?;
        let mut observations = Vec::new();
        observations.try_reserve_exact(maximum).map_err(|_| {
            Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ValidationReportAllocation,
            ))
        })?;
        Ok(Self {
            observations,
            maximum,
        })
    }

    fn growth_capacity(maximum: usize) -> Result<usize> {
        Self::allocation_bytes(maximum)?;
        Ok(maximum.checked_next_power_of_two().unwrap_or(maximum))
    }

    pub(in crate::advanced) fn growth_allocation_bytes(maximum: usize) -> Result<usize> {
        Self::allocation_bytes(Self::growth_capacity(maximum)?)
    }

    /// Reserve spare capacity only when an existing stream report must grow.
    /// Its logical maximum still follows actual messages, not future guesses.
    /// Initial batch allocations continue to use allocate(maximum) unchanged.
    pub(in crate::advanced) fn allocate_growth(maximum: usize) -> Result<Self> {
        let mut storage = Self::allocate(Self::growth_capacity(maximum)?)?;
        storage.maximum = maximum;
        Ok(storage)
    }

    pub(in crate::advanced) fn allocated_bytes(&self) -> Result<usize> {
        self.observations
            .capacity()
            .checked_mul(size_of::<ValidationObservation>())
            .and_then(|bytes| bytes.checked_add(size_of::<ValidationReport>()))
            .ok_or(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ValidationReportCapacityAccounting,
            )))
    }

    pub(in crate::advanced) fn bind(self, prepaid: &mut Credit) -> Result<PreparedReport> {
        let credit = prepaid.split(self.allocated_bytes()?)?;
        Ok(PreparedReport {
            report: ValidationReport {
                observations: self.observations,
                _credit: credit,
            },
            maximum: self.maximum,
        })
    }
}

impl Capture {
    /// Additional report storage for actual messages, not a future stream limit.
    /// The caller admits this together with the corresponding message storage.
    pub(in crate::advanced) fn report_growth_bytes(&self, maximum: usize) -> Result<usize> {
        let previous = self.snapshot_capacity()?;
        if maximum < previous {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ValidationReportCapacityDecreased,
            )));
        }
        let report = self.report.as_ref().expect("checked available report");
        if maximum <= report.observations.capacity() {
            Ok(0)
        } else {
            ReportStorage::growth_allocation_bytes(maximum)
        }
    }

    /// Validate by reference so a rejected candidate can be dropped after guards.
    pub(in crate::advanced) fn check_report_growth(
        &self,
        maximum: usize,
        prepared: Option<&PreparedReport>,
    ) -> Result<()> {
        let required = self.report_growth_bytes(maximum)?;
        if let Some(prepared) = prepared {
            if prepared.maximum != maximum
                || !prepared.report.observations.is_empty()
                || prepared.report.observations.capacity() < maximum
            {
                return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                    crate::OperationOwnershipRejection::ValidationReportGrowthShapeChanged,
                )));
            }
        } else if required != 0 {
            return Err(Error::Rejected(crate::RejectionReason::OperationOwnership(
                crate::OperationOwnershipRejection::ValidationReportGrowthAbsent,
            )));
        }
        Ok(())
    }

    /// Commit prepared metadata under the operation's possession. No allocation
    /// or native call occurs here; the returned old owner is dropped after guards.
    /// The native frame stays in Capture at its original address throughout.
    pub(in crate::advanced) fn attach_report_growth(
        &mut self,
        maximum: usize,
        prepared: Option<PreparedReport>,
    ) -> Result<Option<ValidationReport>> {
        self.check_report_growth(maximum, prepared.as_ref())?;
        let target = self.report.as_mut().expect("checked available report");
        let old = if let Some(mut prepared) = prepared {
            // Observations are small copied scalar records. Input/output buffers
            // and pending native storage are not part of this vector.
            prepared
                .report
                .observations
                .extend_from_slice(&target.observations);
            Some(std::mem::replace(target, prepared.report))
        } else {
            None
        };
        self.maximum = maximum;
        Ok(old)
    }
}
