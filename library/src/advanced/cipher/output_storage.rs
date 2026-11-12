// SPDX-License-Identifier: Apache-2.0
//! Retained output allocation and the next native offer have different widths.
use super::CipherOutputPlan;
use crate::{bounds, Error, Result};

#[derive(Clone, Copy)]
pub(super) enum OutputStorage {
    Initial(CipherOutputPlan),
    Retained {
        capacity: usize,
        offered: Option<usize>,
    },
}

impl OutputStorage {
    pub(super) fn plan(self) -> CipherOutputPlan {
        match self {
            Self::Initial(plan) => plan,
            Self::Retained { capacity, .. } => CipherOutputPlan::Buffer { capacity },
        }
    }

    pub(super) fn validate(self, capacity: usize) -> Result<()> {
        let offered = match self {
            Self::Initial(_) => Some(capacity),
            Self::Retained { offered, .. } => offered,
        };
        if let Some(offered) = offered {
            if offered > capacity {
                return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherRecordOutputBounds,
                )));
            }
            bounds::ck_length(offered)?;
        }
        Ok(())
    }
}
