// SPDX-License-Identifier: Apache-2.0
//! Exact native CKA_ALLOWED_MECHANISMS observations, without local permission checks.
use crate::{attributes, Error, Observation, Result};

use fe11_sys::{CKA_ALLOWED_MECHANISMS, CK_OBJECT_HANDLE};
pub(crate) mod resident;

/// Explicitly read the native attribute without imposing a local permission rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MechanismObservationPlan {
    /// Make no native attribute call.
    NotRequested,
    /// Read the attribute with this explicit byte budget.
    Read {
        /// Maximum native encoded bytes, including an empty list.
        maximum_bytes: usize,
    },
}

/// Native evidence captured by an explicit observation plan.
/// This report does not determine whether a mechanism may be used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MechanismObservationReport {
    selection: MechanismObservationPlan,
    observation: attributes::owned::resident::MechanismValues,
}
impl MechanismObservationReport {
    /// Exact read choice and resource budget.
    pub fn selection(&self) -> &MechanismObservationPlan {
        &self.selection
    }
    /// Native values in their returned order, including unknown states.
    pub fn observation(&self) -> &Observation<Vec<u64>> {
        self.observation.observation()
    }
}
impl MechanismObservationPlan {
    pub(crate) fn record(
        self,
        observation: Observation<Vec<u64>>,
    ) -> Result<MechanismObservationReport> {
        self.record_owned(
            attributes::owned::resident::MechanismValues::from_observation(observation),
        )
    }
    pub(crate) fn record_owned(
        self,
        observation: attributes::owned::resident::MechanismValues,
    ) -> Result<MechanismObservationReport> {
        if let Observation::NativeError {
            function,
            code,
            may_have_effect,
        } = observation.observation()
        {
            return Err(Error::Native {
                function: *function,
                code: *code,
                may_have_effect: *may_have_effect,
            });
        }
        Ok(MechanismObservationReport {
            selection: self,
            observation,
        })
    }
}
