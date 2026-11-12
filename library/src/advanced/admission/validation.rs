// SPDX-License-Identifier: Apache-2.0
//! Check required native functions and the admissibility of admission transitions.
//! History observation and detachment keep their own preconditions.

use super::*;

pub(super) fn require_observation_functions(s: &State) -> Result<()> {
    let t = &s.native.table;
    if t.C_GetAttributeValue.is_none() {
        return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
            crate::KeyAdmissionRejection::AdmissionFunctionsUnavailable,
        )));
    }
    Ok(())
}

pub(super) fn check_initial_functions(
    state: &State,
    policy: &impl crate::crypto::KeyAdmissionDescription,
    generate: bool,
) -> Result<()> {
    require_observation_functions(state)?;
    if generate {
        let available = if policy.is_pair() {
            state.native.table.C_GenerateKeyPair.is_some()
        } else {
            state.native.table.C_GenerateKey.is_some()
        };
        if !available {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::GenerationFunctionsUnavailable,
            )));
        }
        Session::key_admission_search(state, policy.generation_search_required()?)?;
    } else if state.native.table.C_FindObjectsInit.is_none()
        || state.native.table.C_FindObjects.is_none()
        || state.native.table.C_FindObjectsFinal.is_none()
    {
        return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
            crate::KeyAdmissionRejection::AdmissionSearchFunctionsUnavailable,
        )));
    }
    Ok(())
}

impl Admission {
    pub(super) fn check_search_functions(&self, s: &State) -> Result<()> {
        let requires_search = self
            .destinations
            .as_ref()
            .map_or(true, |d| d.maximum_batch() != 0);
        if requires_search
            && (s.native.table.C_FindObjectsInit.is_none()
                || s.native.table.C_FindObjects.is_none()
                || s.native.table.C_FindObjectsFinal.is_none())
        {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AdmissionSearchFunctionsUnavailable,
            )));
        }
        Ok(())
    }

    pub(super) fn retain_history_observation(
        &mut self,
        snapshot: crate::BaseProtection,
    ) -> Result<()> {
        match self.frames.policy_mut() {
            KeyPolicy::Symmetric { .. } => self.history_observations = Some(snapshot),
            KeyPolicy::DerivationBase(p) => p.observe_history(snapshot)?,
            KeyPolicy::Pair(pair) if pair.private => pair.prepared.observe_history(snapshot)?,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::HistoryObservationOwnerAbsent,
                )))
            }
        }
        self.start_mechanism_observation()
    }

    pub(in crate::advanced) fn check_detachment(&self) -> Result<()> {
        self.stage.check_detachment()
    }
}
