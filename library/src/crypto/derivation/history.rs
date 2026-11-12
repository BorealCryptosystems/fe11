// SPDX-License-Identifier: Apache-2.0
//! Explicit reads of native protection and historical attributes.
use super::BaseProtection;
use crate::{AttributeUnavailableCause, Error, Observation, Result};
use fe11_sys::*;

/// Explicit read plan for six public protection/provenance attributes.
/// Each switch is independent; no comparison or propagation policy is applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryObservationPlan {
    /// Request CKA_SENSITIVE.
    pub sensitive: bool,
    /// Request CKA_EXTRACTABLE.
    pub extractable: bool,
    /// Request CKA_ALWAYS_SENSITIVE.
    pub always_sensitive: bool,
    /// Request CKA_NEVER_EXTRACTABLE.
    pub never_extractable: bool,
    /// Request CKA_LOCAL.
    pub local: bool,
    /// Request CKA_KEY_GEN_MECHANISM.
    pub generation: bool,
    /// Aggregate byte budget for the selected read, chosen by the caller.
    pub maximum_bytes: usize,
}
impl HistoryObservationPlan {
    pub(crate) fn field_iter(self) -> impl Iterator<Item = CK_ATTRIBUTE_TYPE> {
        [
            (self.sensitive, CKA_SENSITIVE),
            (self.extractable, CKA_EXTRACTABLE),
            (self.always_sensitive, CKA_ALWAYS_SENSITIVE),
            (self.never_extractable, CKA_NEVER_EXTRACTABLE),
            (self.local, CKA_LOCAL),
            (self.generation, CKA_KEY_GEN_MECHANISM),
        ]
        .into_iter()
        .filter_map(|(requested, field)| requested.then_some(field))
    }
    pub(crate) fn fields(self) -> Result<Vec<CK_ATTRIBUTE_TYPE>> {
        let mut fields = Vec::new();
        fields
            .try_reserve_exact(self.field_iter().count())
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::HistoryObservationDescriptorAllocation,
                ))
            })?;
        fields.extend(self.field_iter());
        Ok(fields)
    }
}
pub(crate) fn snapshot(
    plan: HistoryObservationPlan,
    v: &crate::attributes::ObservedAttributes,
) -> BaseProtection {
    let generation = v.integer(CKA_KEY_GEN_MECHANISM).interpret(|value| {
        if value == CK_UNAVAILABLE_INFORMATION as u64 {
            Observation::Unavailable(AttributeUnavailableCause::Unspecified)
        } else {
            Observation::Observed(value)
        }
    });
    BaseProtection {
        observation_plan: plan,
        current: super::ObservedCurrentKeyProtection {
            sensitive: v.boolean(CKA_SENSITIVE),
            extractable: v.boolean(CKA_EXTRACTABLE),
        },
        historical: super::HistoricalAttributes {
            always_sensitive: v.boolean(CKA_ALWAYS_SENSITIVE),
            never_extractable: v.boolean(CKA_NEVER_EXTRACTABLE),
        },
        local: v.boolean(CKA_LOCAL),
        generation,
    }
}

/// Independent native reads for the two objects in a derivation.
pub struct DerivationObservationPlan {
    /// Parent attributes requested before the native derivation.
    pub parent: HistoryObservationPlan,
    /// Child attributes requested after the native derivation.
    pub child: HistoryObservationPlan,
}
