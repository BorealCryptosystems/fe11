// SPDX-License-Identifier: Apache-2.0
//! A missing native key is an empty lookup, not evidence of derivation support.
use super::{
    generation_transition_spec::history, object_owner::Owner, outcome::Failure,
    selection_symmetric as symmetric,
};
use fe11::*;

fn spec() -> MontgomeryKeySpec {
    MontgomeryKeySpec {
        public_usages: KeyUsageRequest {
            derive: Some(true),
            ..KeyUsageRequest::omitted()
        },
        private_usages: KeyUsageRequest {
            derive: Some(true),
            ..KeyUsageRequest::omitted()
        },
        public_visibility: ObjectVisibility::Public,
        private_visibility: ObjectVisibility::Private,
        public_admission: symmetric::key(false).admission,
        private_admission: symmetric::key(false).admission,
        mechanisms: MechanismObservationPlan::NotRequested,
        domain: MontgomeryDomain::Curve25519,
        id: symmetric::ID.to_vec(),
        label: symmetric::LABEL.into(),
        persistent: false,
    }
}
pub fn montgomery_absent(owner: &Owner) -> std::result::Result<(), Failure> {
    let result = match owner {
        Owner::Session(s) => s.find_montgomery_key(spec(), history()).map(|_| ()),
        Owner::Advanced(s) => s
            .find_montgomery_key(spec(), history())
            .and_then(|mut ticket| s.poll(&mut ticket).map(|_| ())),
    };
    match result {
        Err(Error::Rejected(RejectionReason::ObjectSearch(
            ObjectSearchRejection::SelectedSearchResultAbsent,
        ))) => Ok(()),
        Err(error) => Err(error.into()),
        Ok(()) => Err(Failure::Oracle("empty_montgomery_selector_accepted")),
    }
}
