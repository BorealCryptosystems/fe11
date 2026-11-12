// SPDX-License-Identifier: Apache-2.0
//! One active native frame family; observations and generation stay independent.
use super::selector::Selector;
use super::{FindFrame, KeyPolicy, ReadOwner, Stage};
use crate::{managed::search::SearchCollection, Error, Result};

pub(super) struct SearchStorage {
    pub(super) native: FindFrame,
    pub(super) collection: SearchCollection,
    private: Option<Selector>,
}

// The boxed pair inside policy owns its prepared family observations. Moving
// policy between variants does not move that allocation. Search storage remains
// prepaid while dormant so a later private-key search needs no allocation.
enum Active {
    Search {
        policy: KeyPolicy,
        search: SearchStorage,
    },
    Read {
        policy: KeyPolicy,
        dormant: SearchStorage,
        read: ReadOwner,
    },
    Idle {
        policy: KeyPolicy,
        dormant: SearchStorage,
    },
}

pub(super) struct Frames {
    // Temporarily empty only inside the infallible ownership transitions below.
    // No fallible callback or native dispatch occurs during that transfer.
    active: Option<Active>,
}
impl Frames {
    pub(super) fn new(
        policy: KeyPolicy,
        native: FindFrame,
        collection: SearchCollection,
        private: Option<Selector>,
    ) -> Self {
        Self {
            active: Some(Active::Search {
                policy,
                search: SearchStorage {
                    native,
                    collection,
                    private,
                },
            }),
        }
    }
    pub(super) fn policy(&self) -> &KeyPolicy {
        match self.active.as_ref().expect("completed frame transition") {
            Active::Search { policy, .. }
            | Active::Read { policy, .. }
            | Active::Idle { policy, .. } => policy,
        }
    }
    pub(super) fn policy_mut(&mut self) -> &mut KeyPolicy {
        match self.active.as_mut().expect("completed frame transition") {
            Active::Search { policy, .. }
            | Active::Read { policy, .. }
            | Active::Idle { policy, .. } => policy,
        }
    }
    pub(super) fn search(&self) -> &SearchStorage {
        match self.active.as_ref().expect("completed frame transition") {
            Active::Search { search, .. } => search,
            Active::Read { dormant, .. } | Active::Idle { dormant, .. } => dormant,
        }
    }
    pub(super) fn search_mut(&mut self) -> &mut SearchStorage {
        match self.active.as_mut().expect("completed frame transition") {
            Active::Search { search, .. } => search,
            Active::Read { dormant, .. } | Active::Idle { dormant, .. } => dormant,
        }
    }
    pub(super) fn read(&self) -> Option<&ReadOwner> {
        match self.active.as_ref().expect("completed frame transition") {
            Active::Read { read, .. } => Some(read),
            _ => None,
        }
    }
    pub(super) fn read_mut(&mut self) -> Option<&mut ReadOwner> {
        match self.active.as_mut().expect("completed frame transition") {
            Active::Read { read, .. } => Some(read),
            _ => None,
        }
    }
    fn take_parts(&mut self) -> (KeyPolicy, SearchStorage) {
        match self.active.take().expect("completed frame transition") {
            Active::Search { policy, search } => (policy, search),
            Active::Read {
                policy, dormant, ..
            }
            | Active::Idle { policy, dormant } => (policy, dormant),
        }
    }
    pub(super) fn activate_read(&mut self, read: ReadOwner) {
        let (policy, dormant) = self.take_parts();
        self.active = Some(Active::Read {
            policy,
            dormant,
            read,
        });
    }
    pub(super) fn activate_search(&mut self) {
        let (policy, search) = self.take_parts();
        self.active = Some(Active::Search { policy, search });
    }
    pub(super) fn activate_private_search(&mut self) -> Result<()> {
        let selector = self.search_mut().private.take().ok_or(Error::Rejected(
            crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::PrivateSearchSelectorAbsent,
            ),
        ))?;
        self.activate_search();
        let search = self.search_mut();
        search.native._template = selector.template;
        search.native.attrs = selector.attrs;
        // Previous descriptors and storage are gone before their credit.
        search.native._selector_credit = Some(selector.credit);
        Ok(())
    }
    pub(super) fn idle(&mut self) {
        let (policy, dormant) = self.take_parts();
        self.active = Some(Active::Idle { policy, dormant });
    }

    /// Check at the dispatch boundary as well as when attaching a candidate.
    /// A retained dormant search cannot be mistaken for the active read.
    pub(super) fn check_stage(&self, stage: Stage) -> Result<()> {
        let active = self.active.as_ref().expect("completed frame transition");
        let matches = match stage {
            Stage::Init | Stage::Find | Stage::Final => matches!(active, Active::Search { .. }),
            Stage::Required
            | Stage::RequiredLocal { .. }
            | Stage::PublicMaterial
            | Stage::History
            | Stage::Allowed
            | Stage::Properties => matches!(active, Active::Read { .. }),
            Stage::Generate | Stage::Destroy | Stage::Done | Stage::Failed => true,
        };
        if matches {
            Ok(())
        } else {
            Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AdmissionFramePhase,
            )))
        }
    }
}
