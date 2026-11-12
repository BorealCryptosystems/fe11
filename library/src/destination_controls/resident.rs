// SPDX-License-Identifier: Apache-2.0
//! Destination enumeration enclosed by the mutation's original protection.
use super::*;
use crate::{
    attributes::TemplateSize,
    managed::search::{SearchCandidate, SearchNeed, SearchOwner, SearchStorage},
    session::{observation_protection::ObservationProtection, SessionAccess},
    symmetric::memory::Credit,
};
use fe11_sys::CK_OBJECT_HANDLE;

enum Query {
    Ready(Observation<u64>),
    Search {
        storage: Option<SearchStorage>,
        resources: SearchPlan,
        source: DestinationSource,
    },
    BoundSearch {
        search: SearchOwner,
        source: DestinationSource,
    },
    Consumed,
}
/// Empty native storage prepared together with the enclosing operation graph.
pub(crate) struct Initial(Query);
impl Initial {
    pub(crate) fn has_search(&self) -> bool {
        matches!(self.0, Query::Search { .. } | Query::BoundSearch { .. })
    }

    pub(crate) fn requested(
        selection: &DestinationPlan,
        destination: &DestinationIdentity<'_>,
    ) -> Result<usize> {
        let search = match &selection.search {
            DestinationSearchPlan::NotRequested => 0,
            DestinationSearchPlan::Observe {
                template,
                resources,
                ..
            } => match destination.recipe::<TemplateSize>(template)? {
                Ok(template) => {
                    SearchStorage::requested_bytes(template.owned_bytes()?, *resources)?
                }
                Err(_) => 0,
            },
        };
        search
            .checked_add(std::mem::size_of::<DestinationOwner>())
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectDestination(
                crate::ObjectDestinationRejection::DestinationStorageSize,
            )))
    }
    pub(crate) fn allocate(
        selection: &DestinationPlan,
        destination: &DestinationIdentity<'_>,
    ) -> Result<Self> {
        Ok(Self(match &selection.search {
            DestinationSearchPlan::NotRequested => Query::Ready(Observation::NotRequested),
            DestinationSearchPlan::Observe {
                template,
                resources,
                source,
                ..
            } => match destination.template(template)? {
                Ok(template) => Query::Search {
                    storage: Some(SearchStorage::allocate_owned(template, *resources)?),
                    resources: *resources,
                    source: *source,
                },
                Err(field) => Query::Ready(Observation::Unusable(
                    ObservationIssue::DestinationOperandAbsent(field),
                )),
            },
        }))
    }
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        let bytes = match &self.0 {
            Query::Ready(_) => 0,
            Query::Search { storage, .. } => storage
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectDestination(
                    crate::ObjectDestinationRejection::DestinationSearchPreparationAbsent,
                )))?
                .allocated_bytes()?,
            Query::BoundSearch { .. } | Query::Consumed => {
                return Err(Error::Rejected(crate::RejectionReason::ObjectDestination(
                    crate::ObjectDestinationRejection::DestinationPreparationAlreadyBound,
                )));
            }
        };
        bytes
            .checked_add(std::mem::size_of::<DestinationOwner>())
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectDestination(
                crate::ObjectDestinationRejection::DestinationStorageSize,
            )))
    }

    /// A failed activation keeps its search storage in this initial owner.
    /// The enclosing access-first frame also retains selection and protection.
    pub(crate) fn bind_retained(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        selection: &DestinationPlan,
        source_handle: Option<CK_OBJECT_HANDLE>,
        epoch: u64,
        protection: &mut Option<ObservationProtection>,
        prepaid: &mut Credit,
    ) -> Result<DestinationOwner> {
        if matches!(self.0, Query::Consumed) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectDestination(
                crate::ObjectDestinationRejection::DestinationPreparationAlreadyConsumed,
            )));
        }
        if protection.is_none() {
            return Err(Error::Rejected(crate::RejectionReason::ObjectDestination(
                crate::ObjectDestinationRejection::DestinationProtectionAbsent,
            )));
        }
        session.entry(access)?;
        let observed = !matches!(selection.search, DestinationSearchPlan::NotRequested)
            || !matches!(selection.user, DestinationUserObservation::NotRequested);
        let authentication = observed.then_some(epoch);
        session.snapshot.check_authentication_unchanged(epoch)?;
        // Selection clones share immutable operands. The caller retains its
        // selection if reading the recorded USER role refuses.
        let evaluation = PreparedDestination::bind(
            selection.clone(),
            || session.snapshot.recorded_user(),
            authentication,
        )?;
        if let Query::Search {
            storage,
            resources,
            source,
        } = &mut self.0
        {
            SearchOwner::check_functions(access)?;
            let search = SearchStorage::bind_retained(storage, *resources, epoch, access, prepaid)?;
            // Preserve a successful search transfer if the enclosing owner's
            // credit split fails. No native operation has started in this phase.
            self.0 = Query::BoundSearch {
                search,
                source: *source,
            };
        }
        let credit = prepaid.split(std::mem::size_of::<DestinationOwner>())?;
        let phase = match std::mem::replace(&mut self.0, Query::Consumed) {
            Query::Ready(count) => Phase::Ready { evaluation, count },
            Query::BoundSearch { search, source } => Phase::Searching {
                evaluation,
                search,
                source,
            },
            Query::Search { .. } | Query::Consumed => {
                unreachable!("validated destination preparation")
            }
        };
        Ok(DestinationOwner {
            phase,
            source_handle,
            epoch,
            authentication,
            _protection: protection.take().expect("validated destination protection"),
            _credit: credit,
        })
    }
}
enum Phase {
    Searching {
        evaluation: PreparedDestination,
        search: SearchOwner,
        source: DestinationSource,
    },
    Ready {
        evaluation: PreparedDestination,
        count: Observation<u64>,
    },
    Complete(DestinationReport),
    Stopped,
}
pub(crate) struct DestinationOwner {
    phase: Phase,
    source_handle: Option<CK_OBJECT_HANDLE>,
    epoch: u64,
    authentication: Option<u64>,
    _protection: ObservationProtection,
    _credit: Credit,
}
impl DestinationOwner {
    pub(crate) fn pending(&self) -> bool {
        matches!(&self.phase, Phase::Searching { search, .. } if search.pending())
    }
    pub(crate) fn search_claimed(&self) -> bool {
        matches!(&self.phase, Phase::Searching { search, .. } if search.claimed())
    }
    pub(crate) fn complete(&self) -> bool {
        matches!(self.phase, Phase::Complete(_))
    }
    pub(crate) fn need(&mut self) -> Result<Option<SearchNeed>> {
        match &mut self.phase {
            Phase::Searching { search, .. } => search.need(),
            _ => Ok(None),
        }
    }
    pub(crate) fn attach(&mut self, candidate: SearchCandidate) -> Result<()> {
        match &mut self.phase {
            Phase::Searching { search, .. } => search.attach(candidate),
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectDestination(
                crate::ObjectDestinationRejection::DestinationContinuationPhase,
            ))),
        }
    }
    pub(crate) fn advance(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        session.entry(access)?;
        session
            .snapshot
            .check_authentication_unchanged(self.epoch)?;
        if let Phase::Searching { search, .. } = &mut self.phase {
            search.advance(session, access)?;
            if !search.complete() {
                return Ok(());
            }
        }
        self.phase = match std::mem::replace(&mut self.phase, Phase::Stopped) {
            Phase::Searching {
                evaluation,
                search,
                source,
            } => {
                let found = search.into_collection()?;
                let count = found
                    .iter()
                    .filter(|handle| {
                        source == DestinationSource::Include || Some(**handle) != self.source_handle
                    })
                    .count();
                let count = Observation::Observed(u64::try_from(count).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::ObjectDestination(
                        crate::ObjectDestinationRejection::DestinationCardinalityWidth,
                    ))
                })?);
                Phase::Complete(evaluation.finish(count)?)
            }
            Phase::Ready { evaluation, count } => Phase::Complete(evaluation.finish(count)?),
            Phase::Complete(report) => Phase::Complete(report),
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::ObjectDestination(
                    crate::ObjectDestinationRejection::DestinationCompletionPhase,
                )))
            }
        };
        Ok(())
    }
    pub(crate) fn finish_search(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
    ) -> Result<()> {
        match &mut self.phase {
            Phase::Searching { search, .. } => search.finish(session, access),
            _ => Ok(()),
        }
    }
    pub(crate) fn result(
        self,
        session: &Session,
        access: &SessionAccess<'_>,
    ) -> Result<DestinationReport> {
        let Phase::Complete(report) = self.phase else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectDestination(
                crate::ObjectDestinationRejection::DestinationIncomplete,
            )));
        };
        session.metadata_result(access, self.authentication, Ok(report))
    }
}
