// SPDX-License-Identifier: Apache-2.0
//! Reference search, metadata and content share their original resident protection.
use super::*;
use crate::{
    attributes::{
        owned::resident::{LegacyOwner, ReadStorage, Recipe, ValueNeed},
        Template, TemplateSize,
    },
    content_controls::{
        fingerprint_observation::resident as fingerprint, owned::resident::ContentOwner,
    },
    managed::search::{SearchCandidate, SearchNeed, SearchOwner, SearchPreparation, SearchStorage},
    session::observation_protection::ObservationProtection,
    session::{
        recovery::observations::{context, Prepared, Waiting},
        AdmissionProgress, SessionAccess,
    },
    symmetric::memory::{ControlledReservation, Credit},
    ContentObservation, ContentReadPlan, ProtectedContent,
};
use evaluation::{CurrentEvidence, SearchEvidence};
use fe11_sys::CK_OBJECT_HANDLE;

struct Observed {
    search: SearchEvidence,
    current: CurrentEvidence,
}
enum Stage {
    Search(SearchOwner),
    NeedMetadata(SearchEvidence),
    Metadata {
        search: SearchEvidence,
        read: LegacyOwner,
    },
    NeedContent(Observed),
    Value {
        observed: Observed,
        read: ContentOwner,
    },
    Fingerprint {
        observed: Observed,
        read: Box<fingerprint::FingerprintOwner>,
    },
    Complete {
        observed: Observed,
        content: crate::ContentReport,
    },
    Stopped,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Need {
    Search(SearchNeed),
    Metadata,
    MetadataValue(ValueNeed),
    ValueStart(usize),
    Value(usize),
    FingerprintStart(crate::AttributeReadPlan),
    Fingerprint(fingerprint::Need),
}
pub(crate) struct ReferenceOwner {
    stage: Stage,
    selection: ObjectReferencePlan,
    bound: Vec<(IdentityAttribute, AttributeValue)>,
    // Original caller expectation, consumed once by pure evaluation. Replacement
    // with NotRequested occurs only when transitioning to Complete/Stopped.
    content: ContentObservation,
    handle: CK_OBJECT_HANDLE,
    authentication: Option<u64>,
    protection: ObservationProtection,
    _credit: Credit,
}
impl ReferenceOwner {
    pub(crate) fn pending(&self) -> bool {
        match &self.stage {
            Stage::Search(search) => search.pending(),
            Stage::Metadata { read, .. } => read.pending(),
            Stage::Value { read, .. } => read.pending(),
            Stage::Fingerprint { read, .. } => read.pending(),
            _ => false,
        }
    }
    pub(crate) fn search_claimed(&self) -> bool {
        matches!(&self.stage, Stage::Search(search) if search.claimed())
    }
    pub(crate) fn complete(&self) -> bool {
        matches!(self.stage, Stage::Complete { .. })
    }
    pub(crate) fn need(&mut self) -> Result<Option<Need>> {
        Ok(match &mut self.stage {
            Stage::Search(search) => search.need()?.map(Need::Search),
            Stage::NeedMetadata(_) => Some(Need::Metadata),
            Stage::Metadata { read, .. } => read.need().map(Need::MetadataValue),
            Stage::NeedContent(_) => match content_plan(&self.content) {
                None => None,
                Some(ContentReadPlan::Value { maximum_bytes }) => {
                    Some(Need::ValueStart(maximum_bytes))
                }
                Some(ContentReadPlan::PublicFingerprintV1 { read }) => {
                    Some(Need::FingerprintStart(read))
                }
            },
            Stage::Value { read, .. } => read.need().map(Need::Value),
            Stage::Fingerprint { read, .. } => read.need().map(Need::Fingerprint),
            _ => None,
        })
    }
    pub(crate) fn advance(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        handle: CK_OBJECT_HANDLE,
    ) -> Result<()> {
        if handle != self.handle {
            return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::ReferenceSourceChanged,
            )));
        }
        loop {
            // Dispatch only while the child remains resident, including unwind.
            match &mut self.stage {
                Stage::Search(search) => {
                    search.advance(session, access)?;
                    if !search.complete() {
                        return Ok(());
                    }
                }
                Stage::Metadata { read, .. } => {
                    read.advance(session, access, handle)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Stage::Value { read, .. } => {
                    read.advance(session, access, handle)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Stage::Fingerprint { read, .. } => {
                    read.advance(session, access, handle)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Stage::NeedMetadata(_) if !self.selection.attributes.is_empty() => return Ok(()),
                Stage::NeedContent(_) if content_plan(&self.content).is_some() => return Ok(()),
                Stage::Complete { .. } => return Ok(()),
                Stage::Stopped => {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                        crate::ObjectReferencesRejection::ReferenceObservationStopped,
                    )))
                }
                _ => {}
            }
            self.stage = match std::mem::replace(&mut self.stage, Stage::Stopped) {
                Stage::Search(search) => {
                    let found = search.into_collection()?;
                    Stage::NeedMetadata(SearchEvidence::observe(
                        &self.selection,
                        Some(&found),
                        handle,
                    )?)
                }
                Stage::NeedMetadata(search) => Stage::NeedContent(Observed {
                    search,
                    current: CurrentEvidence::observe(&self.selection, Default::default())?,
                }),
                Stage::Metadata { search, read } => Stage::NeedContent(Observed {
                    search,
                    current: CurrentEvidence::observe(
                        &self.selection,
                        read.public_result(session, access)?,
                    )?,
                }),
                Stage::NeedContent(observed) => {
                    let content =
                        std::mem::replace(&mut self.content, ContentObservation::NotRequested)
                            .observe_with(|_| {
                                Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                                    crate::ObjectReferencesRejection::UnselectedReferenceContent,
                                )))
                            })?;
                    Stage::Complete { observed, content }
                }
                Stage::Value { observed, read } => {
                    let selected =
                        std::mem::replace(&mut self.content, ContentObservation::NotRequested);
                    let content =
                        read.result(session, access, |value| evaluate_content(selected, value))?;
                    Stage::Complete { observed, content }
                }
                Stage::Fingerprint { observed, read } => {
                    let selected =
                        std::mem::replace(&mut self.content, ContentObservation::NotRequested);
                    let content =
                        read.result(session, access, |value| evaluate_content(selected, value))?;
                    Stage::Complete { observed, content }
                }
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                        crate::ObjectReferencesRejection::ReferenceCompletionPhase,
                    )))
                }
            };
        }
    }
    pub(crate) fn attach(&mut self, need: Need, candidate: Candidate) -> Result<()> {
        if self.need()? != Some(need) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::ReferenceContinuationChanged,
            )));
        }
        match (need, candidate) {
            (Need::Search(_), Candidate::Search(candidate)) => match &mut self.stage {
                Stage::Search(search) => search.attach(candidate),
                _ => Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::ReferenceSearchPhase,
                ))),
            },
            (Need::MetadataValue(need), Candidate::MetadataValue(value)) => match &mut self.stage {
                Stage::Metadata { read, .. } => read.attach(need, value),
                _ => Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::ReferenceMetadataPhase,
                ))),
            },
            (Need::Value(length), Candidate::Value(value)) => match &mut self.stage {
                Stage::Value { read, .. } => read.attach(length, value),
                _ => Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::ReferenceContentPhase,
                ))),
            },
            (Need::Fingerprint(need), Candidate::Fingerprint(candidate)) => match &mut self.stage {
                Stage::Fingerprint { read, .. } => read.attach(need, candidate),
                _ => Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::ReferenceFingerprintPhase,
                ))),
            },
            (Need::Metadata, Candidate::Metadata(storage, mut credit)) => {
                let read = storage.bind_with_protection(
                    &mut credit,
                    Recipe::Reference(&self.selection),
                    self.handle,
                    self.authentication,
                    self.protection.duplicate()?,
                )?;
                let Stage::NeedMetadata(search) =
                    std::mem::replace(&mut self.stage, Stage::Stopped)
                else {
                    unreachable!("need checked")
                };
                self.stage = Stage::Metadata { search, read };
                Ok(())
            }
            (Need::ValueStart(maximum), Candidate::ValueStart(mut credit)) => {
                let read = ContentOwner::prepaid_protected(
                    &mut credit,
                    self.handle,
                    maximum,
                    self.authentication,
                    self.protection.duplicate()?,
                )?;
                let Stage::NeedContent(observed) =
                    std::mem::replace(&mut self.stage, Stage::Stopped)
                else {
                    unreachable!("need checked")
                };
                self.stage = Stage::Value { observed, read };
                Ok(())
            }
            (Need::FingerprintStart(plan), Candidate::FingerprintStart(storage, mut credit)) => {
                let reader = self.protection.duplicate()?;
                let header = storage.bind_with_protection(
                    &mut credit,
                    fingerprint_recipe(plan),
                    self.handle,
                    self.authentication,
                    reader.duplicate()?,
                )?;
                let read = Box::new(fingerprint::FingerprintOwner::bind_protected(
                    header,
                    plan,
                    self.handle,
                    self.authentication,
                    reader,
                    &mut credit,
                )?);
                let Stage::NeedContent(observed) =
                    std::mem::replace(&mut self.stage, Stage::Stopped)
                else {
                    unreachable!("need checked")
                };
                self.stage = Stage::Fingerprint { observed, read };
                Ok(())
            }
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::ReferenceCandidateKind,
            ))),
        }
    }
    pub(crate) fn finish_search(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
    ) -> Result<()> {
        match &mut self.stage {
            Stage::Search(search) => search.finish(session, access),
            _ => Ok(()),
        }
    }
    pub(crate) fn result(
        mut self,
        session: &Session,
        access: &SessionAccess<'_>,
    ) -> Result<ObjectReferenceReport> {
        let Stage::Complete { observed, content } = self.stage else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::ReferenceIncomplete,
            )));
        };
        let bound_bytes = evaluation::bound_allocated_bytes(&self.bound)?;
        let bound_credit = if bound_bytes == 0 {
            None
        } else {
            Some(self._credit.split(bound_bytes)?)
        };
        session.metadata_result(
            access,
            self.authentication,
            Ok(evaluation::report(
                self.selection,
                self.bound,
                observed.search,
                observed.current,
                content,
                bound_credit,
            )),
        )
    }
}
pub(crate) fn content_plan(content: &ContentObservation) -> Option<ContentReadPlan> {
    match content {
        ContentObservation::NotRequested => None,
        ContentObservation::Observe(read) => Some(*read),
    }
}
fn evaluate_content(
    selected: ContentObservation,
    value: ProtectedContent,
) -> Result<crate::ContentReport> {
    selected.observe_with(|_| Ok(value))
}
fn fingerprint_recipe(plan: crate::AttributeReadPlan) -> Recipe<'static> {
    Recipe::Fingerprint {
        fields: &[
            crate::attributes::FingerprintAttribute::Class,
            crate::attributes::FingerprintAttribute::KeyType,
        ],
        plan,
    }
}

pub(crate) mod preparation;
use preparation::{prepare, Candidate};
mod runner;
pub(crate) use runner::observe;
