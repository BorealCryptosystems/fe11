// SPDX-License-Identifier: Apache-2.0
//! Discovery keeps selection, publication and optional content in one owner.
use super::*;
use crate::{
    attributes::{
        owned::resident::{LegacyOwner, ReadStorage, Recipe, ValueNeed},
        TemplateSink, TemplateSize,
    },
    content_controls::{
        fingerprint_observation::resident as fingerprint, owned::resident::ContentOwner,
    },
    session::{
        observation_protection::ObservationProtection,
        recovery::observations::{context, Prepared, Waiting},
        SessionAccess,
    },
    symmetric::memory::{ControlledReservation, Credit},
    ContentObservation, ContentReadPlan,
};
use search::{
    SearchCandidate, SearchNeed, SearchOwner, SearchPreparation, SearchStorage, SearchWithdrawal,
};

struct Selected {
    handle: CK_OBJECT_HANDLE,
    report: Option<crate::ObjectSearchReport>,
}
// Retain the actual published identity, not a ManagedObjectRef: the latter
// would keep Inner alive from inside its own session registry. Creator-entry
// retention is the existing identity contract and is released by local
// observation cleanup or proven close; an unknown native return stays retained.
struct Published {
    identity: Arc<ManagedIdentity>,
    report: Option<crate::ObjectSearchReport>,
}
enum Phase {
    Search(SearchOwner),
    NeedRequired(Selected),
    Required {
        selected: Selected,
        read: LegacyOwner,
    },
    NeedProperties {
        selected: Selected,
        key_type: Option<CK_KEY_TYPE>,
    },
    Properties {
        selected: Selected,
        key_type: Option<CK_KEY_TYPE>,
        read: LegacyOwner,
    },
    NeedContent(Published),
    Value {
        published: Published,
        read: ContentOwner,
    },
    Fingerprint {
        published: Published,
        read: Box<fingerprint::FingerprintOwner>,
    },
    Complete {
        published: Published,
        content: crate::ContentReport,
    },
    Stopped,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Need {
    Search(SearchNeed),
    Required,
    Properties,
    MetadataValue(ValueNeed),
    ValueStart(usize),
    Value(usize),
    FingerprintStart(crate::AttributeReadPlan),
    Fingerprint(fingerprint::Need),
}
pub(crate) struct DiscoveryOwner {
    native: Option<Arc<NativeIdentity>>,
    phase: Phase,
    class: ManagedClass,
    admission: crate::ObjectAdmission,
    content: ContentObservation,
    content_stage: &'static str,
    permit: Option<crate::registry::Reservation<crate::managed::NativeIdentity>>,
    epoch: u64,
    protection: ObservationProtection,
    _credit: Credit,
}
impl DiscoveryOwner {
    pub(crate) fn retain_native(mut self, native: Arc<NativeIdentity>) -> Self {
        self.native = Some(native);
        self
    }

    pub(crate) fn pending(&self) -> bool {
        match &self.phase {
            Phase::Search(search) => search.pending(),
            Phase::Required { read, .. } | Phase::Properties { read, .. } => read.pending(),
            Phase::Value { read, .. } => read.pending(),
            Phase::Fingerprint { read, .. } => read.pending(),
            _ => false,
        }
    }
    pub(crate) fn search_claimed(&self) -> bool {
        matches!(&self.phase, Phase::Search(search) if search.claimed())
    }
    pub(crate) fn complete(&self) -> bool {
        matches!(self.phase, Phase::Complete { .. })
    }
    pub(crate) fn need(&mut self) -> Result<Option<Need>> {
        Ok(match &mut self.phase {
            Phase::Search(search) => search.need()?.map(Need::Search),
            Phase::NeedRequired(_) => Some(Need::Required),
            Phase::NeedProperties { .. } => Some(Need::Properties),
            Phase::Required { read, .. } | Phase::Properties { read, .. } => {
                read.need().map(Need::MetadataValue)
            }
            Phase::NeedContent(_) => match content_plan(&self.content) {
                None => None,
                Some(ContentReadPlan::Value { maximum_bytes }) => {
                    Some(Need::ValueStart(maximum_bytes))
                }
                Some(ContentReadPlan::PublicFingerprintV1 { read }) => {
                    Some(Need::FingerprintStart(read))
                }
            },
            Phase::Value { read, .. } => read.need().map(Need::Value),
            Phase::Fingerprint { read, .. } => read.need().map(Need::Fingerprint),
            _ => None,
        })
    }
    pub(crate) fn advance(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        context(session, Some(self.epoch), self.epoch)?;
        if let Some(native) = &self.native {
            session.native_identity_handle(access, native)?;
        }
        loop {
            // Publication remains before content. Every later pass checks the
            // same identity, including creator closure and concurrent revocation.
            match &mut self.phase {
                Phase::Search(search) => {
                    search.advance(session, access)?;
                    if !search.complete() {
                        return Ok(());
                    }
                }
                Phase::Required { selected, read } | Phase::Properties { selected, read, .. } => {
                    read.advance(session, access, selected.handle)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Value { published, read } => {
                    let handle = session.managed_identity_handle(access, &published.identity)?;
                    let result = read.advance(session, access, handle);
                    published.identity.access.result(session, access, result)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Fingerprint { published, read } => {
                    let handle = session.managed_identity_handle(access, &published.identity)?;
                    let result = read.advance(session, access, handle);
                    published.identity.access.result(session, access, result)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::NeedContent(published) => {
                    session.managed_identity_handle(access, &published.identity)?;
                    if content_plan(&self.content).is_some() {
                        return Ok(());
                    }
                }
                Phase::NeedRequired(_) => return Ok(()),
                Phase::NeedProperties { .. } if Recipe::Controls(&self.admission).len() != 0 => {
                    return Ok(())
                }
                Phase::Complete { .. } => return Ok(()),
                Phase::Stopped => {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                        crate::ObjectSearchRejection::ManagedDiscoveryStopped,
                    )))
                }
                _ => {}
            }
            self.phase = match std::mem::replace(&mut self.phase, Phase::Stopped) {
                Phase::Search(search) => {
                    let found = search.into_collection()?;
                    let (handle, report) = self.admission.selection.select(&found)?;
                    Phase::NeedRequired(Selected {
                        handle,
                        report: Some(report),
                    })
                }
                Phase::Required { selected, read } => {
                    let material = read.required_result(session, access)?;
                    material.integer(CKA_CLASS, self.class.raw())?;
                    Phase::NeedProperties {
                        selected,
                        key_type: key_type(self.class, &material)?,
                    }
                }
                Phase::NeedProperties { selected, key_type } => {
                    let properties = self
                        .admission
                        .observe_owned(attributes::ObservedAttributes::empty())?;
                    self.publish(session, access, selected, key_type, properties)?
                }
                Phase::Properties {
                    selected,
                    key_type,
                    read,
                } => {
                    let properties =
                        read.object_observations_result(session, access, &self.admission)?;
                    self.publish(session, access, selected, key_type, properties)?
                }
                Phase::NeedContent(published) => {
                    let content =
                        std::mem::replace(&mut self.content, ContentObservation::NotRequested)
                            .observe_with(|_| {
                                Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                                    crate::ObjectSearchRejection::UnselectedManagedContent,
                                )))
                            })?;
                    Phase::Complete { published, content }
                }
                Phase::Value { published, read } => {
                    let check =
                        std::mem::replace(&mut self.content, ContentObservation::NotRequested);
                    let result =
                        read.result(session, access, |value| check.observe_with(|_| Ok(value)));
                    let content = published.identity.access.result(session, access, result)?;
                    Phase::Complete { published, content }
                }
                Phase::Fingerprint { published, read } => {
                    let check =
                        std::mem::replace(&mut self.content, ContentObservation::NotRequested);
                    let result =
                        read.result(session, access, |value| check.observe_with(|_| Ok(value)));
                    let content = published.identity.access.result(session, access, result)?;
                    Phase::Complete { published, content }
                }
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                        crate::ObjectSearchRejection::ManagedDiscoveryCompletionPhase,
                    )))
                }
            };
        }
    }
    fn publish(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        selected: Selected,
        key_type: Option<CK_KEY_TYPE>,
        properties: crate::ObjectObservationReport,
    ) -> Result<Phase> {
        let identity = session.publish_managed_observation(
            access,
            selected.handle,
            self.class,
            key_type,
            properties,
            self.epoch,
            self.native.as_ref(),
            self.permit
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::DiscoveryQuotaTransferred,
                )))?,
        )?;
        Ok(Phase::NeedContent(Published {
            identity,
            report: selected.report,
        }))
    }
    pub(crate) fn attach(&mut self, need: Need, candidate: Candidate) -> Result<()> {
        if self.need()? != Some(need) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::ManagedDiscoveryContinuationChanged,
            )));
        }
        match (need, candidate) {
            (Need::Search(_), Candidate::Search(candidate)) => match &mut self.phase {
                Phase::Search(search) => search.attach(candidate),
                _ => Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::ManagedDiscoverySearchPhase,
                ))),
            },
            (Need::MetadataValue(need), Candidate::MetadataValue(value)) => match &mut self.phase {
                Phase::Required { read, .. } | Phase::Properties { read, .. } => {
                    read.attach(need, value)
                }
                _ => Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::ManagedDiscoveryMetadataPhase,
                ))),
            },
            (Need::Value(length), Candidate::Value(value)) => match &mut self.phase {
                Phase::Value { read, .. } => read.attach(length, value),
                _ => Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::ManagedDiscoveryContentPhase,
                ))),
            },
            (Need::Fingerprint(need), Candidate::Fingerprint(candidate)) => match &mut self.phase {
                Phase::Fingerprint { read, .. } => read.attach(need, candidate),
                _ => Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::ManagedDiscoveryFingerprintPhase,
                ))),
            },
            (Need::Required | Need::Properties, Candidate::Metadata(storage, mut credit)) => {
                let (handle, recipe) = match &self.phase {
                    Phase::NeedRequired(selected) => (
                        selected.handle,
                        required_recipe(self.class, &self.admission),
                    ),
                    Phase::NeedProperties { selected, .. } => {
                        (selected.handle, Recipe::Controls(&self.admission))
                    }
                    _ => unreachable!("need checked"),
                };
                let read = storage.bind_with_protection(
                    &mut credit,
                    recipe,
                    handle,
                    Some(self.epoch),
                    self.protection.duplicate()?,
                )?;
                self.phase = match std::mem::replace(&mut self.phase, Phase::Stopped) {
                    Phase::NeedRequired(selected) => Phase::Required { selected, read },
                    Phase::NeedProperties { selected, key_type } => Phase::Properties {
                        selected,
                        key_type,
                        read,
                    },
                    _ => unreachable!("need checked"),
                };
                Ok(())
            }
            (Need::ValueStart(maximum), Candidate::ValueStart(mut credit)) => {
                let Phase::NeedContent(published) = &self.phase else {
                    unreachable!("need checked")
                };
                let read = ContentOwner::prepaid_protected(
                    &mut credit,
                    published.identity.handle,
                    maximum,
                    Some(self.epoch),
                    self.protection.duplicate()?,
                )?;
                let Phase::NeedContent(published) =
                    std::mem::replace(&mut self.phase, Phase::Stopped)
                else {
                    unreachable!("need checked")
                };
                self.phase = Phase::Value { published, read };
                Ok(())
            }
            (Need::FingerprintStart(plan), Candidate::FingerprintStart(storage, mut credit)) => {
                let Phase::NeedContent(published) = &self.phase else {
                    unreachable!("need checked")
                };
                let handle = published.identity.handle;
                let header = storage.bind_with_protection(
                    &mut credit,
                    fingerprint_recipe(plan),
                    handle,
                    Some(self.epoch),
                    self.protection.duplicate()?,
                )?;
                let read = Box::new(fingerprint::FingerprintOwner::bind_protected(
                    header,
                    plan,
                    handle,
                    Some(self.epoch),
                    self.protection.duplicate()?,
                    &mut credit,
                )?);
                let Phase::NeedContent(published) =
                    std::mem::replace(&mut self.phase, Phase::Stopped)
                else {
                    unreachable!("need checked")
                };
                self.phase = Phase::Fingerprint { published, read };
                Ok(())
            }
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::ManagedDiscoveryCandidateKind,
            ))),
        }
    }
    fn finish_search(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        match &mut self.phase {
            Phase::Search(search) => search.finish(session, access),
            _ => Ok(()),
        }
    }

    pub(crate) fn take_permit(
        &mut self,
    ) -> Result<crate::registry::Reservation<crate::managed::NativeIdentity>> {
        if !self.complete() {
            return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::DiscoveryPublicationIncomplete,
            )));
        }
        self.permit
            .take()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::DiscoveryQuotaAlreadyTransferred,
            )))
    }
    // Key-pair generation publishes both references before either content read.
    // Restart only the content phase; identity and quota are never recreated.
    pub(crate) fn resume_content(
        &mut self,
        selection: ContentObservation,
        stage: &'static str,
    ) -> Result<()> {
        let Phase::Complete { published, .. } = std::mem::replace(&mut self.phase, Phase::Stopped)
        else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::DiscoveryContentPublicationIncomplete,
            )));
        };
        self.content = selection;
        self.content_stage = stage;
        self.phase = Phase::NeedContent(published);
        Ok(())
    }
    pub(crate) fn result(
        self,
        session: &Session,
        access: &SessionAccess<'_>,
    ) -> Result<ManagedObjectRef> {
        let Phase::Complete { published, content } = self.phase else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectSearch(
                crate::ObjectSearchRejection::ManagedDiscoveryIncomplete,
            )));
        };
        session.managed_identity_handle(access, &published.identity)?;
        published.identity.access.result(session, access, Ok(()))?;
        Ok(reference(
            session,
            published.identity,
            published.report,
            Some(content),
        ))
    }
}
pub(super) fn reference(
    session: &Session,
    identity: Arc<ManagedIdentity>,
    search_report: Option<crate::ObjectSearchReport>,
    content_report: Option<crate::ContentReport>,
) -> ManagedObjectRef {
    ManagedObjectRef {
        native: NativeObjectRef {
            inner: session.inner.clone(),
            identity: identity.native.clone(),
            output_slot: None,
        },
        inner: session.inner.clone(),
        handle: identity.handle,
        identity,
        mutation_report: None,
        content_report,
        destination_report: None,
        search_report,
    }
}
pub(super) fn key_type(
    class: ManagedClass,
    material: &attributes::RequiredAttributes,
) -> Result<Option<CK_KEY_TYPE>> {
    if class.has_key_type() {
        Ok(Some(CK_ULONG::from_ne_bytes(
            material.bytes(CKA_KEY_TYPE)?.try_into().map_err(|_| {
                Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::KeyTypeWidth,
                ))
            })?,
        )))
    } else {
        Ok(None)
    }
}
fn required_recipe(class: ManagedClass, admission: &crate::ObjectAdmission) -> Recipe<'static> {
    Recipe::Required {
        fields: if class.has_key_type() {
            &[CKA_CLASS, CKA_KEY_TYPE]
        } else {
            &[CKA_CLASS]
        },
        maximum: admission.metadata.maximum_bytes,
    }
}
fn content_plan(content: &ContentObservation) -> Option<ContentReadPlan> {
    match content {
        ContentObservation::NotRequested => None,
        ContentObservation::Observe(read) => Some(*read),
    }
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
pub(super) use runner::{find, observe_native};
