// SPDX-License-Identifier: Apache-2.0
//! Readmission preserves search, pre-proof publication and post-proof evidence.
//!
//! Selection protects the original catalogue identity throughout. A completed
//! discovery remains resident through the witness and subsequent observations;
//! temporary reference views exist only during a possession-bound callback.
use super::{discovery, search, ManagedClass, ManagedObjectRef};
use crate::{
    attributes::owned::resident::ValueNeed,
    crypto::{integer_key::PublicDer, key_evidence},
    session::{observation_protection::ObservationProtection, SessionAccess},
    symmetric::memory::Credit,
    Error, ObjectAdmission, ObjectSearchReport, Result, Session,
};
use fe11_sys::*;

enum Phase {
    RsaDiscovery {
        read: Box<crate::crypto::rsa_observation::Owner>,
        second: crate::crypto::rsa_evidence::Initial,
    },
    SecondSelection(crate::crypto::rsa_evidence::Initial),
    SecondSearch {
        read: search::SearchOwner,
        second: crate::crypto::rsa_evidence::Initial,
    },
    RsaEvidence {
        report: ObjectSearchReport,
        handle: CK_OBJECT_HANDLE,
        read: Box<crate::crypto::rsa_evidence::Owner>,
    },
    RsaAdmission {
        report: ObjectSearchReport,
        evidence: key_evidence::Evidence,
        read: Box<discovery::DiscoveryOwner>,
    },
    PublicEvidence {
        report: ObjectSearchReport,
        handle: CK_OBJECT_HANDLE,
        read: Box<crate::crypto::public_import::observation::Owner>,
    },
    PublicAdmission {
        report: ObjectSearchReport,
        mechanisms: crate::MechanismObservationReport,
        read: Box<discovery::DiscoveryOwner>,
    },
    Search(search::SearchOwner),
    Evidence {
        report: ObjectSearchReport,
        read: Box<key_evidence::Owner>,
    },
    Admission {
        report: ObjectSearchReport,
        signing: Box<key_evidence::Owner>,
        read: Box<discovery::DiscoveryOwner>,
    },
    Ready {
        report: ObjectSearchReport,
        signing: Box<key_evidence::Owner>,
        reference: Box<discovery::DiscoveryOwner>,
    },
    Stopped,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Need {
    RsaDiscovery(crate::crypto::rsa_observation::Need),
    SecondSelection,
    Search(search::SearchNeed),
    Metadata(ValueNeed),
    Admission(discovery::Need),
}
pub(crate) struct Owner {
    phase: Phase,
    prepared_evidence: Option<preparation::Initial>,
    class: ManagedClass,
    prepared_reference: Option<discovery::preparation::SelectedInitial>,
    permit: Option<crate::registry::Reservation<crate::managed::NativeIdentity>>,
    publication: Option<PublicDer>,
    second_search: Option<search::SearchStorage>,
    second_selection: Option<super::mutations::PreparedManagedSelection>,
    admission: ObjectAdmission,
    protection: Option<ObservationProtection>,
    epoch: u64,
    prepaid: Credit,
    _credit: Credit,
}
impl Owner {
    fn protection(&self) -> Result<ObservationProtection> {
        self.protection
            .as_ref()
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::ReadmissionSelectionAbsent,
            )))?
            .duplicate()
    }
    fn select_again(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        selection: crate::managed::OwnedSelectionGuard,
    ) -> Result<()> {
        let Phase::SecondSelection(second) = std::mem::replace(&mut self.phase, Phase::Stopped)
        else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::SecondRsaSelectionPhase,
            )));
        };
        let protection = ObservationProtection::selection(session, selection, &mut self.prepaid)?;
        let storage = self.second_search.take().ok_or(Error::Rejected(
            crate::RejectionReason::ObjectReferences(
                crate::ObjectReferencesRejection::SecondRsaSearchPreparationAbsent,
            ),
        ))?;
        let read = storage.bind(self.admission.search, self.epoch, access, &mut self.prepaid)?;
        self.protection = Some(protection);
        self.phase = Phase::SecondSearch { read, second };
        Ok(())
    }

    pub(crate) fn pending(&self) -> bool {
        match &self.phase {
            Phase::RsaDiscovery { read, .. } => read.pending(),
            Phase::RsaEvidence { read, .. } => read.pending(),
            Phase::RsaAdmission { read, .. } => read.pending(),
            Phase::SecondSearch { read, .. } => read.pending(),
            Phase::SecondSelection(_) => false,
            Phase::PublicEvidence { read, .. } => read.pending(),
            Phase::PublicAdmission { read, .. } => read.pending(),
            Phase::Search(read) => read.pending(),
            Phase::Evidence { read, .. } => read.pending(),
            Phase::Admission { signing, read, .. } => signing.pending() || read.pending(),
            Phase::Ready {
                signing, reference, ..
            } => signing.pending() || reference.pending(),
            Phase::Stopped => false,
        }
    }
    pub(crate) fn search_claimed(&self) -> bool {
        matches!(&self.phase, Phase::Search(read) | Phase::SecondSearch { read, .. } if read.claimed())
    }
    fn finish_search(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        match &mut self.phase {
            Phase::Search(read) | Phase::SecondSearch { read, .. } => read.finish(session, access),
            _ => Ok(()),
        }
    }
    fn complete(&self) -> bool {
        matches!(&self.phase, Phase::Ready { signing, .. } if signing.complete())
            || matches!(&self.phase, Phase::PublicAdmission { read, .. } | Phase::RsaAdmission { read, .. } if read.complete())
    }
    fn need(&mut self) -> Result<Option<Need>> {
        Ok(match &mut self.phase {
            Phase::RsaDiscovery { read, .. } => read.need().map(Need::RsaDiscovery),
            Phase::SecondSelection(_) => Some(Need::SecondSelection),
            Phase::SecondSearch { read, .. } => read.need()?.map(Need::Search),
            Phase::RsaEvidence { read, .. } => read.need().map(Need::Metadata),
            Phase::RsaAdmission { read, .. } => read.need()?.map(Need::Admission),
            Phase::PublicEvidence { read, .. } => read.need().map(Need::Metadata),
            Phase::PublicAdmission { read, .. } => read.need()?.map(Need::Admission),
            Phase::Search(read) => read.need()?.map(Need::Search),
            Phase::Evidence { read, .. } => read.need().map(Need::Metadata),
            Phase::Admission { read, .. } => read.need()?.map(Need::Admission),
            Phase::Ready { .. } => None,
            Phase::Stopped => None,
        })
    }
    fn advance(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        crate::session::recovery::observations::context(session, Some(self.epoch), self.epoch)?;
        session.entry(access)?;
        loop {
            match &mut self.phase {
                Phase::RsaDiscovery { read, .. } => {
                    read.advance(session, access)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::SecondSelection(_) => return Ok(()),
                Phase::SecondSearch { read, .. } => {
                    read.advance(session, access)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::RsaEvidence { read, .. } => {
                    self.publication.as_ref().ok_or(Error::Rejected(
                        crate::RejectionReason::ObjectReferences(
                            crate::ObjectReferencesRejection::RsaObservedPublicationAbsent,
                        ),
                    ))?;
                    read.advance(session, access)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::RsaAdmission { read, .. } => {
                    read.advance(session, access)?;
                    return Ok(());
                }
                Phase::PublicEvidence { read, .. } => {
                    read.advance(session, access)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::PublicAdmission { read, .. } => {
                    read.advance(session, access)?;
                    return Ok(());
                }
                Phase::Search(read) => {
                    read.advance(session, access)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Evidence { read, .. } => {
                    read.advance(session, access)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Admission { read, .. } => {
                    read.advance(session, access)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Ready { .. } => return Ok(()),
                Phase::Stopped => {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                        crate::ObjectReferencesRejection::KeyReadmissionStopped,
                    )))
                }
            }
            self.phase = match std::mem::replace(&mut self.phase, Phase::Stopped) {
                Phase::RsaDiscovery { read, second } => {
                    let public = read.result()?;
                    // This is the original between-search structural validation;
                    // it performs no resource admission or native operation.
                    crate::crypto::integer_key::rsa_der(&public)?;
                    self.publication = Some(public);
                    drop(self.protection.take());
                    Phase::SecondSelection(second)
                }
                Phase::SecondSearch { read, second } => {
                    let found = read.into_collection()?;
                    let (handle, report) = self.admission.selection.select(&found)?;
                    Phase::RsaEvidence {
                        report,
                        handle,
                        read: Box::new(second.bind(
                            handle,
                            self.epoch,
                            self.protection()?,
                            &mut self.prepaid,
                        )?),
                    }
                }
                Phase::RsaEvidence {
                    report,
                    handle,
                    read,
                } => {
                    let evidence = read.result()?;
                    let initial = self.prepared_reference.take().ok_or(Error::Rejected(
                        crate::RejectionReason::ObjectReferences(
                            crate::ObjectReferencesRejection::RsaReferencePreparationAbsent,
                        ),
                    ))?;
                    let permit = self.permit.take().ok_or(Error::Rejected(
                        crate::RejectionReason::ObjectReferences(
                            crate::ObjectReferencesRejection::RsaReferenceQuotaTransferred,
                        ),
                    ))?;
                    let read = initial.bind(
                        self.class,
                        handle,
                        self.admission.clone(),
                        crate::ContentObservation::NotRequested,
                        "managed admission",
                        permit,
                        self.epoch,
                        self.protection()?,
                        &mut self.prepaid,
                    )?;
                    Phase::RsaAdmission {
                        report,
                        evidence,
                        read: Box::new(read),
                    }
                }
                Phase::Search(read) => {
                    let found = read.into_collection()?;
                    let (handle, report) = self.admission.selection.select(&found)?;
                    let initial = self.prepared_evidence.take().ok_or(Error::Rejected(
                        crate::RejectionReason::ObjectReferences(
                            crate::ObjectReferencesRejection::KeyEvidencePreparationAbsent,
                        ),
                    ))?;
                    match initial {
                        preparation::Initial::PrivateRsa { first, second } => Phase::RsaDiscovery {
                            read: Box::new(first.bind(
                                handle,
                                self.epoch,
                                self.protection()?,
                                &mut self.prepaid,
                            )?),
                            second,
                        },
                        preparation::Initial::Signing(initial) => Phase::Evidence {
                            report,
                            read: Box::new(initial.bind(
                                handle,
                                self.epoch,
                                self.protection()?,
                                &mut self.prepaid,
                            )?),
                        },
                        preparation::Initial::Public(initial) => Phase::PublicEvidence {
                            report,
                            handle,
                            read: Box::new(initial.bind(
                                handle,
                                self.epoch,
                                self.protection()?,
                                &mut self.prepaid,
                            )?),
                        },
                    }
                }
                Phase::PublicEvidence {
                    report,
                    handle,
                    read,
                } => {
                    let mechanisms = read.result()?;
                    let initial = self.prepared_reference.take().ok_or(Error::Rejected(
                        crate::RejectionReason::ObjectReferences(
                            crate::ObjectReferencesRejection::KeyReferencePreparationAbsent,
                        ),
                    ))?;
                    let permit = self.permit.take().ok_or(Error::Rejected(
                        crate::RejectionReason::ObjectReferences(
                            crate::ObjectReferencesRejection::KeyReferenceQuotaTransferred,
                        ),
                    ))?;
                    let read = initial.bind(
                        self.class,
                        handle,
                        self.admission.clone(),
                        crate::ContentObservation::NotRequested,
                        "managed admission",
                        permit,
                        self.epoch,
                        self.protection()?,
                        &mut self.prepaid,
                    )?;
                    Phase::PublicAdmission {
                        report,
                        mechanisms,
                        read: Box::new(read),
                    }
                }
                Phase::Evidence {
                    report,
                    read: signing,
                } => {
                    let initial = self.prepared_reference.take().ok_or(Error::Rejected(
                        crate::RejectionReason::ObjectReferences(
                            crate::ObjectReferencesRejection::SigningReferencePreparationAbsent,
                        ),
                    ))?;
                    let permit = self.permit.take().ok_or(Error::Rejected(
                        crate::RejectionReason::ObjectReferences(
                            crate::ObjectReferencesRejection::SigningReferenceQuotaTransferred,
                        ),
                    ))?;
                    let read = initial.bind(
                        ManagedClass::PrivateKey,
                        signing.handle(),
                        self.admission.clone(),
                        crate::ContentObservation::NotRequested,
                        "managed admission",
                        permit,
                        self.epoch,
                        self.protection()?,
                        &mut self.prepaid,
                    )?;
                    Phase::Admission {
                        report,
                        signing,
                        read: Box::new(read),
                    }
                }
                Phase::Admission {
                    report,
                    signing,
                    read,
                } => Phase::Ready {
                    report,
                    signing,
                    reference: read,
                },
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                        crate::ObjectReferencesRejection::KeyReadmissionCompletionPhase,
                    )))
                }
            };
        }
    }

    fn result(
        self,
        session: &Session,
        access: &SessionAccess<'_>,
    ) -> Result<(ManagedObjectRef, Evidence, PublicDer)> {
        let (report, reference, evidence) = match self.phase {
            Phase::RsaAdmission {
                report,
                evidence,
                read,
            } => (report, read, Evidence::PrivateRsa(evidence)),
            Phase::Ready {
                report,
                signing,
                reference,
            } => (report, reference, Evidence::Signing(signing.result()?)),
            Phase::PublicAdmission {
                report,
                mechanisms,
                read,
            } => (report, read, Evidence::Public(mechanisms)),
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::KeyReadmissionIncomplete,
                )))
            }
        };
        let key = reference
            .result(session, access)?
            .with_search_report(report);
        Ok((
            key,
            evidence,
            self.publication
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::KeyPublicationAbsent,
                )))?,
        ))
    }
}
enum Evidence {
    PrivateRsa(key_evidence::Evidence),
    Signing(key_evidence::Evidence),
    Public(crate::MechanismObservationReport),
}
mod preparation;
mod runner;
pub(crate) use runner::{observe, observe_private_rsa, observe_public};
