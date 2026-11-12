// SPDX-License-Identifier: Apache-2.0
//! Prepaid generation lifetimes, independent of descriptive observations.
use crate::managed::NativeIdentity;
use crate::{CreatedObjectSet, Error, NativeObjectRef, Result, Session};
use std::sync::{Arc, Weak};

pub(super) struct Publication {
    inner: Weak<crate::module::Inner>,
    identities: [Option<Arc<NativeIdentity>>; 2],
    published: usize,
}

impl Publication {
    pub(super) fn prepare(
        session: &Session,
        count: usize,
        epoch: u64,
        permit: &mut crate::registry::Reservation<NativeIdentity>,
        credit: &mut crate::symmetric::memory::Credit,
    ) -> Result<Self> {
        let mut identities = [None, None];
        for slot in identities.iter_mut().take(count) {
            *slot = Some(NativeIdentity::prepare_creation(
                session, epoch, permit, credit,
            )?);
        }
        Ok(Self {
            inner: Arc::downgrade(&session.inner),
            identities,
            published: 0,
        })
    }

    pub(super) fn publish(
        &mut self,
        state: &crate::module::State,
        entry: &crate::module::SessionEntry,
        handles: &[fe11_sys::CK_OBJECT_HANDLE],
        permit: &mut crate::registry::Reservation<NativeIdentity>,
    ) -> Result<()> {
        if self.published != 0 || handles.len() != self.identities.iter().flatten().count() {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::GenerationPublicationArity,
            )));
        }
        let inner =
            self.inner
                .upgrade()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::GenerationModuleUnavailable,
                )))?;
        for (index, handle) in handles.iter().copied().enumerate() {
            NativeIdentity::publish_at(
                self.identities[index]
                    .as_mut()
                    .expect("prepared generation slot"),
                &inner,
                entry,
                state,
                handle,
                permit,
            )?;
            self.published += 1;
        }
        Ok(())
    }

    pub(super) fn complete(&self) -> bool {
        self.published != 0 && self.published == self.identities.iter().flatten().count()
    }

    pub(super) fn identity(&self, index: usize) -> Option<&Arc<NativeIdentity>> {
        if index < self.published {
            self.identities[index].as_ref()
        } else {
            None
        }
    }

    pub(super) fn objects(&self, inner: &Arc<crate::module::Inner>) -> Result<CreatedObjectSet> {
        if !self.complete() {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::GenerationPublicationIncomplete,
            )));
        }
        let reference = |index| NativeObjectRef {
            inner: inner.clone(),
            identity: self
                .identity(index)
                .expect("published generation slot")
                .clone(),
            output_slot: Some(index),
        };
        Ok(if self.published == 2 {
            CreatedObjectSet::pair([reference(0), reference(1)])
        } else {
            CreatedObjectSet::one(reference(0))
        })
    }
}

use super::*;

impl PublicationQuota {
    pub(super) fn permit(
        &mut self,
    ) -> Result<&mut crate::registry::Reservation<crate::managed::NativeIdentity>> {
        match self {
            Self::Bound(permit) => Ok(permit),
        }
    }
}

impl Admission {
    pub(super) fn finish_terminal(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        rv: CK_RV,
        _name: &'static str,
    ) -> Result<()> {
        let stage = self.stage;
        let result = self.finish(s, entry, rv);
        if let Err(cause) = result {
            if stage == Stage::Init
                && matches!(&cause, Error::Native { function: "C_FindObjectsInit", code, .. }
                    if *code == fe11_sys::CKR_OPERATION_ACTIVE as u64)
                && !self.pending
                && !s.native.is_uncertain()
            {
                // This refused attempt acquired no native search. Retire only
                // its own owner; the older search must remain usable and must
                // not receive an unsolicited FindObjectsFinal from this call.
                self.failure = Some(cause);
                self.stage = Stage::Done;
                return Ok(());
            }
            let cause = if stage == Stage::Final {
                search_final_failure(&mut self.failure, &mut self.search_diagnostic, cause)
            } else {
                cause
            };
            if self.generation.is_some() {
                if stage == Stage::Generate {
                    let generation = self.generation.as_mut().unwrap();
                    generation.refused(s, rv);
                    if generation.storage_retained() {
                        // A returned error is not proof that native storage is
                        // unused. Keep the operation and its guards installed
                        // until explicit successful cancellation or close.
                        self.stage = Stage::Failed;
                        entry.poisoned.store(true, Ordering::Release);
                        return Err(cause);
                    }
                }
                if matches!(stage, Stage::Init | Stage::Find | Stage::Final) {
                    self.stage = Stage::Failed;
                    entry.poisoned.store(true, Ordering::Release);
                    return Err(cause);
                }
                self.creation_failure(s, entry, cause);
                return Ok(());
            }
            // The selected public object's key type or canonical identity
            // differs from the request. Search and attribute reading are
            // complete, and no private operation has started. Preserve the
            // refusal without retiring a healthy session or destroying objects
            // that this call did not create.
            if rv == CKR_OK
                && matches!(
                    (stage, &cause),
                    (
                        Stage::Required | Stage::RequiredLocal { .. },
                        Error::Rejected(
                            crate::RejectionReason::KeyAdmission(crate::KeyAdmissionRejection::ClassicalPairSpkiMismatch)
                                | crate::RejectionReason::AttributePreparation(crate::AttributePreparationRejection::KeyTypeMismatch)
                                | crate::RejectionReason::KeyDerivation(crate::KeyDerivationRejection::DerivationBaseRequestedIdentityMismatch)
                        )
                    ) | (
                        Stage::PublicMaterial,
                        Error::Rejected(
                            crate::RejectionReason::KeyAdmission(crate::KeyAdmissionRejection::PqcPairSpkiMismatch)
                                | crate::RejectionReason::KeyAdmission(crate::KeyAdmissionRejection::MlKemPairSpkiMismatch)
                                | crate::RejectionReason::ClassicalSignatures(crate::ClassicalSignaturesRejection::VerificationSelectorPublicIdentity)
                        )
                    )
                )
            {
                self.failure = Some(cause);
                self.stage = Stage::Done;
                return Ok(());
            }
            self.stage = Stage::Failed;
            entry.poisoned.store(true, Ordering::Release);
            // The dispatch/control boundary already observed this return.
            return Err(cause);
        }
        Ok(())
    }

    pub(in crate::advanced) fn result(
        &mut self,
        s: &State,
        session: &Session,
    ) -> Result<OperationProgress> {
        let result = self.publish(s, session);
        if let Some(publication) = self.publication.as_ref().filter(|value| value.complete()) {
            return Ok(OperationProgress::CreatedObjects(crate::CreatedObjects {
                objects: publication.objects(&session.inner)?,
                observation: result.and_then(super::super::GeneratedObjects::from_progress),
                remainder: None,
            }));
        }
        if let Err(cause) = result {
            if self
                .generation
                .as_ref()
                .is_some_and(|g| g.created && !g.cleanup_attempted)
            {
                self.creation_failure(s, &session.entry, cause);
                return if self.complete() {
                    Err(self.failure.take().expect("terminal creation failure"))
                } else {
                    Ok(OperationProgress::Ready)
                };
            }
            return Err(cause);
        }
        result
    }

    pub(super) fn publish(&mut self, s: &State, session: &Session) -> Result<OperationProgress> {
        if !self.complete() {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AdmissionIncomplete,
            )));
        }
        if let Some(cause) = self.failure.take() {
            return Err(cause);
        }
        // The slot reader excludes destructive closes between this epoch check
        // and registry insertion/object_creator. A local non-creator close can
        // intervene, but cannot destroy these handles or advance the epoch.
        if self.generation.is_none()
            && self.close_epoch != session.snapshot.domain.close_epoch.load(Ordering::Acquire)
        {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::SessionCloseDuringAdmissionRediscover,
            )));
        }
        if self.found.len() != 1 {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AdmissionSelectedHandleAbsent,
            )));
        }
        session
            .snapshot
            .check_authentication_unchanged(self.observation_authentication)?;
        let attrs = self.attributes.as_ref().ok_or(Error::Rejected(
            crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AdmissionAttributesAbsent,
            ),
        ))?;
        match self.frames.policy_mut() {
            KeyPolicy::DerivationBase(prepared) => {
                let properties = self.object_report.take().ok_or(Error::Rejected(
                    crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::BaseObjectReportAbsent,
                    ),
                ))?;
                let mut reference = match prepared.class() {
                    ManagedClass::SecretKey => session.observed_secret_reference(
                        s,
                        self.found[0],
                        attrs,
                        properties,
                        self.observation_authentication,
                        self.publication
                            .as_ref()
                            .and_then(|value| value.identity(0)),
                        self.permit.permit()?,
                    )?,
                    ManagedClass::PrivateKey => session.observed_private_key_reference(
                        s,
                        self.found[0],
                        attrs,
                        prepared.key_type(),
                        properties,
                        self.observation_authentication,
                        self.publication
                            .as_ref()
                            .and_then(|value| value.identity(0)),
                        self.permit.permit()?,
                    )?,
                    _ => {
                        return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                            crate::KeyAdmissionRejection::DerivationBasePublicationClass,
                        )))
                    }
                };
                reference.search_report = self.search_report.take();
                if let Some(destinations) = &mut self.destinations {
                    reference = destinations.take(0)?.attach(session, reference)?;
                }
                let mechanisms = self.mechanism_report.take().ok_or(Error::Rejected(
                    crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::BaseMechanismReportAbsent,
                    ),
                ))?;
                match prepared.finish(reference, mechanisms)? {
                    crate::crypto::derivation::DerivationBaseResult::Agreement(key) => {
                        Ok(OperationProgress::AgreementKey(key))
                    }
                    crate::crypto::derivation::DerivationBaseResult::Montgomery(key) => {
                        Ok(OperationProgress::MontgomeryKey(key))
                    }
                    crate::crypto::derivation::DerivationBaseResult::Hkdf(key) => {
                        Ok(OperationProgress::HkdfKey(key))
                    }
                    crate::crypto::derivation::DerivationBaseResult::IntroducedAgreement(key) => {
                        Ok(OperationProgress::IntroducedAgreementKey(key))
                    }
                }
            }
            KeyPolicy::Symmetric { spec, publication } => {
                let mut managed = session.observed_secret_reference(
                    s,
                    self.found[0],
                    attrs,
                    self.object_report.take().ok_or(Error::Rejected(
                        crate::RejectionReason::KeyAdmission(
                            crate::KeyAdmissionRejection::ObjectAdmissionReportAbsent,
                        ),
                    ))?,
                    self.observation_authentication,
                    self.publication
                        .as_ref()
                        .and_then(|value| value.identity(0)),
                    self.permit.permit()?,
                )?;
                managed.search_report = self.search_report.take();
                if let Some(destinations) = &mut self.destinations {
                    managed = destinations.take(0)?.attach(session, managed)?;
                }
                publication.finish(
                    session,
                    spec,
                    managed,
                    self.history_observations.take().ok_or(Error::Rejected(
                        crate::RejectionReason::KeyAdmission(
                            crate::KeyAdmissionRejection::AdmissionProtectionObservationsAbsent,
                        ),
                    ))?,
                    self.mechanism_report.take().ok_or(Error::Rejected(
                        crate::RejectionReason::KeyAdmission(
                            crate::KeyAdmissionRejection::SymmetricMechanismReportAbsent,
                        ),
                    ))?,
                    self.generation
                        .as_ref()
                        .is_some_and(|generation| generation.created),
                )
            }
            KeyPolicy::VerificationPublic { prepared, .. } => {
                let mut managed = session.observed_public_key_reference(
                    s,
                    self.found[0],
                    attrs,
                    prepared.key_type(),
                    self.object_report.take().ok_or(Error::Rejected(
                        crate::RejectionReason::KeyAdmission(
                            crate::KeyAdmissionRejection::ObjectAdmissionReportAbsent,
                        ),
                    ))?,
                    self.observation_authentication,
                    self.publication
                        .as_ref()
                        .and_then(|value| value.identity(0)),
                    self.permit.permit()?,
                )?;
                managed.search_report = self.search_report.take();
                Ok(OperationProgress::VerificationKey(prepared.finish(
                    managed,
                    self.mechanism_report.take().ok_or(Error::Rejected(
                        crate::RejectionReason::KeyAdmission(
                            crate::KeyAdmissionRejection::MechanismAdmissionReportAbsent,
                        ),
                    ))?,
                )?))
            }
            KeyPolicy::Pair(pair) => {
                // Resolve every phase-owned observation/report before the first
                // registry insertion. An incomplete pair must not publish one
                // side while still discovering a missing owner on the other.
                let public_attributes = pair.public_attributes.as_ref().ok_or(Error::Rejected(
                    crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::PairPublicObservationsAbsent,
                    ),
                ))?;
                let public_properties = pair.public_properties.take().ok_or(Error::Rejected(
                    crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::PublicObjectAdmissionReportAbsent,
                    ),
                ))?;
                let private_properties = self.object_report.take().ok_or(Error::Rejected(
                    crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::ObjectAdmissionReportAbsent,
                    ),
                ))?;
                let public_allowed = pair.public_allowed.take().ok_or(Error::Rejected(
                    crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::PublicMechanismAdmissionReportAbsent,
                    ),
                ))?;
                let private_allowed = self.mechanism_report.take().ok_or(Error::Rejected(
                    crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::MechanismAdmissionReportAbsent,
                    ),
                ))?;
                let mut public = session.observed_public_key_reference(
                    s,
                    pair.public_handle,
                    public_attributes,
                    pair.prepared.key_type(),
                    public_properties,
                    self.observation_authentication,
                    self.publication
                        .as_ref()
                        .and_then(|value| value.identity(0)),
                    self.permit.permit()?,
                )?;
                public.search_report = pair.public_search.take();
                let mut private = session.observed_private_key_reference(
                    s,
                    self.found[0],
                    attrs,
                    pair.prepared.key_type(),
                    private_properties,
                    self.observation_authentication,
                    self.publication
                        .as_ref()
                        .and_then(|value| value.identity(1)),
                    self.permit.permit()?,
                )?;
                private.search_report = self.search_report.take();
                if let Some(destinations) = &mut self.destinations {
                    public = destinations.take(0)?.attach(session, public)?;
                    private = destinations.take(1)?.attach(session, private)?;
                }
                pair.prepared
                    .finish(public, private, public_allowed, private_allowed)
            }
        }
    }
}
