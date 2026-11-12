// SPDX-License-Identifier: Apache-2.0
//! Expose the admission owner’s current work, retained objects and resource need.
//! These views describe local progression, not a fresh native observation.

use super::*;

impl Admission {
    pub(in crate::advanced) fn created_objects(
        &self,
        inner: &Arc<crate::module::Inner>,
    ) -> Result<Option<crate::CreatedObjectSet>> {
        self.publication
            .as_ref()
            .filter(|value| value.complete())
            .map(|value| value.objects(inner))
            .transpose()
    }

    pub(in crate::advanced) fn deferred_creation_failure(
        &mut self,
        session: &Session,
    ) -> Result<Option<OperationProgress>> {
        if self.failure.is_none()
            || !self
                .publication
                .as_ref()
                .is_some_and(|value| value.complete())
        {
            return Ok(None);
        }
        Ok(Some(OperationProgress::CreatedObjects(
            crate::CreatedObjects {
                objects: self
                    .publication
                    .as_ref()
                    .expect("published creation")
                    .objects(&session.inner)?,
                observation: Err(self
                    .failure
                    .take()
                    .expect("stored creation observation error")),
                remainder: None,
            },
        )))
    }

    pub(super) fn reset_search(&mut self) {
        let plan = self.frames.policy().object_admission().search;
        self.frames.activate_search();
        // Admission::new reserved the maximum of the immutable pair plans.
        self.frames
            .search_mut()
            .native
            .handles
            .resize(plan.batch_size.get(), CK_INVALID_HANDLE);
        self.frames.search_mut().collection.reset(plan);
        self.found.clear();
    }

    pub(in crate::advanced) fn pending(&self) -> bool {
        self.pending
    }

    pub(super) fn reading_attributes(&self) -> bool {
        matches!(
            self.stage,
            Stage::Required
                | Stage::PublicMaterial
                | Stage::History
                | Stage::Allowed
                | Stage::Properties
        )
    }

    pub(in crate::advanced) fn resource_budget(&self) -> &Arc<Budget> {
        self._metadata.budget()
    }

    pub(in crate::advanced) fn resource_need(&self) -> Option<ResourceNeed> {
        if self.pending {
            return None;
        }
        if self.stage == Stage::Find {
            if let SearchAcceptance::Preparing { need, .. } = self.frames.search().native.acceptance
            {
                return Some(ResourceNeed::Search(need));
            }
        }
        if matches!(self.stage, Stage::RequiredLocal { .. }) {
            if let KeyPolicy::Pair(pair) = self.frames.policy() {
                return pair
                    .prepared
                    .observation_need()
                    .map(ResourceNeed::PublicEncoding);
            }
        }
        if self.reading_attributes() {
            return self
                .frames
                .read()
                .and_then(ReadOwner::need)
                .map(ResourceNeed::Read);
        }
        None
    }

    pub(in crate::advanced) fn attach_resource(
        &mut self,
        candidate: ResourceCandidate,
    ) -> Result<()> {
        if self.pending {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AdmissionPreparationChanged,
            )));
        }
        match candidate {
            ResourceCandidate::PublicEncoding(candidate)
                if matches!(self.stage, Stage::RequiredLocal { .. }) =>
            {
                match self.frames.policy_mut() {
                    KeyPolicy::Pair(pair) => pair.prepared.attach_observation(candidate),
                    _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::AdmissionPreparationChanged,
                    ))),
                }
            }
            ResourceCandidate::Read(candidate) if self.reading_attributes() => self
                .frames
                .read_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::AttributeFrameAbsent,
                )))?
                .attach(candidate),
            ResourceCandidate::Search(candidate) if self.stage == Stage::Find => {
                let SearchAcceptance::Preparing { rv, count, need } =
                    self.frames.search().native.acceptance
                else {
                    return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::SearchPreparationChanged,
                    )));
                };
                if need != candidate.need() {
                    return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::SearchPreparationChanged,
                    )));
                }
                self.frames.search_mut().collection.attach(candidate)?;
                self.frames.search_mut().native.acceptance =
                    SearchAcceptance::Prepared { rv, count };
                Ok(())
            }
            _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AdmissionPreparationChanged,
            ))),
        }
    }

    pub(in crate::advanced) fn native_started(&self) -> bool {
        self.dispatched
            || self
                .generation
                .as_ref()
                .is_some_and(Generation::effect_possible)
    }

    pub(in crate::advanced) fn active_categories(&self) -> CK_FLAGS {
        if matches!(self.stage, Stage::Find | Stage::Final)
            || self.stage == Stage::Init && self.pending
        {
            CKF_FIND_OBJECTS
        } else if self
            .generation
            .as_ref()
            .is_some_and(Generation::storage_retained)
        {
            self.generation.as_ref().unwrap().category()
        } else {
            0
        }
    }

    pub(in crate::advanced) fn next_function(&self) -> Result<Option<&'static str>> {
        if matches!(self.stage, Stage::RequiredLocal { .. } | Stage::Done) {
            // Local validation may select another read or cleanup.
            // Reporting the completed C_GetAttributeValue here would falsely
            // suggest that the caller can authenticate or redispatch it.
            return Ok(None);
        }
        self.function().map(Some)
    }

    pub(in crate::advanced) fn function(&self) -> Result<&'static str> {
        self.frames.check_stage(self.stage)?;
        match self.stage {
            Stage::Generate => Ok(self
                .generation
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::GenerationOwnerAbsent,
                )))?
                .function()),
            Stage::Destroy => Ok("C_DestroyObject"),
            Stage::Init => Ok("C_FindObjectsInit"),
            Stage::Find => Ok("C_FindObjects"),
            Stage::Final => Ok("C_FindObjectsFinal"),
            Stage::Required
            | Stage::PublicMaterial
            | Stage::History
            | Stage::Allowed
            | Stage::Properties => Ok("C_GetAttributeValue"),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AdmissionNotActive,
            ))),
        }
    }

    pub(super) fn next_read(&mut self, stage: Stage) -> Result<()> {
        let read = self.read_plans.select(stage, self.frames.policy())?;
        self.frames.activate_read(read);
        self.stage = stage;
        Ok(())
    }

    pub(super) fn after_object_observations(&mut self) -> Result<()> {
        let KeyPolicy::Pair(pair) = self.frames.policy_mut() else {
            return Ok(());
        };
        if pair.private {
            if pair.public_handle == self.found[0] {
                return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::GeneratedPairHandles,
                )));
            }
            self.stage = Stage::Done;
            self.frames.idle();
        } else {
            pair.public_handle = self.found[0];
            pair.public_attributes = self.attributes.take();
            pair.public_allowed = self.mechanism_report.take();
            pair.public_properties = self.object_report.take();
            pair.public_search = self.search_report.take();
            pair.private = true;
            self.found.clear();
            if let Some(generation) = &self.generation {
                self.frames.idle();
                self.found.push(generation.private_handle());
                self.next_read(Stage::Required)?;
            } else {
                self.frames.activate_private_search()?;
                self.reset_search();
                self.stage = Stage::Init;
            }
        }
        Ok(())
    }

    pub(super) fn creation_failure(&mut self, s: &State, entry: &SessionEntry, cause: Error) {
        if self
            .publication
            .as_ref()
            .is_some_and(publication::Publication::complete)
        {
            self.failure = Some(cause);
            self.stage = Stage::Done;
            return;
        }
        match self
            .generation
            .as_mut()
            .unwrap()
            .begin_cleanup(s, entry, cause)
        {
            Ok(()) => self.stage = Stage::Destroy,
            Err(cause) => {
                self.failure = Some(cause);
                self.stage = Stage::Done;
            }
        }
    }
}
