// SPDX-License-Identifier: Apache-2.0
//! Interpret returned searches, creation and attribute observations.
//! Completion publishes owned results or preserves the exact failure and cleanup owner.

use super::*;

// A completed Final failure is terminal in finish_terminal. Consume the stored
// collection cause only there; pre-dispatch waits/refusals leave it installed
// for continuation. With no earlier refusal, retain the exact Final error.
pub(super) fn search_final_failure(
    primary: &mut Option<Error>,
    storage: &mut Option<crate::error::CleanupDiagnostic>,
    failure: Error,
) -> Error {
    let Some(cause) = primary.take() else {
        return failure;
    };
    let mut diagnostic = storage.take().expect("prepared search cleanup diagnostic");
    diagnostic.replace_operation(cause);
    diagnostic.finish_sequence(Some(failure))
}

impl Admission {
    pub(in crate::advanced) fn complete(&self) -> bool {
        self.stage == Stage::Done
    }

    /// Accept a completed response after any dynamically discovered capacity
    /// has been prepared outside coordination guards. The original response
    /// and its credits stay installed; this phase never repeats the native read.
    pub(super) fn accept_required(&mut self) -> Result<()> {
        let attrs = self.attributes.as_ref().ok_or(Error::Rejected(
            crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AttributeFrameAbsent,
            ),
        ))?;
        match self.frames.policy_mut() {
            KeyPolicy::DerivationBase(p) => p.validate(&attrs)?,
            KeyPolicy::Symmetric { spec, .. } => keys::validate_required(&attrs, spec)?,
            KeyPolicy::VerificationPublic { prepared, .. } => prepared.validate_identity(&attrs)?,
            KeyPolicy::Pair(pair) => pair.prepared.validate(pair.private, &attrs)?,
        }
        if matches!(self.frames.policy(), KeyPolicy::VerificationPublic { prepared } if prepared.needs_material_observation())
        {
            self.next_read(Stage::PublicMaterial)?;
            return Ok(());
        }
        if let KeyPolicy::Pair(pair) = self.frames.policy() {
            if !pair.private {
                if pair.prepared.public_material_field().is_some() {
                    // The preceding structural read established
                    // the public class before any CKA_VALUE request.
                    self.next_read(Stage::PublicMaterial)?;
                    return Ok(());
                }
            }
        }
        if let Some(plan) = self.frames.policy().history_plan() {
            if plan.field_iter().next().is_none() {
                let observed = crate::attributes::ObservedAttributes::empty();
                self.retain_history_observation(crate::crypto::derivation::history::snapshot(
                    plan, &observed,
                ))?;
            } else {
                self.next_read(Stage::History)?;
            }
        } else {
            self.start_mechanism_observation()?;
        }
        Ok(())
    }

    pub(super) fn finish(&mut self, s: &State, entry: &SessionEntry, rv: CK_RV) -> Result<()> {
        match self.stage {
            Stage::RequiredLocal { .. } => self.accept_required()?,
            Stage::Generate => {
                let handle = self.generation.as_mut().unwrap().generated(s, entry, rv)?;
                self.publication
                    .as_mut()
                    .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::GenerationPublicationAbsent,
                    )))?
                    .publish(
                        s,
                        entry,
                        self.generation.as_ref().unwrap().handles(),
                        self.permit.permit()?,
                    )?;
                entry.snapshot.check()?;

                self.found.clear();
                self.found.push(handle);
                self.next_read(Stage::Required)?;
            }
            Stage::Destroy => {
                if let Some(cause) = self.generation.as_mut().unwrap().cleaned(s, entry, rv) {
                    self.failure = Some(cause);
                    self.stage = Stage::Done;
                }
            }
            Stage::Init => {
                check(rv, "C_FindObjectsInit", false)?;
                self.stage = Stage::Find;
            }
            Stage::Find => {
                check(rv, "C_FindObjects", false)?;
                let count = match self.frames.search().native.acceptance {
                    SearchAcceptance::Prepared {
                        rv: returned,
                        count,
                    } if returned == rv => count,
                    SearchAcceptance::Native => bounds::final_length(
                        *self.frames.search().native.count,
                        self.frames.search().native.handles.len(),
                    )?,
                    _ => {
                        return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                            crate::KeyAdmissionRejection::SearchResponseAcceptanceChanged,
                        )))
                    }
                };
                let search = self.frames.search_mut();
                let batch = &mut search.native.handles[..count];
                let result = match search.collection.preparation_need(batch) {
                    Ok(Some(need)) => {
                        search.native.acceptance = SearchAcceptance::Preparing { rv, count, need };
                        return Ok(());
                    }
                    Ok(None) => search.collection.append_prepared(batch),
                    Err(error) => Err(error),
                };
                self.frames.search_mut().native.acceptance = SearchAcceptance::Native;
                match result {
                    Ok(()) => {
                        if count == 0 {
                            self.stage = Stage::Final;
                        }
                    }
                    Err(managed::search::CollectionError::Malformed) => {
                        return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                            crate::KeyAdmissionRejection::InvalidOrRepeatedObjectHandle,
                        )));
                    }
                    Err(managed::search::CollectionError::Local(cause)) => {
                        // A selected resource refusal does not terminate Find.
                        // Complete Final first; preserve both causes if Final refuses.
                        self.failure = Some(cause);
                        self.stage = Stage::Final;
                    }
                }
            }
            Stage::Final => {
                check(rv, "C_FindObjectsFinal", false)?;
                if self.failure.is_some() {
                    self.stage = Stage::Done;
                    return Ok(());
                }
                self.found.clear();
                if let Some(destinations) = &mut self.destinations {
                    let result =
                        destinations.finish(self.frames.search().collection.handles().len());
                    self.frames.search_mut().collection.clear();
                    if let Err(cause) = result {
                        self.failure = Some(cause);
                        self.stage = Stage::Done;
                        return Ok(());
                    }
                    let search = self.frames.search_mut();
                    self.stage =
                        if destinations.activate(&mut search.native, &mut search.collection)? {
                            Stage::Init
                        } else {
                            Stage::Generate
                        };
                    return Ok(());
                }
                if self.generation.is_none() {
                    match self
                        .frames
                        .policy()
                        .object_admission()
                        .selection
                        .select(self.frames.search().collection.handles())
                    {
                        Ok((handle, report)) => {
                            self.found.push(handle);
                            self.search_report = Some(report);
                        }
                        Err(cause) => {
                            self.frames.search_mut().collection.clear();
                            self.failure = Some(cause);
                            self.stage = Stage::Done;
                            return Ok(());
                        }
                    }
                }

                // Search outputs no longer own any native pointer after Final.
                // Keep only the selected handle(s), release storage and credit.
                self.frames.search_mut().collection.clear();
                if self.found.len() != 1 {
                    self.stage = Stage::Done;
                } else {
                    self.next_read(Stage::Required)?;
                }
            }
            Stage::Required
            | Stage::PublicMaterial
            | Stage::History
            | Stage::Allowed
            | Stage::Properties => {
                let read = self
                    .frames
                    .read_mut()
                    .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::AttributeFrameAbsent,
                    )))?
                    .active_mut()?;
                if !read.complete() {
                    read.accept(rv)?;
                }
                if !read.complete() {
                    return Ok(());
                }
                let values = read.take()?;
                // The snapshot owns both payload and table credit across phases.
                match self.stage {
                    Stage::Required => {
                        let attrs = values.require_all()?;
                        if let KeyPolicy::Pair(pair) = self.frames.policy_mut() {
                            pair.prepared.prepare_observation(pair.private, &attrs)?;
                        }
                        self.attributes = Some(attrs);
                        self.stage = Stage::RequiredLocal { rv };
                    }
                    Stage::PublicMaterial => {
                        let attrs = values.require_all()?;
                        match self.frames.policy_mut() {
                            KeyPolicy::VerificationPublic { prepared, .. } => {
                                prepared.validate_material(&attrs)?
                            }
                            KeyPolicy::Pair(pair) => {
                                if pair.private {
                                    return Err(Error::Rejected(
                                        crate::RejectionReason::KeyAdmission(crate::KeyAdmissionRejection::PrivateMaterialReadIsNotAnAdmission),
                                    ));
                                }
                                pair.prepared.observe_public(&attrs)?;
                            }
                            _ => {
                                return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                                    crate::KeyAdmissionRejection::PublicMaterialOwnerAbsent,
                                )))
                            }
                        }
                        self.start_mechanism_observation()?;
                    }
                    Stage::History => {
                        let observed = values;
                        let plan = self.frames.policy().history_plan().ok_or(Error::Rejected(
                            crate::RejectionReason::KeyAdmission(
                                crate::KeyAdmissionRejection::HistoryObservationOwnerAbsent,
                            ),
                        ))?;
                        let snapshot =
                            crate::crypto::derivation::history::snapshot(plan, &observed);
                        self.retain_history_observation(snapshot)?;
                    }
                    Stage::Allowed => {
                        let value = read.take_mechanisms(&values)?;
                        self.mechanism_report =
                            Some(self.frames.policy().mechanisms().record_owned(value)?);
                        self.start_object_observation()?;
                    }
                    Stage::Properties => {
                        let observations = values;
                        self.object_report = Some(
                            self.frames
                                .policy()
                                .object_admission()
                                .observe_owned(observations)?,
                        );
                        self.complete_object_observations()?;
                    }
                    _ => unreachable!(),
                }
            }

            _ => {
                return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::DuplicateAdmissionCompletion,
                )))
            }
        }
        Ok(())
    }

    pub(super) fn complete_object_observations(&mut self) -> Result<()> {
        // The report is the sole owner of UniqueId evidence and its credit.
        // Keep it through pair phases; identity getters borrow it after publication.
        self.object_report.as_ref().ok_or(Error::Rejected(
            crate::RejectionReason::KeyAdmission(crate::KeyAdmissionRejection::ObjectReportAbsent),
        ))?;
        self.stage = Stage::Done;
        self.after_object_observations()
    }

    pub(super) fn accept_async(&mut self, rv: CK_RV) -> Result<()> {
        if matches!(self.stage, Stage::Init | Stage::Final | Stage::Destroy) {
            return Ok(());
        }
        let result = &self.completion.result;
        if result.ulVersion != 0 {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AdmissionAsynchronousVersion,
            )));
        }
        // No result, stale capacity or object handle may be consumed on error.
        // Existing stage-specific failure/cleanup handling retains its scope.
        if rv != CKR_OK {
            return Ok(());
        }
        match self.stage {
            Stage::Generate => self
                .generation
                .as_mut()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::GenerationOwnerAbsent,
                )))?
                .accept_async(result),

            // Attribute arrays and find results retain their own descriptor and
            // count checks in finish; this is not a new Join output encoding.
            _ => Ok(()),
        }
    }

    /// A control-boundary failure retains its own frame and any independent
    /// creation uncertainty. Both diagnostics were reserved before dispatch.
    pub(super) fn return_boundary_failure(
        &mut self,
        s: &State,
        result: crate::native_return::protocol::ReturnCode,
        cause: Error,
    ) -> Error {
        s.native.mark_uncertain();
        self.stage = Stage::Failed;
        self.pending = true;
        let cause = if result.code() == CKR_OK {
            cause
        } else {
            self.return_diagnostic
                .take()
                .expect("one terminal admission boundary failure")
                .bind(result.function())
                .boundary_failure(result.code(), cause)
        };
        if let Some(generation) = &mut self.generation {
            generation.completion_failure(cause)
        } else {
            cause
        }
    }

    pub(in crate::advanced) fn take_retirement_diagnostic(
        &mut self,
    ) -> Option<crate::error::CleanupDiagnostic> {
        self.retirement_diagnostic.take()
    }
}
