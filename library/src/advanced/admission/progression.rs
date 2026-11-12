// SPDX-License-Identifier: Apache-2.0
//! Drive key admission through search, generation and observation phases.
//! Native return handling decides which state and cleanup authority survive.

use super::*;

impl Stage {
    pub(super) fn check_detachment(self) -> Result<()> {
        // Attached searches retain their owner; transferring that owner is refused.
        if self == Self::Find {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::ObjectSearchDetachmentDeferred,
            )));
        }
        if matches!(
            self,
            Self::Required
                | Self::RequiredLocal { .. }
                | Self::PublicMaterial
                | Self::History
                | Self::Allowed
                | Self::Properties
        ) {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AttributeReadDetachmentDeferred,
            )));
        }
        Ok(())
    }
}

impl Admission {
    pub(in crate::advanced) fn drive(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        observe: bool,
        remaining: &mut usize,
    ) -> Result<()> {
        if self.stage == Stage::Failed {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AdmissionFailedExplicitCleanupRequired,
            )));
        }
        loop {
            if self.stage == Stage::Find && !self.pending {
                if let SearchAcceptance::Prepared { rv, .. } =
                    self.frames.search().native.acceptance
                {
                    self.finish_terminal(s, entry, rv, "C_FindObjects")?;
                    continue;
                }
            }
            if self.resource_need().is_some() {
                return Ok(());
            }
            if let Stage::RequiredLocal { rv } = self.stage {
                self.finish_terminal(s, entry, rv, "C_GetAttributeValue")?;
                continue;
            }
            // A completed native response is not a new dispatch or observation.
            // Resume its local acceptance without spending pacing again.
            if self.reading_attributes() && !self.pending {
                if let Some(rv) = self.frames.read().and_then(ReadOwner::completed_rv) {
                    self.finish_terminal(s, entry, rv, "C_GetAttributeValue")?;
                    continue;
                }
                if self.resource_need().is_some() {
                    return Ok(());
                }
            }
            if self.complete() || self.pending && !observe || !spend(remaining) {
                return Ok(());
            }
            {
                if let Err(cause) = entry
                    .snapshot
                    .check_authentication_unchanged(self.observation_authentication)
                {
                    // A changed local epoch is not native completion. Retain an
                    // outstanding frame/search for explicit cancellation or close.
                    if self.pending || self.active_categories() != 0 || self.generation.is_none() {
                        return Err(cause);
                    }
                    if !matches!(self.stage, Stage::Destroy | Stage::Done) {
                        self.creation_failure(s, entry, cause);
                        continue;
                    }
                }
            }
            if s.native.is_uncertain() {
                return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::NativeStateUncertain,
                )));
            }
            if self.generation.is_none()
                && self.close_epoch != entry.snapshot.domain.close_epoch.load(Ordering::Acquire)
                && !self.pending
            {
                // A pending output frame remains owned until completion. An
                // active search is finalized without consuming another handle.
                // Never dispatch a new handle-using step after a possible close.
                if matches!(self.stage, Stage::Find | Stage::Final) {
                    self.stage = Stage::Final;
                } else if self.active_categories() != 0 {
                    return Err(Error::Rejected(
                        crate::RejectionReason::KeyAdmission(crate::KeyAdmissionRejection::SessionCloseDuringAdmissionExplicitCleanupRequired),
                    ));
                } else {
                    self.failure = Some(Error::Rejected(crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::SessionCloseDuringAdmissionRediscover,
                    )));
                    self.stage = Stage::Done;
                    return Ok(());
                }
            }
            if self.stage == Stage::Init && !self.pending {
                entry.recovery.observations.check_search_available()?;
            }
            let name = self.function()?;
            let rv = if self.pending {
                let call =
                    s.native
                        .asynchronous
                        .and_then(|f| f.complete)
                        .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                            crate::SessionLifecycleRejection::CAsyncCompleteUnavailable,
                        )))?;
                self.completion.name.fill(0);
                self.completion.name[..name.len()].copy_from_slice(name.as_bytes());
                let output = if matches!(self.stage, Stage::Init | Stage::Final | Stage::Destroy) {
                    std::ptr::null_mut()
                } else {
                    &mut *self.completion.result
                };
                s.native.record("C_AsyncComplete")?;
                self.dispatched = true;
                // SAFETY: native output descriptors/counts and completion storage
                // remain in the installed frame. Never dereference result.pValue.
                unsafe { call(entry.handle, self.completion.name.as_mut_ptr(), output) }
            } else {
                if self.stage == Stage::Find {
                    *self.frames.search_mut().native.count = CK_UNAVAILABLE_INFORMATION;
                }
                // SAFETY: all search/policy allocations are owned and stable;
                // count is bounded, and no secret key value attribute is selected.
                unsafe {
                    match self.stage {
                        Stage::Generate | Stage::Destroy => match self
                            .generation
                            .as_mut()
                            .unwrap()
                            .dispatch(s, entry, self.stage)
                        {
                            Ok(rv) => rv,
                            Err(cause) => {
                                self.failure = Some(if self.stage == Stage::Destroy {
                                    self.generation
                                        .as_mut()
                                        .unwrap()
                                        .cleanup_dispatch_failed(s, cause)
                                } else {
                                    cause
                                });
                                self.stage = Stage::Done;
                                return Ok(());
                            }
                        },
                        Stage::Init => {
                            let call = crate::native::functions::resolve(
                                s.native.table.C_FindObjectsInit,
                                "C_FindObjectsInit",
                            )?;
                            let search = &mut self.frames.search_mut().native;
                            let attrs = search.attrs.as_mut_ptr();
                            let count = search.attrs.len() as CK_ULONG;
                            s.native.record(name)?;
                            self.dispatched = true;
                            call(entry.handle, attrs, count)
                        }
                        Stage::Find => {
                            let call = crate::native::functions::resolve(
                                s.native.table.C_FindObjects,
                                "C_FindObjects",
                            )?;
                            let search = &mut self.frames.search_mut().native;
                            let handles = search.handles.as_mut_ptr();
                            let capacity = search.handles.len() as CK_ULONG;
                            let count = &mut *search.count;
                            s.native.record(name)?;
                            self.dispatched = true;
                            call(entry.handle, handles, capacity, count)
                        }
                        Stage::Final => {
                            let call = crate::native::functions::resolve(
                                s.native.table.C_FindObjectsFinal,
                                "C_FindObjectsFinal",
                            )?;
                            s.native.record(name)?;
                            self.dispatched = true;
                            call(entry.handle)
                        }

                        _ => {
                            let call = crate::native::functions::resolve(
                                s.native.table.C_GetAttributeValue,
                                "C_GetAttributeValue",
                            )?;
                            let read = self.frames.read_mut().unwrap().active_mut()?;
                            let attrs = read.attrs.as_mut_ptr();
                            let count = read.attrs.len() as CK_ULONG;
                            s.native.record(name)?;
                            self.dispatched = true;
                            call(entry.handle, self.found[0], attrs, count)
                        }
                    }
                }
            };
            use crate::native_return::protocol::PendingInspection;
            let observe_context = |_| {
                if rv != CKR_PENDING {
                    s.apply_session_failure(
                        entry,
                        rv,
                        if name == "C_GetAttributeValue" {
                            crate::native_return::attribute_scope(rv)
                        } else if matches!(self.stage, Stage::Generate | Stage::Destroy) {
                            crate::native_return::native_context_scope(rv)
                        } else {
                            crate::native_return::failure_scope(rv)
                        },
                    );
                }
            };
            let returned = if self.pending {
                s.native.observe_async_return(rv);
                PendingInspection::completed(name, rv, observe_context)
            } else {
                PendingInspection::returned(name, rv, observe_context)
            };
            let result = returned
                .inspect(|| {
                    // The control returns the target's inputs independently of
                    // whether its result proves non-creation. Validate them
                    // before accept_async can project successful handles.
                    if self.stage == Stage::Generate {
                        self.generation
                            .as_mut()
                            .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                                crate::KeyAdmissionRejection::GenerationOwnerAbsent,
                            )))?
                            .inspect_returned_inputs()?;
                    }
                    if name == "C_GetAttributeValue" {
                        self.frames
                            .read_mut()
                            .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                                crate::KeyAdmissionRejection::AttributeFrameAbsent,
                            )))?
                            .active_mut()?
                            .validate_identity()?;
                    }
                    if self.pending {
                        self.accept_async(rv)?;
                    }
                    if rv == CKR_OK && self.stage == Stage::Find {
                        let search = &self.frames.search().native;
                        bounds::final_length(*search.count, search.handles.len())?;
                    }
                    Ok(())
                })
                .resolve(|result, cause| self.return_boundary_failure(s, result, cause))?;
            if rv == CKR_PENDING {
                self.pending = true;
                if entry.mode != AdvancedSessionMode::Asynchronous {
                    s.native.mark_uncertain();
                    return Err(Error::Native {
                        function: name,
                        code: rv as u64,
                        may_have_effect: true,
                    });
                }
                return Ok(());
            }
            if !result.memory_returned() {
                s.native.mark_uncertain();
                self.pending = true;
                self.stage = Stage::Failed;
                let cause = Error::Native {
                    function: name,
                    code: rv as u64,
                    may_have_effect: true,
                };
                return Err(if let Some(generation) = &mut self.generation {
                    generation.completion_failure(cause)
                } else {
                    cause
                });
            }
            self.pending = false;
            self.finish_terminal(s, entry, rv, name)?;
        }
    }
}
