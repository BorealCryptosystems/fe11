// SPDX-License-Identifier: Apache-2.0
//! Route joined native results back to their pending admission phase.
//! The required output capacity belongs to that phase, not to a generic key buffer.

use super::*;

impl Admission {
    pub(in crate::advanced) fn joined_capacity(&self) -> Result<Option<usize>> {
        self.check_detachment()?;
        if !self.pending {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AdmissionNotPending,
            )));
        }
        Ok(match self.stage {
            Stage::Init | Stage::Final | Stage::Generate | Stage::Destroy => None,

            // This private integration does not define a new encoding for
            // descriptor arrays or handles/counts after detachment.
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::JoinedAdmissionOutputContractUnresolved,
                )))
            }
        })
    }

    pub(in crate::advanced) fn accept_joined(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        result: super::super::asynchronous::JoinedResult,
    ) -> Result<()> {
        crate::native_return::protocol::PendingInspection::forwarded(result.observed)
            .inspect(|| {
                if self.stage == Stage::Generate {
                    self.generation
                        .as_mut()
                        .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                            crate::KeyAdmissionRejection::GenerationOwnerAbsent,
                        )))?
                        .inspect_returned_inputs()?;
                }
                Ok(())
            })
            .resolve(|observed, cause| self.return_boundary_failure(s, observed, cause))?;
        // Native context was already observed by JoinedCall. Search retains its
        // ordinary-refusal notification, independently of that context fact.
        if matches!(self.stage, Stage::Init | Stage::Final)
            && crate::native_return::native_context_scope(result.return_value)
                == crate::native_return::FailureScope::None
        {
            s.apply_failure_scope(
                &entry.snapshot,
                crate::native_return::failure_scope(result.return_value),
            );
        }
        self.joined_capacity()?;
        entry
            .snapshot
            .check_authentication_unchanged(self.observation_authentication)?;
        let name = self.function()?;
        let projected = (|| -> Result<CK_RV> {
            match self.stage {
                Stage::Generate => self
                    .generation
                    .as_mut()
                    .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::GenerationOwnerAbsent,
                    )))?
                    .accept_joined(result),

                Stage::Init | Stage::Final | Stage::Destroy => Ok(result.project(name, None)?.0),
                _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::JoinedAdmissionOutputContractUnresolved,
                ))),
            }
        })();
        let rv = match projected {
            Ok(rv) => rv,
            Err(cause) => {
                s.native.mark_uncertain();
                self.stage = Stage::Failed;
                return Err(if let Some(generation) = &mut self.generation {
                    generation.completion_failure(cause)
                } else {
                    cause
                });
            }
        };
        self.pending = false;
        self.finish_terminal(s, entry, rv, name)
    }
}
