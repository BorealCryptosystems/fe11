// SPDX-License-Identifier: Apache-2.0
//! Private export retains secret output through its final identity/property reads.
use super::*;
use crate::{
    attributes::owned::resident::{LegacyOwner, ReadStorage, Recipe, ValueNeed},
    session::{
        observation_protection::ObservationProtection,
        recovery::observations::{context, Prepared, Waiting},
        SessionAccess,
    },
    symmetric::memory::{ControlledReservation, Credit},
};

enum Phase {
    Identity(LegacyOwner),
    Before {
        algorithm: PqcPrivateKeyAlgorithm,
        read: LegacyOwner,
    },
    NeedPrivate {
        algorithm: PqcPrivateKeyAlgorithm,
        before: crate::ObjectObservationReport,
    },
    Private {
        call: export::ExportCall,
        before: crate::ObjectObservationReport,
    },
    AfterIdentity {
        output: PqcPrivateExport,
        before: crate::ObjectObservationReport,
        read: LegacyOwner,
    },
    AfterProperties {
        output: PqcPrivateExport,
        before: crate::ObjectObservationReport,
        read: LegacyOwner,
    },
    Complete(PqcPrivateExport),
    Stopped,
}
struct FutureReads {
    before: Option<ReadStorage>,
    identity: Option<ReadStorage>,
    after: Option<ReadStorage>,
    credit: Credit,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Need {
    Metadata(ValueNeed),
    Private(PqcPrivateKeyAlgorithm),
}
pub(crate) struct PqcExportOwner {
    phase: Phase,
    future: FutureReads,
    admission: crate::ObjectAdmission,
    protection: ObservationProtection,
    epoch: u64,
    _credit: Credit,
}
impl PqcExportOwner {
    pub(crate) fn pending(&self) -> bool {
        match &self.phase {
            Phase::Identity(read)
            | Phase::Before { read, .. }
            | Phase::AfterIdentity { read, .. }
            | Phase::AfterProperties { read, .. } => read.pending(),
            // An uncertain private call retains its own duplicated proof in
            // NativeFrame. There is no second native continuation to poll here.
            _ => false,
        }
    }
    fn need(&self) -> Option<Need> {
        match &self.phase {
            Phase::Identity(read)
            | Phase::Before { read, .. }
            | Phase::AfterIdentity { read, .. }
            | Phase::AfterProperties { read, .. } => read.need().map(Need::Metadata),
            Phase::NeedPrivate { algorithm, .. } => Some(Need::Private(*algorithm)),
            _ => None,
        }
    }
    fn bind_properties(
        &mut self,
        storage: ReadStorage,
        handle: CK_OBJECT_HANDLE,
    ) -> Result<LegacyOwner> {
        storage.bind_with_protection(
            &mut self.future.credit,
            Recipe::Controls(&self.admission),
            handle,
            Some(self.epoch),
            self.protection.duplicate()?,
        )
    }
    fn empty_properties(&self) -> Result<crate::ObjectObservationReport> {
        self.admission
            .observe_owned(crate::attributes::ObservedAttributes::empty())
    }
    fn advance(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        handle: CK_OBJECT_HANDLE,
    ) -> Result<()> {
        context(session, Some(self.epoch), self.epoch)?;
        loop {
            match &mut self.phase {
                Phase::Identity(read)
                | Phase::Before { read, .. }
                | Phase::AfterIdentity { read, .. }
                | Phase::AfterProperties { read, .. } => {
                    read.advance(session, access, handle)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::NeedPrivate { .. } | Phase::Complete(_) => return Ok(()),
                Phase::Private { .. } => {}
                Phase::Stopped => {
                    return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                        crate::PostQuantumKeysRejection::PqcExportStopped,
                    )))
                }
            }
            self.phase = match std::mem::replace(&mut self.phase, Phase::Stopped) {
                Phase::Identity(read) => {
                    let algorithm = validate_exportable(&read.required_result(session, access)?)?;
                    if let Some(storage) = self.future.before.take() {
                        Phase::Before {
                            algorithm,
                            read: self.bind_properties(storage, handle)?,
                        }
                    } else {
                        Phase::NeedPrivate {
                            algorithm,
                            before: self.empty_properties()?,
                        }
                    }
                }
                Phase::Before { algorithm, read } => Phase::NeedPrivate {
                    algorithm,
                    before: read.object_observations_result(session, access, &self.admission)?,
                },
                Phase::Private { call, before } => {
                    let output = export::read_prepared(access, session, handle, call)?;
                    let storage = self.future.identity.take().ok_or(Error::Rejected(
                        crate::RejectionReason::PostQuantumKeys(
                            crate::PostQuantumKeysRejection::PqcExportIdentityPreparationAbsent,
                        ),
                    ))?;
                    let read = storage.bind_with_protection(
                        &mut self.future.credit,
                        identity_recipe(&self.admission),
                        handle,
                        Some(self.epoch),
                        self.protection.duplicate()?,
                    )?;
                    Phase::AfterIdentity {
                        output,
                        before,
                        read,
                    }
                }
                Phase::AfterIdentity {
                    mut output,
                    before,
                    read,
                } => {
                    if validate_exportable(&read.required_result(session, access)?)?
                        != output.algorithm
                    {
                        return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                            crate::PostQuantumKeysRejection::PqcPrivateIdentityChangedDuringExport,
                        )));
                    }
                    if let Some(storage) = self.future.after.take() {
                        Phase::AfterProperties {
                            output,
                            before,
                            read: self.bind_properties(storage, handle)?,
                        }
                    } else {
                        output.property_reports = Some((before, self.empty_properties()?));
                        Phase::Complete(output)
                    }
                }
                Phase::AfterProperties {
                    mut output,
                    before,
                    read,
                } => {
                    output.property_reports = Some((
                        before,
                        read.object_observations_result(session, access, &self.admission)?,
                    ));
                    Phase::Complete(output)
                }
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                        crate::PostQuantumKeysRejection::PqcExportCompletionPhase,
                    )))
                }
            };
        }
    }
    fn attach(&mut self, need: Need, candidate: Candidate) -> Result<()> {
        if self.need() != Some(need) {
            return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcExportContinuationChanged,
            )));
        }
        match (need, candidate) {
            (Need::Metadata(need), Candidate::Metadata(value)) => match &mut self.phase {
                Phase::Identity(read)
                | Phase::Before { read, .. }
                | Phase::AfterIdentity { read, .. }
                | Phase::AfterProperties { read, .. } => read.attach(need, value),
                _ => Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                    crate::PostQuantumKeysRejection::PqcExportMetadataPhase,
                ))),
            },
            (Need::Private(_), Candidate::Private(storage, mut credit)) => {
                let call = storage.bind(&mut credit, self.protection.duplicate()?)?;
                let Phase::NeedPrivate { before, .. } =
                    std::mem::replace(&mut self.phase, Phase::Stopped)
                else {
                    unreachable!("need checked");
                };
                self.phase = Phase::Private { call, before };
                Ok(())
            }
            _ => Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcExportCandidateKind,
            ))),
        }
    }
    fn result(
        self,
        session: &Session,
        access: &SessionAccess<'_>,
        key: &ManagedObjectRef,
    ) -> Result<PqcPrivateExport> {
        let Phase::Complete(output) = self.phase else {
            return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcExportIncomplete,
            )));
        };
        session.managed_handle(access, key)?;
        session.metadata_result(access, Some(self.epoch), Ok(output))
    }
}
fn identity_recipe(admission: &crate::ObjectAdmission) -> Recipe<'static> {
    Recipe::Required {
        fields: &[CKA_CLASS, CKA_KEY_TYPE, CKA_PARAMETER_SET],
        maximum: admission.metadata.maximum_bytes,
    }
}
enum Candidate {
    Metadata(crate::attributes::owned::resident::ValueCandidate),
    Private(export::Storage, Credit),
}
fn prepare(
    need: Need,
    encoding: PqcPrivateEncoding,
    policy: &crate::ResourceAdmission,
    waiter: &Waiting<'_>,
) -> Result<Candidate> {
    match need {
        Need::Metadata(need) => {
            crate::attributes::owned::resident::prepare_value(need, waiter.budget(), policy, || {
                waiter.check()
            })
            .map(Candidate::Metadata)
        }
        Need::Private(algorithm) => {
            let mut required = export::Storage::requested(algorithm, encoding)?;
            loop {
                let mut credit = match waiter.budget().reserve_controlled_retaining(
                    required,
                    crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
                    policy,
                    || {
                        waiter.check()?;
                        Ok(None::<()>)
                    },
                    || Ok(None),
                )? {
                    ControlledReservation::Acquired(credit) => credit,
                    ControlledReservation::Redirect(()) => unreachable!("no redirect requested"),
                };
                let storage = export::Storage::allocate(algorithm, encoding)?;
                let actual = storage.allocated_bytes()?;
                if actual > required {
                    drop(storage);
                    drop(credit);
                    required = actual;
                    continue;
                }
                credit.release(required - actual);
                return Ok(Candidate::Private(storage, credit));
            }
        }
    }
}
mod runner;
pub(super) use runner::export;
