// SPDX-License-Identifier: Apache-2.0
//! Post-creation observation for opaque symmetric and HKDF results.
//!
//! Each snapshot is the result of an explicit native read. Fe11 retains it
//! without comparing it to a prior snapshot or a protection expectation.
use super::{observation, *};
use crate::{
    attributes::owned::resident::{LegacyOwner, ReadStorage, Recipe, ValueNeed},
    session::{observation_protection::ObservationProtection, SessionAccess},
    symmetric::memory::Credit,
    MechanismObservationPlan, MechanismObservationReport, Session,
};

#[derive(Clone, Copy)]
enum OutputKind {
    Symmetric,
    Hkdf,
}
#[derive(Clone, Copy)]
pub(crate) struct Spec<'a> {
    key: observation::Spec,
    mechanisms: &'a MechanismObservationPlan,
    kind: OutputKind,
}
impl<'a> Spec<'a> {
    pub(crate) fn symmetric(spec: &'a crate::SymmetricKeySpec) -> Self {
        Self {
            key: observation::Spec {
                identity: observation::Identity::Symmetric {
                    algorithm: spec.algorithm,
                    hmac: spec.hmac_key_type,
                },
                maximum: spec.admission.metadata.maximum_bytes,
                history: spec.history,
            },
            mechanisms: &spec.mechanisms,
            kind: OutputKind::Symmetric,
        }
    }
    pub(crate) fn hkdf(spec: &'a HkdfKeySpec, history: HistoryObservationPlan) -> Self {
        Self {
            key: observation::Spec {
                identity: observation::Identity::Hkdf {
                    kind: spec.kind,
                    length: spec.length,
                },
                maximum: spec.admission.metadata.maximum_bytes,
                history,
            },
            mechanisms: &spec.mechanisms,
            kind: OutputKind::Hkdf,
        }
    }
}
pub(crate) enum Evidence {
    Symmetric {
        protection: crate::SymmetricProtection,
        mechanisms: MechanismObservationReport,
    },
    Hkdf {
        protection: BaseProtection,

        mechanisms: MechanismObservationReport,
    },
}
fn mechanism_recipe(selection: &MechanismObservationPlan) -> Option<Recipe<'static>> {
    match *selection {
        MechanismObservationPlan::NotRequested => None,
        MechanismObservationPlan::Read { maximum_bytes } => Some(Recipe::Precise {
            field: CKA_ALLOWED_MECHANISMS,
            maximum: maximum_bytes,
        }),
    }
}
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b)
        .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
            crate::KeyDerivationRejection::DerivedOutputObservationStorageSize,
        )))
}
pub(crate) struct Initial {
    snapshot: observation::Initial,
    mechanisms: Option<ReadStorage>,
    selection: MechanismObservationPlan,
    kind: OutputKind,
}
impl Initial {
    pub(crate) fn requested(spec: Spec<'_>) -> Result<usize> {
        add(
            add(
                std::mem::size_of::<Owner>(),
                observation::Initial::requested(spec.key)?,
            )?,
            mechanism_recipe(spec.mechanisms)
                .map(ReadStorage::requested)
                .transpose()?
                .unwrap_or(0),
        )
    }
    pub(crate) fn allocate(spec: Spec<'_>) -> Result<Self> {
        Ok(Self {
            snapshot: observation::Initial::allocate(spec.key)?,
            mechanisms: mechanism_recipe(spec.mechanisms)
                .map(ReadStorage::allocate)
                .transpose()?,
            selection: spec.mechanisms.clone(),
            kind: spec.kind,
        })
    }
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        add(
            add(
                std::mem::size_of::<Owner>(),
                self.snapshot.allocated_bytes()?,
            )?,
            self.mechanisms
                .as_ref()
                .map(ReadStorage::allocated_bytes)
                .transpose()?
                .unwrap_or(0),
        )
    }
    pub(crate) fn bind(
        self,
        handle: CK_OBJECT_HANDLE,
        epoch: u64,

        protection: ObservationProtection,
        prepaid: &mut Credit,
    ) -> Result<Owner> {
        // A later protection/snapshot bind can fail while the deferred
        // mechanism-read storage still exists. Move it into a scope that ends
        // before its split credit, including on those partial failures.
        let future;
        let storage = self;
        let credit = prepaid.split(std::mem::size_of::<Owner>())?;
        future = prepaid.split(
            storage
                .mechanisms
                .as_ref()
                .map(ReadStorage::allocated_bytes)
                .transpose()?
                .unwrap_or(0),
        )?;
        let snapshot = storage
            .snapshot
            .bind(handle, epoch, protection.duplicate()?, prepaid)?;
        Ok(Owner {
            phase: Phase::Snapshot(Box::new(snapshot)),
            mechanisms: storage.mechanisms,
            selection: storage.selection,
            kind: storage.kind,
            handle,
            epoch,

            protection,
            prepaid: future,
            _credit: credit,
        })
    }
}
enum Phase {
    Snapshot(Box<observation::Owner>),
    Mechanisms {
        snapshot: BaseProtection,

        read: LegacyOwner,
    },
    Complete(Evidence),
    Stopped,
}
pub(crate) struct Owner {
    phase: Phase,
    mechanisms: Option<ReadStorage>,
    selection: MechanismObservationPlan,
    kind: OutputKind,
    handle: CK_OBJECT_HANDLE,
    epoch: u64,

    protection: ObservationProtection,
    prepaid: Credit,
    _credit: Credit,
}
impl Owner {
    pub(crate) fn pending(&self) -> bool {
        match &self.phase {
            Phase::Snapshot(read) => read.pending(),
            Phase::Mechanisms { read, .. } => read.pending(),
            _ => false,
        }
    }
    pub(crate) fn complete(&self) -> bool {
        matches!(self.phase, Phase::Complete(_))
    }
    pub(crate) fn need(&self) -> Option<ValueNeed> {
        match &self.phase {
            Phase::Snapshot(read) => read.need(),
            Phase::Mechanisms { read, .. } => read.need(),
            _ => None,
        }
    }
    pub(crate) fn attach(
        &mut self,
        need: ValueNeed,
        value: crate::attributes::owned::resident::ValueCandidate,
    ) -> Result<()> {
        match &mut self.phase {
            Phase::Snapshot(read) => read.attach(need, value),
            Phase::Mechanisms { read, .. } => read.attach(need, value),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::DerivedOutputAttachmentPhase,
            ))),
        }
    }
    fn finish(&self, snapshot: BaseProtection, mechanisms: MechanismObservationReport) -> Phase {
        Phase::Complete(match self.kind {
            OutputKind::Symmetric => Evidence::Symmetric {
                protection: crate::symmetric::keys::protection_snapshot(
                    snapshot,
                    crate::GenerationInvocation::NotGeneratedByThisCall,
                ),
                mechanisms,
            },
            OutputKind::Hkdf => Evidence::Hkdf {
                protection: snapshot,
                mechanisms,
            },
        })
    }
    pub(crate) fn advance(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        session
            .snapshot
            .check_authentication_unchanged(self.epoch)?;
        session.entry(access)?;
        loop {
            match &mut self.phase {
                Phase::Snapshot(read) => {
                    read.advance(session, access)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Mechanisms { read, .. } => {
                    read.advance(session, access, self.handle)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Complete(_) => return Ok(()),
                Phase::Stopped => {
                    return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                        crate::KeyDerivationRejection::DerivedOutputObservationStopped,
                    )))
                }
            }
            self.phase = match std::mem::replace(&mut self.phase, Phase::Stopped) {
                Phase::Snapshot(read) => {
                    let snapshot = read.result()?;

                    match self.mechanisms.take() {
                        Some(storage) => {
                            let recipe = mechanism_recipe(&self.selection).ok_or(
                                Error::Rejected(crate::RejectionReason::KeyDerivation(
                                    crate::KeyDerivationRejection::DerivedMechanismRecipeAbsent,
                                )),
                            )?;
                            let read = storage.bind_with_protection(
                                &mut self.prepaid,
                                recipe,
                                self.handle,
                                Some(self.epoch),
                                self.protection.duplicate()?,
                            )?;
                            Phase::Mechanisms { snapshot, read }
                        }
                        None => {
                            self.finish(snapshot, self.selection.record(Observation::NotRequested)?)
                        }
                    }
                }
                Phase::Mechanisms { snapshot, read } => {
                    let observed = read.precise_result(session, access)?;
                    self.finish(snapshot, self.selection.record_owned(observed)?)
                }
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                        crate::KeyDerivationRejection::DerivedOutputTransition,
                    )))
                }
            };
        }
    }
    pub(crate) fn result(self) -> Result<Evidence> {
        match self.phase {
            Phase::Complete(evidence) => Ok(evidence),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::DerivedOutputIncomplete,
            ))),
        }
    }
}
