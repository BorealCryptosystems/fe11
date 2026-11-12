// SPDX-License-Identifier: Apache-2.0
//! One object reader across caller-selected property and mechanism observations.
use super::*;
use crate::{
    attributes::owned::resident::{LegacyOwner, ReadStorage, Recipe, ValueNeed},
    session::{observation_protection::ObservationProtection, SessionAccess},
    symmetric::memory::Credit,
    ObjectAdmission, ObjectObservationReport, Session,
};

mod runner;
pub(crate) use runner::observe;

enum Phase {
    Properties(LegacyOwner),
    Mechanisms {
        properties: ObjectObservationReport,
        read: LegacyOwner,
    },
    Complete {
        properties: ObjectObservationReport,
        mechanisms: MechanismObservationReport,
    },
    Stopped,
}
pub(crate) struct PolicyOwner {
    phase: Phase,
    properties: ObjectAdmission,
    mechanisms: MechanismObservationPlan,
    future: Option<ReadStorage>,
    prepaid: Credit,
    protection: ObservationProtection,
    handle: CK_OBJECT_HANDLE,
    authentication: Option<u64>,
    _credit: Credit,
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
        .ok_or(Error::Rejected(crate::RejectionReason::Mechanisms(
            crate::MechanismsRejection::PolicyObservationStorageSize,
        )))
}
pub(crate) struct Initial {
    properties: Option<ReadStorage>,
    mechanisms: Option<ReadStorage>,
}
impl Initial {
    pub(crate) fn requested(
        properties: &ObjectAdmission,
        mechanisms: &MechanismObservationPlan,
    ) -> Result<usize> {
        Recipe::Controls(properties).validate()?;
        let mut bytes = std::mem::size_of::<PolicyOwner>();
        if Recipe::Controls(properties).len() != 0 {
            bytes = add(bytes, ReadStorage::requested(Recipe::Controls(properties))?)?;
        }
        if let Some(recipe) = mechanism_recipe(mechanisms) {
            bytes = add(bytes, ReadStorage::requested(recipe)?)?;
        }
        Ok(bytes)
    }
    pub(crate) fn allocate(
        properties: &ObjectAdmission,
        mechanisms: &MechanismObservationPlan,
    ) -> Result<Self> {
        let properties = if Recipe::Controls(properties).len() == 0 {
            None
        } else {
            Some(ReadStorage::allocate(Recipe::Controls(properties))?)
        };
        Ok(Self {
            properties,
            mechanisms: mechanism_recipe(mechanisms)
                .map(ReadStorage::allocate)
                .transpose()?,
        })
    }
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        let properties = self
            .properties
            .as_ref()
            .map(ReadStorage::allocated_bytes)
            .transpose()?
            .unwrap_or(0);
        let mechanisms = self
            .mechanisms
            .as_ref()
            .map(ReadStorage::allocated_bytes)
            .transpose()?
            .unwrap_or(0);
        add(
            add(std::mem::size_of::<PolicyOwner>(), properties)?,
            mechanisms,
        )
    }
    pub(crate) fn bind(
        self,
        properties: ObjectAdmission,
        mechanisms: MechanismObservationPlan,
        handle: CK_OBJECT_HANDLE,
        authentication: Option<u64>,
        protection: ObservationProtection,
        prepaid: &mut Credit,
    ) -> Result<PolicyOwner> {
        let credit = prepaid.split(std::mem::size_of::<PolicyOwner>())?;
        let phase = match self.properties {
            Some(storage) => Phase::Properties(storage.bind_with_protection(
                prepaid,
                Recipe::Controls(&properties),
                handle,
                authentication,
                protection.duplicate()?,
            )?),
            None => Phase::Stopped,
        };
        let future_bytes = self
            .mechanisms
            .as_ref()
            .map(ReadStorage::allocated_bytes)
            .transpose()?
            .unwrap_or(0);
        let mut owner = PolicyOwner {
            phase,
            properties,
            mechanisms,
            future: self.mechanisms,
            prepaid: prepaid.split(future_bytes)?,
            protection,
            handle,
            authentication,
            _credit: credit,
        };
        if matches!(owner.phase, Phase::Stopped) {
            let empty = owner
                .properties
                .observe_owned(crate::attributes::ObservedAttributes::empty())?;
            owner.phase = owner.mechanisms(empty)?;
        }
        Ok(owner)
    }
}
impl PolicyOwner {
    fn read(&self) -> Option<&LegacyOwner> {
        match &self.phase {
            Phase::Properties(read) | Phase::Mechanisms { read, .. } => Some(read),
            _ => None,
        }
    }
    pub(crate) fn pending(&self) -> bool {
        self.read().is_some_and(LegacyOwner::pending)
    }
    pub(crate) fn need(&self) -> Option<ValueNeed> {
        self.read().and_then(LegacyOwner::need)
    }
    pub(crate) fn complete(&self) -> bool {
        matches!(self.phase, Phase::Complete { .. })
    }
    pub(crate) fn attach(
        &mut self,
        need: ValueNeed,
        value: crate::attributes::owned::resident::ValueCandidate,
    ) -> Result<()> {
        match &mut self.phase {
            Phase::Properties(read) | Phase::Mechanisms { read, .. } => read.attach(need, value),
            _ => Err(Error::Rejected(crate::RejectionReason::Mechanisms(
                crate::MechanismsRejection::PolicyObservationPhase,
            ))),
        }
    }
    fn mechanisms(&mut self, properties: ObjectObservationReport) -> Result<Phase> {
        match self.future.take() {
            Some(storage) => {
                let recipe = mechanism_recipe(&self.mechanisms).ok_or(Error::Rejected(
                    crate::RejectionReason::Mechanisms(
                        crate::MechanismsRejection::PolicyMechanismRecipeAbsent,
                    ),
                ))?;
                Ok(Phase::Mechanisms {
                    properties,
                    read: storage.bind_with_protection(
                        &mut self.prepaid,
                        recipe,
                        self.handle,
                        self.authentication,
                        self.protection.duplicate()?,
                    )?,
                })
            }
            None => Ok(Phase::Complete {
                properties,
                mechanisms: self.mechanisms.record(crate::Observation::NotRequested)?,
            }),
        }
    }
    pub(crate) fn advance(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        handle: CK_OBJECT_HANDLE,
    ) -> Result<()> {
        if handle != self.handle {
            return Err(Error::Rejected(crate::RejectionReason::Mechanisms(
                crate::MechanismsRejection::PolicyObservationSourceChanged,
            )));
        }
        loop {
            match &mut self.phase {
                Phase::Properties(read) | Phase::Mechanisms { read, .. } => {
                    read.advance(session, access, handle)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Complete { .. } => return Ok(()),
                Phase::Stopped => {
                    return Err(Error::Rejected(crate::RejectionReason::Mechanisms(
                        crate::MechanismsRejection::PolicyObservationStopped,
                    )))
                }
            }
            self.phase = match std::mem::replace(&mut self.phase, Phase::Stopped) {
                Phase::Properties(read) => {
                    let properties =
                        read.object_observations_result(session, access, &self.properties)?;
                    self.mechanisms(properties)?
                }
                Phase::Mechanisms { properties, read } => Phase::Complete {
                    properties,
                    mechanisms: self
                        .mechanisms
                        .record_owned(read.precise_result(session, access)?)?,
                },
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::Mechanisms(
                        crate::MechanismsRejection::PolicyObservationCompletionPhase,
                    )))
                }
            };
        }
    }
    pub(crate) fn result<T>(
        mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        finish: impl FnOnce(ObjectObservationReport, MechanismObservationReport) -> Result<T>,
    ) -> Result<T> {
        let Phase::Complete {
            properties,
            mechanisms,
        } = std::mem::replace(&mut self.phase, Phase::Stopped)
        else {
            return Err(Error::Rejected(crate::RejectionReason::Mechanisms(
                crate::MechanismsRejection::PolicyObservationIncomplete,
            )));
        };
        // Keep the original reader through construction of this historical result.
        // Publication does not revalidate or renew the context that produced it.
        session.metadata_result(access, self.authentication, finish(properties, mechanisms))
    }
}
