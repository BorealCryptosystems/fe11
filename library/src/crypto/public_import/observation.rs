// SPDX-License-Identifier: Apache-2.0
//! Typed public-object conversion and explicitly selected mechanism observations.
//!
//! This child owns completed observations, while its parent retains the creation
//! ticket and destination reservation. A resource wait never repeats CreateObject.
use crate::{
    attributes::owned::resident::{LegacyOwner, ReadStorage, Recipe, ValueNeed},
    session::{observation_protection::ObservationProtection, SessionAccess},
    symmetric::memory::Credit,
    Error, MechanismObservationPlan, MechanismObservationReport, Result, Session,
};
use fe11_sys::*;
use std::mem::size_of;

#[derive(Clone, Copy)]
pub(crate) struct Spec<'a> {
    pub(crate) identity: &'a [(CK_ATTRIBUTE_TYPE, CK_ULONG)],
    pub(crate) maximum: usize,
    pub(crate) mechanisms: &'a MechanismObservationPlan,
}

struct Description {
    identity: Vec<(CK_ATTRIBUTE_TYPE, CK_ULONG)>,
    identity_fields: Vec<CK_ATTRIBUTE_TYPE>,
    maximum: usize,
    mechanisms: MechanismObservationPlan,
}
impl Description {
    fn bytes(&self) -> Result<usize> {
        let mut bytes = add(
            size_of::<Owner>(),
            self.identity
                .capacity()
                .checked_mul(size_of::<(CK_ATTRIBUTE_TYPE, CK_ULONG)>()),
        )?;

        bytes = add(
            bytes,
            self.identity_fields
                .capacity()
                .checked_mul(size_of::<CK_ATTRIBUTE_TYPE>()),
        )?;

        Ok(bytes)
    }
    fn identity_recipe(&self) -> Recipe<'_> {
        Recipe::Required {
            fields: &self.identity_fields,
            maximum: self.maximum,
        }
    }
}
fn add(bytes: usize, extra: Option<usize>) -> Result<usize> {
    extra
        .and_then(|extra| bytes.checked_add(extra))
        .ok_or(Error::Rejected(crate::RejectionReason::KeyEncoding(
            crate::KeyEncodingRejection::PublicImportObservationStorageSize,
        )))
}
fn copy<T: Clone>(source: &[T]) -> Result<Vec<T>> {
    let mut target = Vec::new();
    target.try_reserve_exact(source.len()).map_err(|_| {
        Error::Rejected(crate::RejectionReason::KeyEncoding(
            crate::KeyEncodingRejection::PublicImportObservationAllocation,
        ))
    })?;
    target.extend_from_slice(source);
    Ok(target)
}
fn mechanism_recipe(admission: &MechanismObservationPlan) -> Option<Recipe<'static>> {
    match *admission {
        MechanismObservationPlan::NotRequested => None,
        MechanismObservationPlan::Read { maximum_bytes } => Some(Recipe::Precise {
            field: CKA_ALLOWED_MECHANISMS,
            maximum: maximum_bytes,
        }),
    }
}

pub(crate) struct Initial {
    description: Description,
    identity: ReadStorage,
    mechanisms: Option<ReadStorage>,
}
impl Initial {
    /// Planning borrows the caller's public data. All owned candidates, including
    /// these copies, are dropped together if the allocator exceeds the reservation.
    pub(crate) fn requested(spec: Spec<'_>) -> Result<usize> {
        let mut bytes = add(
            size_of::<Owner>(),
            spec.identity
                .len()
                .checked_mul(size_of::<(CK_ATTRIBUTE_TYPE, CK_ULONG)>()),
        )?;

        bytes = add(
            bytes,
            spec.identity
                .len()
                .checked_mul(size_of::<CK_ATTRIBUTE_TYPE>()),
        )?;

        // ReadStorage depends on field cardinality, not field values. Its recipe
        // still validates and binds the actual distinct fields at allocation.
        bytes = add(
            bytes,
            Some(ReadStorage::requested_unique(spec.identity.len())?),
        )?;

        if let Some(recipe) = mechanism_recipe(spec.mechanisms) {
            bytes = add(bytes, Some(ReadStorage::requested(recipe)?))?;
        }
        Ok(bytes)
    }
    pub(crate) fn allocate(spec: Spec<'_>) -> Result<Self> {
        let description = Description {
            identity: copy(spec.identity)?,
            identity_fields: spec.identity.iter().map(|(field, _)| *field).collect(),
            maximum: spec.maximum,
            mechanisms: spec.mechanisms.clone(),
        };
        description.identity_recipe().validate()?;
        if description.identity.is_empty() {
            return Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
                crate::KeyEncodingRejection::PublicImportObservationFieldsAbsent,
            )));
        }
        Ok(Self {
            identity: ReadStorage::allocate(description.identity_recipe())?,
            mechanisms: mechanism_recipe(spec.mechanisms)
                .map(ReadStorage::allocate)
                .transpose()?,
            description,
        })
    }
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        let mut bytes = add(
            self.description.bytes()?,
            Some(self.identity.allocated_bytes()?),
        )?;
        if let Some(read) = &self.mechanisms {
            bytes = add(bytes, Some(read.allocated_bytes()?))?;
        }
        Ok(bytes)
    }
    pub(crate) fn bind(
        self,
        handle: CK_OBJECT_HANDLE,
        epoch: u64,
        protection: ObservationProtection,
        prepaid: &mut Credit,
    ) -> Result<Owner> {
        let credit = prepaid.split(self.description.bytes()?)?;
        let identity = self.identity.bind_with_protection(
            prepaid,
            self.description.identity_recipe(),
            handle,
            Some(epoch),
            protection.duplicate()?,
        )?;
        let future_bytes = self
            .mechanisms
            .as_ref()
            .map(ReadStorage::allocated_bytes)
            .transpose()?
            .unwrap_or(0);
        Ok(Owner {
            phase: Phase::Identity(identity),
            description: self.description,
            mechanisms: self.mechanisms,
            prepaid: prepaid.split(future_bytes)?,
            protection,
            handle,
            epoch,
            _credit: credit,
        })
    }
}
enum Phase {
    Identity(LegacyOwner),
    Mechanisms(LegacyOwner),
    Complete(MechanismObservationReport),
    Stopped,
}
pub(crate) struct Owner {
    phase: Phase,
    description: Description,
    mechanisms: Option<ReadStorage>,
    prepaid: Credit,
    protection: ObservationProtection,
    handle: CK_OBJECT_HANDLE,
    epoch: u64,
    _credit: Credit,
}
impl Owner {
    fn read(&self) -> Option<&LegacyOwner> {
        match &self.phase {
            Phase::Identity(read) | Phase::Mechanisms(read) => Some(read),
            _ => None,
        }
    }
    pub(crate) fn pending(&self) -> bool {
        self.read().is_some_and(LegacyOwner::pending)
    }
    pub(crate) fn complete(&self) -> bool {
        matches!(self.phase, Phase::Complete(_))
    }
    pub(crate) fn need(&self) -> Option<ValueNeed> {
        self.read().and_then(LegacyOwner::need)
    }
    pub(crate) fn attach(
        &mut self,
        need: ValueNeed,
        value: crate::attributes::owned::resident::ValueCandidate,
    ) -> Result<()> {
        match &mut self.phase {
            Phase::Identity(read) | Phase::Mechanisms(read) => read.attach(need, value),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
                crate::KeyEncodingRejection::PublicImportObservationPhase,
            ))),
        }
    }
    pub(crate) fn advance(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        loop {
            match &mut self.phase {
                Phase::Identity(read) | Phase::Mechanisms(read) => {
                    read.advance(session, access, self.handle)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Complete(_) => return Ok(()),
                Phase::Stopped => {
                    return Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
                        crate::KeyEncodingRejection::PublicImportObservationStopped,
                    )))
                }
            }
            self.phase = match std::mem::replace(&mut self.phase, Phase::Stopped) {
                Phase::Identity(read) => {
                    let identity = read.required_result(session, access)?;
                    for (field, expected) in &self.description.identity {
                        identity.integer(*field, *expected)?;
                    }
                    if let Some(read) = self.mechanisms.take() {
                        let recipe = mechanism_recipe(&self.description.mechanisms).ok_or(
                            Error::Rejected(crate::RejectionReason::KeyEncoding(
                                crate::KeyEncodingRejection::PublicImportMechanismRecipeAbsent,
                            )),
                        )?;
                        Phase::Mechanisms(read.bind_with_protection(
                            &mut self.prepaid,
                            recipe,
                            self.handle,
                            Some(self.epoch),
                            self.protection.duplicate()?,
                        )?)
                    } else {
                        Phase::Complete(
                            self.description
                                .mechanisms
                                .record(crate::Observation::NotRequested)?,
                        )
                    }
                }
                Phase::Mechanisms(read) => Phase::Complete(
                    self.description
                        .mechanisms
                        .record_owned(read.precise_result(session, access)?)?,
                ),
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
                        crate::KeyEncodingRejection::PublicImportObservationCompletionPhase,
                    )))
                }
            };
        }
    }
    pub(crate) fn result(self) -> Result<MechanismObservationReport> {
        match self.phase {
            Phase::Complete(report) => Ok(report),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
                crate::KeyEncodingRejection::PublicImportObservationIncomplete,
            ))),
        }
    }
}
