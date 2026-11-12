// SPDX-License-Identifier: Apache-2.0
//! Structural key identity followed by explicitly selected public provenance.
//!
//! This owner never reads a private value. History and mechanism-list reads
//! are selected by the caller; unavailable attributes remain unavailable.
use crate::{
    attributes::owned::resident::{LegacyOwner, ReadStorage, Recipe, ValueNeed},
    session::{observation_protection::ObservationProtection, SessionAccess},
    symmetric::memory::Credit,
    Error, HistoryObservationPlan, MechanismObservationPlan, MechanismObservationReport, Result,
    Session, TransportProtection,
};
use fe11_sys::*;

#[derive(Clone, Copy)]
pub(crate) enum Order {
    HistoryThenMechanisms,
    MechanismsThenHistory,
}
#[derive(Clone, Copy)]
pub(crate) struct Introduction {
    pub(crate) origin: crate::IntroductionOrigin,
}
struct IntroductionSelection {
    origin: crate::IntroductionOrigin,
}
impl Introduction {
    fn owned(self) -> IntroductionSelection {
        IntroductionSelection {
            origin: self.origin,
        }
    }
}
#[derive(Clone, Copy)]
pub(crate) struct Spec<'a> {
    pub(crate) order: Order,
    pub(crate) introduction: Option<Introduction>,
    pub(crate) identity: &'a [(CK_ATTRIBUTE_TYPE, CK_ULONG)],
    pub(crate) maximum: usize,
    pub(crate) history: HistoryObservationPlan,
    pub(crate) mechanisms: Option<&'a MechanismObservationPlan>,
}
pub(crate) struct Evidence {
    pub(crate) introduction: Option<crate::IntroductionReport>,
    pub(crate) history: TransportProtection,
    pub(crate) mechanisms: Option<MechanismObservationReport>,
}
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b)
        .ok_or(Error::Rejected(crate::RejectionReason::KeyEncoding(
            crate::KeyEncodingRejection::KeyEvidenceStorageSize,
        )))
}
fn identity_bytes(count: usize) -> Result<usize> {
    count
        .checked_mul(std::mem::size_of::<(CK_ATTRIBUTE_TYPE, CK_ULONG)>())
        .ok_or(Error::Rejected(crate::RejectionReason::KeyEncoding(
            crate::KeyEncodingRejection::KeyEvidenceStorageSize,
        )))
}
fn field_bytes(count: usize) -> Result<usize> {
    count
        .checked_mul(std::mem::size_of::<CK_ATTRIBUTE_TYPE>())
        .ok_or(Error::Rejected(crate::RejectionReason::KeyEncoding(
            crate::KeyEncodingRejection::KeyEvidenceStorageSize,
        )))
}
fn mechanism_recipe(selection: Option<&MechanismObservationPlan>) -> Option<Recipe<'static>> {
    match *selection? {
        MechanismObservationPlan::NotRequested => None,
        MechanismObservationPlan::Read { maximum_bytes } => Some(Recipe::Precise {
            field: CKA_ALLOWED_MECHANISMS,
            maximum: maximum_bytes,
        }),
    }
}
pub(crate) struct Initial {
    order: Order,
    introduction: Option<IntroductionSelection>,
    maximum: usize,
    history_plan: HistoryObservationPlan,
    mechanism_plan: Option<MechanismObservationPlan>,
    expected: Vec<(CK_ATTRIBUTE_TYPE, CK_ULONG)>,
    fields: Vec<CK_ATTRIBUTE_TYPE>,
    identity: ReadStorage,
    history: Option<ReadStorage>,
    mechanisms: Option<ReadStorage>,
}
impl Initial {
    pub(crate) fn requested(spec: Spec<'_>) -> Result<usize> {
        let count = spec.identity.len();
        let mut bytes = add(
            std::mem::size_of::<Owner>(),
            identity_bytes(spec.identity.len())?,
        )?;
        bytes = add(bytes, field_bytes(count)?)?;
        bytes = add(bytes, ReadStorage::requested_unique(count)?)?;
        if Recipe::History(spec.history).len() != 0 {
            bytes = add(
                bytes,
                ReadStorage::requested(Recipe::History(spec.history))?,
            )?;
        }
        if let Some(recipe) = mechanism_recipe(spec.mechanisms) {
            bytes = add(bytes, ReadStorage::requested(recipe)?)?;
        }
        Ok(bytes)
    }
    pub(crate) fn allocate(spec: Spec<'_>) -> Result<Self> {
        let mut expected = Vec::new();
        expected
            .try_reserve_exact(spec.identity.len())
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::KeyEncoding(
                    crate::KeyEncodingRejection::KeyEvidenceAllocation,
                ))
            })?;
        expected.extend_from_slice(spec.identity);
        let mut fields = Vec::new();
        fields.try_reserve_exact(spec.identity.len()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyEncoding(
                crate::KeyEncodingRejection::KeyEvidenceAllocation,
            ))
        })?;
        fields.extend(spec.identity.iter().map(|(field, _)| *field));
        if fields.is_empty() {
            return Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
                crate::KeyEncodingRejection::KeyEvidenceIdentityAbsent,
            )));
        }
        let recipe = Recipe::Required {
            fields: &fields,
            maximum: spec.maximum,
        };
        recipe.validate()?;
        Ok(Self {
            order: spec.order,
            introduction: spec.introduction.map(Introduction::owned),
            maximum: spec.maximum,
            history_plan: spec.history,
            mechanism_plan: spec.mechanisms.cloned(),
            identity: ReadStorage::allocate(recipe)?,
            expected,
            fields,
            history: if Recipe::History(spec.history).len() == 0 {
                None
            } else {
                Some(ReadStorage::allocate(Recipe::History(spec.history))?)
            },
            mechanisms: mechanism_recipe(spec.mechanisms)
                .map(ReadStorage::allocate)
                .transpose()?,
        })
    }
    fn fixed_bytes(&self) -> Result<usize> {
        add(
            add(
                std::mem::size_of::<Owner>(),
                identity_bytes(self.expected.capacity())?,
            )?,
            field_bytes(self.fields.capacity())?,
        )
    }

    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        let mut bytes = add(self.fixed_bytes()?, self.identity.allocated_bytes()?)?;
        if let Some(read) = &self.history {
            bytes = add(bytes, read.allocated_bytes()?)?;
        }
        if let Some(read) = &self.mechanisms {
            bytes = add(bytes, read.allocated_bytes()?)?;
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
        let credit = prepaid.split(self.fixed_bytes()?)?;
        let identity = self.identity.bind_with_protection(
            prepaid,
            Recipe::Required {
                fields: &self.fields,
                maximum: self.maximum,
            },
            handle,
            Some(epoch),
            protection.duplicate()?,
        )?;
        let future_bytes = add(
            self.history
                .as_ref()
                .map(ReadStorage::allocated_bytes)
                .transpose()?
                .unwrap_or(0),
            self.mechanisms
                .as_ref()
                .map(ReadStorage::allocated_bytes)
                .transpose()?
                .unwrap_or(0),
        )?;
        Ok(Owner {
            order: self.order,
            introduction: self.introduction,
            phase: Phase::Identity(identity),
            expected: self.expected,
            _fields: self.fields,
            history: self.history_plan,
            mechanisms: self.mechanism_plan,
            future_history: self.history,
            future_mechanisms: self.mechanisms,
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
    HistoryFirst(LegacyOwner),
    MechanismsAfterHistory {
        history: TransportProtection,
        read: LegacyOwner,
    },
    MechanismsFirst(LegacyOwner),
    HistoryAfterMechanisms {
        mechanisms: Option<MechanismObservationReport>,
        read: LegacyOwner,
    },
    Complete(Evidence),
    Stopped,
}
pub(crate) struct Owner {
    phase: Phase,
    order: Order,
    introduction: Option<IntroductionSelection>,
    expected: Vec<(CK_ATTRIBUTE_TYPE, CK_ULONG)>,
    _fields: Vec<CK_ATTRIBUTE_TYPE>,
    history: HistoryObservationPlan,
    mechanisms: Option<MechanismObservationPlan>,
    future_history: Option<ReadStorage>,
    future_mechanisms: Option<ReadStorage>,
    prepaid: Credit,
    protection: ObservationProtection,
    handle: CK_OBJECT_HANDLE,
    epoch: u64,
    _credit: Credit,
}
impl Owner {
    /// Handle already bound to this observation owner; no native call.
    pub(crate) fn handle(&self) -> CK_OBJECT_HANDLE {
        self.handle
    }

    fn evaluate_mechanisms(
        &self,
        observation: crate::attributes::owned::resident::MechanismValues,
    ) -> Result<Option<MechanismObservationReport>> {
        self.mechanisms
            .as_ref()
            .map(|selection| selection.record_owned(observation))
            .transpose()
    }

    fn read(&self) -> Option<&LegacyOwner> {
        match &self.phase {
            Phase::Identity(read)
            | Phase::HistoryFirst(read)
            | Phase::MechanismsFirst(read)
            | Phase::MechanismsAfterHistory { read, .. }
            | Phase::HistoryAfterMechanisms { read, .. } => Some(read),
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
            Phase::Identity(read)
            | Phase::HistoryFirst(read)
            | Phase::MechanismsFirst(read)
            | Phase::MechanismsAfterHistory { read, .. }
            | Phase::HistoryAfterMechanisms { read, .. } => read.attach(need, value),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
                crate::KeyEncodingRejection::KeyEvidencePhase,
            ))),
        }
    }
    fn bind(&mut self, storage: ReadStorage, recipe: Recipe<'_>) -> Result<LegacyOwner> {
        storage.bind_with_protection(
            &mut self.prepaid,
            recipe,
            self.handle,
            Some(self.epoch),
            self.protection.duplicate()?,
        )
    }
    fn unobserved_history(&self) -> Result<TransportProtection> {
        let empty = crate::attributes::ObservedAttributes::empty();
        Ok(crate::crypto::derivation::history::snapshot(
            self.history,
            &empty,
        ))
    }
    fn finish(
        &self,
        history: TransportProtection,
        mechanisms: Option<MechanismObservationReport>,
    ) -> Result<Phase> {
        let introduction = self
            .introduction
            .as_ref()
            .map(|selection| crate::transport::secret_keys::report(history, selection.origin))
            .transpose()?;
        Ok(Phase::Complete(Evidence {
            introduction,
            history,
            mechanisms,
        }))
    }
    fn after_history(&mut self, history: TransportProtection) -> Result<Phase> {
        match self.future_mechanisms.take() {
            Some(storage) => {
                let recipe = mechanism_recipe(self.mechanisms.as_ref()).ok_or(Error::Rejected(
                    crate::RejectionReason::KeyEncoding(
                        crate::KeyEncodingRejection::KeyEvidenceMechanismRecipeAbsent,
                    ),
                ))?;
                Ok(Phase::MechanismsAfterHistory {
                    history,
                    read: self.bind(storage, recipe)?,
                })
            }
            None => self.finish(
                history,
                self.evaluate_mechanisms(
                    crate::attributes::owned::resident::MechanismValues::from_observation(
                        crate::Observation::NotRequested,
                    ),
                )?,
            ),
        }
    }
    fn after_mechanisms(
        &mut self,
        mechanisms: Option<MechanismObservationReport>,
    ) -> Result<Phase> {
        match self.future_history.take() {
            Some(storage) => Ok(Phase::HistoryAfterMechanisms {
                mechanisms,
                read: self.bind(storage, Recipe::History(self.history))?,
            }),
            None => self.finish(self.unobserved_history()?, mechanisms),
        }
    }
    fn begin_evidence(&mut self) -> Result<Phase> {
        // Preserve each existing family's call/refusal order. A refusal never
        // activates the later selected read merely to complete a shared shape.
        match self.order {
            Order::HistoryThenMechanisms => match self.future_history.take() {
                Some(storage) => Ok(Phase::HistoryFirst(
                    self.bind(storage, Recipe::History(self.history))?,
                )),
                None => self.after_history(self.unobserved_history()?),
            },
            Order::MechanismsThenHistory => match self.future_mechanisms.take() {
                Some(storage) => {
                    let recipe = mechanism_recipe(self.mechanisms.as_ref()).ok_or(
                        Error::Rejected(crate::RejectionReason::KeyEncoding(
                            crate::KeyEncodingRejection::KeyEvidenceMechanismRecipeAbsent,
                        )),
                    )?;
                    Ok(Phase::MechanismsFirst(self.bind(storage, recipe)?))
                }
                None => self.after_mechanisms(self.evaluate_mechanisms(
                    crate::attributes::owned::resident::MechanismValues::from_observation(
                        crate::Observation::NotRequested,
                    ),
                )?),
            },
        }
    }
    pub(crate) fn advance(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        loop {
            match &mut self.phase {
                Phase::Identity(read)
                | Phase::HistoryFirst(read)
                | Phase::MechanismsFirst(read)
                | Phase::MechanismsAfterHistory { read, .. }
                | Phase::HistoryAfterMechanisms { read, .. } => {
                    read.advance(session, access, self.handle)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Complete(_) => return Ok(()),
                Phase::Stopped => {
                    return Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
                        crate::KeyEncodingRejection::KeyEvidenceStopped,
                    )))
                }
            }
            self.phase = match std::mem::replace(&mut self.phase, Phase::Stopped) {
                Phase::Identity(read) => {
                    let values = read.required_result(session, access)?;
                    for (field, expected) in &self.expected {
                        values.integer(*field, *expected)?;
                    }
                    self.begin_evidence()?
                }
                Phase::HistoryFirst(read) => {
                    self.after_history(read.history_result(session, access, self.history)?)?
                }
                Phase::MechanismsFirst(read) => self.after_mechanisms(
                    self.evaluate_mechanisms(read.precise_result(session, access)?)?,
                )?,
                Phase::MechanismsAfterHistory { history, read } => self.finish(
                    history,
                    self.evaluate_mechanisms(read.precise_result(session, access)?)?,
                )?,
                Phase::HistoryAfterMechanisms { mechanisms, read } => self.finish(
                    read.history_result(session, access, self.history)?,
                    mechanisms,
                )?,
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
                        crate::KeyEncodingRejection::KeyEvidenceCompletionPhase,
                    )))
                }
            };
        }
    }
    pub(crate) fn result(self) -> Result<Evidence> {
        match self.phase {
            Phase::Complete(evidence) => Ok(evidence),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
                crate::KeyEncodingRejection::KeyEvidenceIncomplete,
            ))),
        }
    }
}
