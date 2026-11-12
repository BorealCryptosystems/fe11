// SPDX-License-Identifier: Apache-2.0
//! Immutable read plans and guard-free aggregate metadata preparation.
use super::super::{KeyPolicy, Stage};
use super::recipe::{Kind, Recipe};
use super::{
    PreparedRead, PreparedStorage, ReadCandidate, ReadFrame, ReadNeed, ReadStage, SizePlan,
};

use crate::crypto::KeyAdmissionDescription;
use crate::{
    attributes::PreciseAttributeValue,
    symmetric::memory::{Budget, ControlledReservation, Credit},
    Error, Result,
};
use fe11_sys::{CK_ATTRIBUTE, CK_ATTRIBUTE_TYPE};
use std::sync::Arc;

pub(crate) struct ReadPlan {
    kinds: Vec<CK_ATTRIBUTE_TYPE>,
    limit: usize,
    precise: bool,
    decode_mechanisms: bool,
    _credit: Credit,
}
impl ReadPlan {}

// Plans are immutable and shared across rechecks. A stale waiter can keep only
// its plan's credited metadata, never a read frame, native buffer or operation.
pub(in crate::advanced) struct ReadPlans {
    plans: [[Option<Arc<ReadPlan>>; 5]; 2],
}
impl ReadPlans {
    pub(in crate::advanced::admission) fn requested_bytes(
        policy: &dyn KeyAdmissionDescription,
    ) -> Result<usize> {
        let mut total = 0usize;
        visit_recipes(policy, |recipe| {
            let (count, _, _) = recipe.shape()?;
            if count != 0 {
                total = total
                    .checked_add(plan_bytes(count)?)
                    .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::OwnedAttributeMetadata,
                    )))?;
            }
            Ok(())
        })?;
        Ok(total)
    }
    pub(in crate::advanced::admission) fn select(
        &self,
        stage: Stage,
        policy: &KeyPolicy,
    ) -> Result<ReadOwner> {
        let kind = match stage {
            Stage::Required => Kind::Required,
            Stage::PublicMaterial => Kind::Material,
            Stage::History => Kind::History,
            Stage::Allowed => Kind::Mechanisms,
            Stage::Properties => Kind::Properties,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::AttributeFrameAbsent,
                )))
            }
        };
        let private = matches!(policy, KeyPolicy::Pair(pair) if pair.private);
        let recipe = Recipe {
            policy,
            private,
            kind,
        };
        let (count, limit, precise) = recipe.shape()?;
        let plan = self.plans[usize::from(private)][kind.index()]
            .as_ref()
            .filter(|p| {
                p.kinds.len() == count
                    && p.limit == limit
                    && p.precise == precise
                    && p.decode_mechanisms == matches!(kind, Kind::Mechanisms)
            })
            .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AdmissionObservationPlanExceeded,
            )))?;
        let mut kinds = plan.kinds.iter();
        let mut matches = true;
        recipe.visit(|kind| matches &= kinds.next() == Some(&kind));
        if !matches || kinds.next().is_some() {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AdmissionObservationPlanExceeded,
            )));
        }
        Ok(ReadOwner::Planned(plan.clone()))
    }
}

pub(in crate::advanced) enum ReadOwner {
    Planned(Arc<ReadPlan>),
    Active(ReadFrame),
}
impl ReadOwner {
    pub(in crate::advanced) fn need(&self) -> Option<ReadNeed> {
        match self {
            Self::Planned(plan) => Some(ReadNeed::Frame(plan.clone())),
            Self::Active(frame) => frame.need(),
        }
    }
    pub(in crate::advanced) fn completed_rv(&self) -> Option<fe11_sys::CK_RV> {
        match self {
            Self::Planned(_) => None,
            Self::Active(frame) => frame.completed_rv(),
        }
    }
    pub(in crate::advanced) fn active_mut(&mut self) -> Result<&mut ReadFrame> {
        match self {
            Self::Active(frame) => Ok(frame),
            Self::Planned(_) => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AttributeFrameAbsent,
            ))),
        }
    }
    pub(in crate::advanced) fn attach(&mut self, candidate: ReadCandidate) -> Result<()> {
        if !self.need().is_some_and(|need| need.same(candidate.need())) {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AttributePreparationChanged,
            )));
        }
        match self {
            Self::Planned(_) => {
                let PreparedStorage::Frame(frame) = candidate.storage else {
                    return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::AttributePreparationChanged,
                    )));
                };
                *self = Self::Active(frame);
                Ok(())
            }
            Self::Active(frame) => frame.attach(candidate),
        }
    }
}

pub(super) fn prepare_frame<T>(
    plan: Arc<ReadPlan>,
    budget: &Arc<Budget>,
    retained_bytes: usize,
    admission: &crate::ResourceAdmission,
    mut before: impl FnMut() -> Result<Option<T>>,
) -> Result<PreparedRead<T>> {
    let count = plan.kinds.len();
    let width = std::mem::size_of::<CK_ATTRIBUTE>()
        + std::mem::size_of::<CK_ATTRIBUTE_TYPE>()
        + std::mem::size_of::<usize>()
        + std::mem::size_of::<Option<PreciseAttributeValue>>()
        + std::mem::size_of::<crate::AttributeValue>()
        + std::mem::size_of::<Credit>()
        + std::mem::size_of::<Option<usize>>();
    let fixed = std::mem::size_of::<ReadFrame>()
        + std::mem::size_of::<SizePlan>()
        + 2 * std::mem::size_of::<usize>();
    let mut required = count
        .checked_mul(width)
        .and_then(|n| n.checked_add(fixed))
        .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
            crate::KeyAdmissionRejection::OwnedAttributeMetadata,
        )))?;
    loop {
        let mut credit = match budget.reserve_controlled_retaining(
            required,
            crate::session::lifecycle_diagnostics::Store::including(retained_bytes)?,
            admission,
            &mut before,
            || Ok(None),
        )? {
            ControlledReservation::Acquired(credit) => credit,
            ControlledReservation::Redirect(route) => return Ok(PreparedRead::Redirect(route)),
        };
        fn vector<T>(count: usize, total: &mut usize) -> Result<Vec<T>> {
            let mut v = Vec::new();
            v.try_reserve_exact(count).map_err(|_| {
                Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::OwnedAttributeAllocation,
                ))
            })?;
            *total = v
                .capacity()
                .checked_mul(std::mem::size_of::<T>())
                .and_then(|n| n.checked_add(*total))
                .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::OwnedAttributeMetadata,
                )))?;
            Ok(v)
        }
        let mut allocated = fixed;
        let mut kinds = vector(count, &mut allocated)?;
        kinds.extend_from_slice(&plan.kinds);
        let mut attrs = vector(count, &mut allocated)?;
        let mut indices = vector(count, &mut allocated)?;
        let mut values = vector(count, &mut allocated)?;
        let output = vector(count, &mut allocated)?;
        let retained = vector(count, &mut allocated)?;
        let mut lengths = vector(count, &mut allocated)?;
        for (i, kind) in kinds.iter().enumerate() {
            attrs.push(CK_ATTRIBUTE {
                r#type: *kind,
                pValue: std::ptr::null_mut(),
                ulValueLen: 0,
            });
            indices.push(i);
            values.push(None);
            lengths.push(None);
        }
        let size_bytes = lengths
            .capacity()
            .checked_mul(std::mem::size_of::<Option<usize>>())
            .and_then(|n| {
                n.checked_add(std::mem::size_of::<SizePlan>() + 2 * std::mem::size_of::<usize>())
            })
            .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::OwnedAttributeMetadata,
            )))?;
        let mut frame = ReadFrame {
            kinds,
            attrs,
            indices,
            slots: Vec::new(),
            values,
            output,
            stage: ReadStage::Size,
            limit: plan.limit,
            precise: plan.precise,
            decode_mechanisms: plan.decode_mechanisms,
            mechanisms: None,
            sizes: Arc::new(SizePlan {
                lengths,
                bytes: 0,
                _credit: credit.split(0)?,
            }),
            retained,
            _slot_credit: None,
            _credit: credit.split(0)?,
        };
        if allocated > required {
            drop(frame);
            drop(credit);
            required = allocated;
            continue;
        }
        credit.release(required - allocated);
        Arc::get_mut(&mut frame.sizes)
            .expect("unpublished sizing plan")
            ._credit = credit.split(size_bytes)?;
        frame._credit = credit.split(allocated - size_bytes)?;
        return Ok(PreparedRead::Ready(ReadCandidate {
            need: ReadNeed::Frame(plan),
            storage: PreparedStorage::Frame(frame),
            credit,
        }));
    }
}

fn visit_recipes(
    policy: &dyn KeyAdmissionDescription,
    mut visit: impl FnMut(Recipe<'_>) -> Result<()>,
) -> Result<()> {
    let count = if policy.is_pair() { 2 } else { 1 };
    for row in 0..count {
        for kind in Kind::ALL {
            visit(Recipe {
                policy,
                private: row != 0,
                kind,
            })?;
        }
    }
    Ok(())
}
fn plan_bytes(capacity: usize) -> Result<usize> {
    capacity
        .checked_mul(std::mem::size_of::<CK_ATTRIBUTE_TYPE>())
        .and_then(|n| {
            n.checked_add(std::mem::size_of::<ReadPlan>() + 2 * std::mem::size_of::<usize>())
        })
        .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
            crate::KeyAdmissionRejection::OwnedAttributeMetadata,
        )))
}
struct PlanStorage {
    kinds: Vec<CK_ATTRIBUTE_TYPE>,
    limit: usize,
    precise: bool,
    decode_mechanisms: bool,
}
pub(in crate::advanced::admission) struct PlansStorage {
    plans: [[Option<PlanStorage>; 5]; 2],
}
impl PlansStorage {
    pub(in crate::advanced::admission) fn allocate(
        policy: &dyn KeyAdmissionDescription,
    ) -> Result<Self> {
        let mut plans = std::array::from_fn(|_| std::array::from_fn(|_| None));
        visit_recipes(policy, |recipe| {
            let (count, limit, precise) = recipe.shape()?;
            if count == 0 {
                return Ok(());
            }
            let mut kinds = Vec::new();
            kinds.try_reserve_exact(count).map_err(|_| {
                Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::OwnedAttributeMetadataAllocation,
                ))
            })?;
            recipe.visit(|kind| kinds.push(kind));
            if kinds.len() != count
                || kinds
                    .iter()
                    .enumerate()
                    .any(|(i, k)| kinds[..i].contains(k))
            {
                return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::DuplicateAttribute,
                )));
            }
            plans[usize::from(recipe.private)][recipe.kind.index()] = Some(PlanStorage {
                kinds,
                limit,
                precise,
                decode_mechanisms: matches!(recipe.kind, Kind::Mechanisms),
            });
            Ok(())
        })?;
        Ok(Self { plans })
    }
    pub(in crate::advanced::admission) fn allocated_bytes(&self) -> Result<usize> {
        self.plans
            .iter()
            .flatten()
            .flatten()
            .try_fold(0usize, |total, plan| {
                total
                    .checked_add(plan_bytes(plan.kinds.capacity())?)
                    .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                        crate::KeyAdmissionRejection::OwnedAttributeMetadata,
                    )))
            })
    }
    pub(in crate::advanced::admission) fn bind(self, prepaid: &mut Credit) -> Result<ReadPlans> {
        let mut plans = std::array::from_fn(|_| std::array::from_fn(|_| None));
        for (row, storage) in self.plans.into_iter().enumerate() {
            for (column, storage) in storage.into_iter().enumerate() {
                if let Some(storage) = storage {
                    let credit = prepaid.split(plan_bytes(storage.kinds.capacity())?)?;
                    plans[row][column] = Some(Arc::new(ReadPlan {
                        kinds: storage.kinds,
                        limit: storage.limit,
                        precise: storage.precise,
                        decode_mechanisms: storage.decode_mechanisms,
                        _credit: credit,
                    }));
                }
            }
        }
        Ok(ReadPlans { plans })
    }
}
