// SPDX-License-Identifier: Apache-2.0
//! RSA transport observations use the common native attribute owner.
//! No modulus/exponent comparison or public/private matching is performed here.
use super::key_evidence;
use crate::{
    session::observation_protection::ObservationProtection, symmetric::memory::Credit,
    MechanismObservationPlan, Result,
};
use fe11_sys::CK_OBJECT_HANDLE;

#[derive(Clone, Copy)]
pub(crate) struct Spec<'a> {
    pub(crate) identity: key_evidence::Spec<'a>,
    pub(crate) mechanisms: &'a MechanismObservationPlan,
    pub(crate) introduction: Option<key_evidence::Introduction>,
}
impl<'a> Spec<'a> {
    fn native(self) -> key_evidence::Spec<'a> {
        key_evidence::Spec {
            order: key_evidence::Order::HistoryThenMechanisms,
            introduction: self.introduction,
            mechanisms: Some(self.mechanisms),
            ..self.identity
        }
    }
}

pub(crate) struct Initial(key_evidence::Initial);
pub(crate) use key_evidence::Owner;
impl Initial {
    pub(crate) fn requested(spec: Spec<'_>) -> Result<usize> {
        key_evidence::Initial::requested(spec.native())
    }
    pub(crate) fn allocate(spec: Spec<'_>) -> Result<Self> {
        key_evidence::Initial::allocate(spec.native()).map(Self)
    }
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        self.0.allocated_bytes()
    }
    pub(crate) fn bind(
        self,
        handle: CK_OBJECT_HANDLE,
        epoch: u64,
        protection: ObservationProtection,
        prepaid: &mut Credit,
    ) -> Result<Owner> {
        self.0.bind(handle, epoch, protection, prepaid)
    }
}
