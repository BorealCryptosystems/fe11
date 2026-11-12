// SPDX-License-Identifier: Apache-2.0
//! Family-specific evidence graphs share only selection and reference custody.
use super::*;
use crate::crypto::public_import::observation;

#[derive(Clone, Copy)]
pub(super) enum Plan<'a> {
    Signing { evidence: key_evidence::Spec<'a> },
    Public(observation::Spec<'a>),
    PrivateRsa(crate::crypto::rsa_evidence::Spec<'a>),
}
pub(super) enum Initial {
    Signing(key_evidence::Initial),
    Public(observation::Initial),
    PrivateRsa {
        first: crate::crypto::rsa_observation::Initial,
        second: crate::crypto::rsa_evidence::Initial,
    },
}
impl Plan<'_> {
    pub(super) fn class(self) -> ManagedClass {
        match self {
            Self::Signing { .. } | Self::PrivateRsa(_) => ManagedClass::PrivateKey,
            Self::Public(_) => ManagedClass::PublicKey,
        }
    }
    pub(super) fn two_searches(self) -> bool {
        matches!(self, Self::PrivateRsa(_))
    }
    pub(super) fn requested(self) -> Result<usize> {
        match self {
            Self::Signing { evidence } => key_evidence::Initial::requested(evidence),
            Self::Public(evidence) => observation::Initial::requested(evidence),
            Self::PrivateRsa(spec) => {
                crate::crypto::rsa_observation::Initial::requested(spec.identity)?
                    .checked_add(crate::crypto::rsa_evidence::Initial::requested(spec)?)
                    .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                        crate::ObjectReferencesRejection::RsaReadmissionStorageSize,
                    )))
            }
        }
    }
    pub(super) fn allocate(self) -> Result<Initial> {
        match self {
            Self::Signing { evidence } => {
                Ok(Initial::Signing(key_evidence::Initial::allocate(evidence)?))
            }
            Self::Public(evidence) => observation::Initial::allocate(evidence).map(Initial::Public),
            Self::PrivateRsa(spec) => Ok(Initial::PrivateRsa {
                first: crate::crypto::rsa_observation::Initial::allocate(spec.identity)?,
                second: crate::crypto::rsa_evidence::Initial::allocate(spec)?,
            }),
        }
    }
}
impl Initial {
    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        match self {
            Self::Signing(value) => value.allocated_bytes(),
            Self::Public(value) => value.allocated_bytes(),
            Self::PrivateRsa { first, second } => first
                .allocated_bytes()?
                .checked_add(second.allocated_bytes()?)
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectReferences(
                    crate::ObjectReferencesRejection::RsaReadmissionStorageSize,
                ))),
        }
    }
}
