// SPDX-License-Identifier: Apache-2.0
//! Family-specific native observations after private object creation.
use crate::{
    attributes::owned::resident::ValueNeed,
    crypto::key_evidence,
    session::{observation_protection::ObservationProtection, SessionAccess},
    symmetric::memory::Credit,
    Error, Result, Session,
};
use fe11_sys::CK_OBJECT_HANDLE;

// Child preparations already account for their owner. The containing enum is
// boxed by CreationOwner; retain its additional layout bytes in that parent's
// prepaid credit until the whole creation has completed.
fn containing_bytes<T>(bytes: usize) -> Result<usize> {
    bytes
        .checked_add(std::mem::size_of::<Owner>().saturating_sub(std::mem::size_of::<T>()))
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
            crate::ObjectCreationRejection::PrivateObservationStorageSize,
        )))
}

#[derive(Clone, Copy)]
pub(crate) enum Plan<'a> {
    Key(key_evidence::Spec<'a>),
    Rsa(crate::crypto::rsa_evidence::Spec<'a>),
    Signing { evidence: key_evidence::Spec<'a> },
}
pub(in crate::managed::mutations::create::resident) enum Initial {
    Key(key_evidence::Initial),
    Rsa(crate::crypto::rsa_evidence::Initial),
    Signing(key_evidence::Initial),
}
impl Plan<'_> {
    pub(crate) fn requested(self) -> Result<usize> {
        match self {
            Self::Rsa(spec) => containing_bytes::<crate::crypto::rsa_evidence::Owner>(
                crate::crypto::rsa_evidence::Initial::requested(spec)?,
            ),
            Self::Key(spec) => {
                containing_bytes::<key_evidence::Owner>(key_evidence::Initial::requested(spec)?)
            }
            Self::Signing { evidence } => {
                containing_bytes::<key_evidence::Owner>(key_evidence::Initial::requested(evidence)?)
            }
        }
    }
    pub(in crate::managed::mutations::create::resident) fn allocate(self) -> Result<Initial> {
        match self {
            Self::Rsa(spec) => {
                crate::crypto::rsa_evidence::Initial::allocate(spec).map(Initial::Rsa)
            }
            Self::Key(spec) => key_evidence::Initial::allocate(spec).map(Initial::Key),
            Self::Signing { evidence } => {
                key_evidence::Initial::allocate(evidence).map(Initial::Signing)
            }
        }
    }
}
impl Initial {
    pub(in crate::managed::mutations::create::resident) fn allocated_bytes(&self) -> Result<usize> {
        match self {
            Self::Rsa(read) => {
                containing_bytes::<crate::crypto::rsa_evidence::Owner>(read.allocated_bytes()?)
            }
            Self::Key(read) => containing_bytes::<key_evidence::Owner>(read.allocated_bytes()?),
            Self::Signing(read) => containing_bytes::<key_evidence::Owner>(read.allocated_bytes()?),
        }
    }
    pub(in crate::managed::mutations::create::resident) fn bind(
        self,
        handle: CK_OBJECT_HANDLE,
        epoch: u64,
        protection: ObservationProtection,
        prepaid: &mut Credit,
    ) -> Result<Owner> {
        match self {
            Self::Rsa(read) => read
                .bind(handle, epoch, protection, prepaid)
                .map(Owner::Rsa),
            Self::Key(read) => read
                .bind(handle, epoch, protection, prepaid)
                .map(Owner::Key),
            Self::Signing(read) => read
                .bind(handle, epoch, protection, prepaid)
                .map(Owner::Signing),
        }
    }
}
pub(in crate::managed::mutations::create::resident) enum Owner {
    Key(key_evidence::Owner),
    Rsa(crate::crypto::rsa_evidence::Owner),
    Signing(key_evidence::Owner),
}
pub(crate) enum Evidence {
    Key(key_evidence::Evidence),
    Signing(key_evidence::Evidence),
}
impl Owner {
    pub(in crate::managed::mutations::create::resident) fn pending(&self) -> bool {
        match self {
            Self::Key(read) => read.pending(),
            Self::Rsa(read) => read.pending(),
            Self::Signing(read) => read.pending(),
        }
    }
    pub(in crate::managed::mutations::create::resident) fn complete(&self) -> bool {
        match self {
            Self::Key(read) => read.complete(),
            Self::Rsa(read) => read.complete(),
            Self::Signing(read) => read.complete(),
        }
    }

    pub(in crate::managed::mutations::create::resident) fn need(&self) -> Option<ValueNeed> {
        match self {
            Self::Key(read) => read.need(),
            Self::Rsa(read) => read.need(),
            Self::Signing(read) => read.need(),
        }
    }
    pub(in crate::managed::mutations::create::resident) fn advance(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
    ) -> Result<()> {
        match self {
            Self::Key(read) => read.advance(session, access),
            Self::Rsa(read) => read.advance(session, access),
            Self::Signing(read) => read.advance(session, access),
        }
    }
    pub(in crate::managed::mutations::create::resident) fn attach(
        &mut self,
        need: ValueNeed,
        value: crate::attributes::owned::resident::ValueCandidate,
    ) -> Result<()> {
        match self {
            Self::Key(read) => read.attach(need, value),
            Self::Rsa(read) => read.attach(need, value),
            Self::Signing(read) => read.attach(need, value),
        }
    }

    pub(in crate::managed::mutations::create::resident) fn result(self) -> Result<Evidence> {
        match self {
            Self::Key(read) => read.result().map(Evidence::Key),
            Self::Rsa(read) => read.result().map(Evidence::Key),
            Self::Signing(read) => read.result().map(Evidence::Signing),
        }
    }
}
