// SPDX-License-Identifier: Apache-2.0
//! Independent RSA object observations and an explicit public-key encoding.
use super::*;
use crate::{
    attributes::{
        owned::resident::{LegacyOwner, ReadStorage, Recipe, ValueNeed},
        RequiredAttributes,
    },
    crypto::integer_key::{PublicDer, PublicDerCandidate, PublicDerNeed, RsaSpki},
    session::{observation_protection::ObservationProtection, SessionAccess},
    symmetric::memory::Credit,
};

fn recipe(maximum: usize, private: bool) -> Recipe<'static> {
    Recipe::Required {
        fields: if private {
            &[CKA_CLASS, CKA_KEY_TYPE, CKA_MODULUS]
        } else {
            &[CKA_CLASS, CKA_KEY_TYPE, CKA_MODULUS, CKA_PUBLIC_EXPONENT]
        },
        maximum,
    }
}
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b)
        .ok_or(Error::Rejected(crate::RejectionReason::ObjectObservation(
            crate::ObjectObservationRejection::RsaPairObservationStorage,
        )))
}
pub(super) struct Initial {
    public: ReadStorage,
    private: ReadStorage,
    maximum: [usize; 2],
}
impl Initial {
    pub(super) fn requested(maximum: [usize; 2]) -> Result<usize> {
        add(
            add(
                std::mem::size_of::<Owner>(),
                ReadStorage::requested(recipe(maximum[0], false))?,
            )?,
            ReadStorage::requested(recipe(maximum[1], true))?,
        )
    }
    pub(super) fn allocate(maximum: [usize; 2]) -> Result<Self> {
        Ok(Self {
            public: ReadStorage::allocate(recipe(maximum[0], false))?,
            private: ReadStorage::allocate(recipe(maximum[1], true))?,
            maximum,
        })
    }
    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        add(
            add(std::mem::size_of::<Owner>(), self.public.allocated_bytes()?)?,
            self.private.allocated_bytes()?,
        )
    }
    pub(super) fn bind(
        self,
        handles: [CK_OBJECT_HANDLE; 2],

        epoch: u64,
        protection: ObservationProtection,
        prepaid: &mut Credit,
    ) -> Result<Owner> {
        // Keep deferred private-read storage charged if public binding fails.
        let future;
        let storage = self;
        let credit = prepaid.split(std::mem::size_of::<Owner>())?;
        future = prepaid.split(storage.private.allocated_bytes()?)?;
        let public = storage.public.bind_with_protection(
            prepaid,
            recipe(storage.maximum[0], false),
            handles[0],
            Some(epoch),
            protection.duplicate()?,
        )?;
        Ok(Owner {
            phase: Phase::Public(public),
            private: Some(storage.private),
            maximum: storage.maximum[1],
            handles,
            epoch,
            protection,
            prepaid: future,
            _credit: credit,
        })
    }
}
pub(super) struct Evidence {
    pub(super) fingerprint: PublicKeyFingerprint,
    pub(super) public_der: PublicDer,
    pub(super) modulus_bits: [usize; 2],
}
enum Phase {
    Public(LegacyOwner),
    Private {
        public: RequiredAttributes,
        read: LegacyOwner,
    },
    Encoding {
        public: RequiredAttributes,
        bits: [usize; 2],
        need: PublicDerNeed,
    },
    Prepared {
        public: RequiredAttributes,
        bits: [usize; 2],
        candidate: PublicDerCandidate,
    },
    Complete(Evidence),
    Stopped,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Need {
    Value(ValueNeed),
    Encoding(PublicDerNeed),
}
pub(super) enum Candidate {
    Value(crate::attributes::owned::resident::ValueCandidate),
    Encoding(PublicDerCandidate),
}
pub(super) struct Owner {
    phase: Phase,
    private: Option<ReadStorage>,
    maximum: usize,
    handles: [CK_OBJECT_HANDLE; 2],

    epoch: u64,
    protection: ObservationProtection,
    prepaid: Credit,
    _credit: Credit,
}
impl Owner {
    pub(super) fn pending(&self) -> bool {
        match &self.phase {
            Phase::Public(read) | Phase::Private { read, .. } => read.pending(),
            _ => false,
        }
    }
    pub(super) fn complete(&self) -> bool {
        matches!(self.phase, Phase::Complete(_))
    }
    pub(super) fn need(&self) -> Option<Need> {
        match &self.phase {
            Phase::Public(read) | Phase::Private { read, .. } => read.need().map(Need::Value),
            Phase::Encoding { need, .. } => Some(Need::Encoding(*need)),
            _ => None,
        }
    }
    pub(super) fn attach(&mut self, need: Need, candidate: Candidate) -> Result<()> {
        if self.need() != Some(need) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectObservation(
                crate::ObjectObservationRejection::RsaPairContinuationChanged,
            )));
        }
        match (&mut self.phase, need, candidate) {
            (
                Phase::Public(read) | Phase::Private { read, .. },
                Need::Value(need),
                Candidate::Value(value),
            ) => read.attach(need, value),
            (Phase::Encoding { .. }, Need::Encoding(_), Candidate::Encoding(candidate)) => {
                let Phase::Encoding { public, bits, .. } =
                    std::mem::replace(&mut self.phase, Phase::Stopped)
                else {
                    unreachable!()
                };
                self.phase = Phase::Prepared {
                    public,
                    bits,
                    candidate,
                };
                Ok(())
            }
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectObservation(
                crate::ObjectObservationRejection::RsaPairCandidateKind,
            ))),
        }
    }
    pub(super) fn advance(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        session
            .snapshot
            .check_authentication_unchanged(self.epoch)?;
        session.entry(access)?;
        loop {
            match &mut self.phase {
                Phase::Public(read) => {
                    read.advance(session, access, self.handles[0])?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Private { read, .. } => {
                    read.advance(session, access, self.handles[1])?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Encoding { .. } | Phase::Complete(_) => return Ok(()),
                Phase::Prepared { .. } => {}
                Phase::Stopped => {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectObservation(
                        crate::ObjectObservationRejection::RsaPairObservationStopped,
                    )))
                }
            }
            self.phase = match std::mem::replace(&mut self.phase, Phase::Stopped) {
                Phase::Public(read) => {
                    let public = read.required_result(session, access)?;
                    let private =
                        self.private
                            .take()
                            .ok_or(Error::Rejected(crate::RejectionReason::ObjectObservation(
                            crate::ObjectObservationRejection::RsaPrivateSnapshotPreparationAbsent,
                        )))?;
                    let read = private.bind_with_protection(
                        &mut self.prepaid,
                        recipe(self.maximum, true),
                        self.handles[1],
                        Some(self.epoch),
                        self.protection.duplicate()?,
                    )?;
                    Phase::Private { public, read }
                }
                Phase::Private { public, read } => {
                    let private = read.required_result(session, access)?;
                    for (snapshot, class) in [
                        (&public, ObjectClass::PublicKey),
                        (&private, ObjectClass::PrivateKey),
                    ] {
                        snapshot.integer(CKA_CLASS, class.raw())?;
                        snapshot.integer(CKA_KEY_TYPE, CKK_RSA)?;
                    }
                    let modulus = public.bytes(CKA_MODULUS)?;
                    let exponent = public.bytes(CKA_PUBLIC_EXPONENT)?;
                    // Widths describe each object independently; no pairwise
                    // public/private equality or possession claim is made.
                    let private_bits =
                        crate::crypto::integer_key::bit_length(private.bytes(CKA_MODULUS)?)?;
                    let encoding = RsaSpki::new(modulus, exponent)?;
                    let bits = [encoding.modulus_bits()?, private_bits];
                    let length =
                        usize::try_from(der::Encode::encoded_len(&encoding).map_err(|_| {
                            Error::Rejected(crate::RejectionReason::KeyEncoding(
                                crate::KeyEncodingRejection::PublicDerLength,
                            ))
                        })?)
                        .map_err(|_| {
                            Error::Rejected(crate::RejectionReason::KeyEncoding(
                                crate::KeyEncodingRejection::PublicDerWidth,
                            ))
                        })?;
                    Phase::Encoding {
                        public,
                        bits,
                        need: PublicDerNeed::new(length, false),
                    }
                }
                Phase::Prepared {
                    public,
                    bits,
                    candidate,
                } => {
                    let encoding = RsaSpki::new(
                        public.bytes(CKA_MODULUS)?,
                        public.bytes(CKA_PUBLIC_EXPONENT)?,
                    )?;
                    let public_der = candidate.encode(&encoding)?.primary;
                    let fingerprint = PublicKeyFingerprint(Sha256::digest(&public_der).into());
                    Phase::Complete(Evidence {
                        fingerprint,
                        public_der,
                        modulus_bits: bits,
                    })
                }
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectObservation(
                        crate::ObjectObservationRejection::RsaPairCompletionPhase,
                    )))
                }
            };
        }
    }
    pub(super) fn result(self) -> Result<Evidence> {
        match self.phase {
            Phase::Complete(evidence) => Ok(evidence),
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectObservation(
                crate::ObjectObservationRejection::RsaPairObservationIncomplete,
            ))),
        }
    }
}
