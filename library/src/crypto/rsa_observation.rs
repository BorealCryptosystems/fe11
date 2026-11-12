// SPDX-License-Identifier: Apache-2.0
//! Observe a private RSA object's public encoding without guarded credit waits.
//! Returned attribute storage remains resident while an empty DER candidate is
//! admitted. Encoding consumes that candidate once; no attribute call is replayed.
use super::{
    integer_key::{PublicDer, PublicDerCandidate, PublicDerNeed, RsaSpki},
    key_evidence,
};
use crate::{
    attributes::{
        owned::resident::{LegacyOwner, ReadStorage, Recipe, ValueNeed},
        RequiredAttributes,
    },
    session::{observation_protection::ObservationProtection, SessionAccess},
    symmetric::memory::Credit,
    Error, Result, Session,
};
use fe11_sys::*;

fn recipe(maximum: usize) -> Recipe<'static> {
    Recipe::Required {
        fields: &[CKA_MODULUS, CKA_PUBLIC_EXPONENT],
        maximum,
    }
}
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(Error::Rejected(
        crate::RejectionReason::ClassicalSignatures(
            crate::ClassicalSignaturesRejection::RsaObservationStorageSize,
        ),
    ))
}
pub(crate) struct Initial {
    identity: key_evidence::Initial,
    public: ReadStorage,
    maximum: usize,
}
impl Initial {
    pub(crate) fn requested(spec: key_evidence::Spec<'_>) -> Result<usize> {
        add(
            add(
                std::mem::size_of::<Owner>(),
                key_evidence::Initial::requested(spec)?,
            )?,
            ReadStorage::requested(recipe(spec.maximum))?,
        )
    }
    pub(crate) fn allocate(spec: key_evidence::Spec<'_>) -> Result<Self> {
        if spec.introduction.is_some() || spec.mechanisms.is_some() {
            return Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::RsaDiscoveryEvidenceSequence,
                ),
            ));
        }
        Ok(Self {
            identity: key_evidence::Initial::allocate(spec)?,
            public: ReadStorage::allocate(recipe(spec.maximum))?,
            maximum: spec.maximum,
        })
    }
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        add(
            add(
                std::mem::size_of::<Owner>(),
                self.identity.allocated_bytes()?,
            )?,
            self.public.allocated_bytes()?,
        )
    }
    pub(crate) fn bind(
        self,
        handle: CK_OBJECT_HANDLE,
        epoch: u64,
        protection: ObservationProtection,
        prepaid: &mut Credit,
    ) -> Result<Owner> {
        let credit = prepaid.split(std::mem::size_of::<Owner>())?;
        let identity = self
            .identity
            .bind(handle, epoch, protection.duplicate()?, prepaid)?;
        let future = prepaid.split(self.public.allocated_bytes()?)?;
        Ok(Owner {
            phase: Phase::Identity(Box::new(identity)),
            public: Some(self.public),
            maximum: self.maximum,

            handle,
            epoch,
            protection,
            prepaid: future,
            _credit: credit,
        })
    }
}
enum Phase {
    Identity(Box<key_evidence::Owner>),
    Public(LegacyOwner),
    Encoding {
        values: RequiredAttributes,
        need: PublicDerNeed,
    },
    Prepared {
        values: RequiredAttributes,
        candidate: PublicDerCandidate,
    },
    Complete(PublicDer),
    Stopped,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Need {
    Metadata(ValueNeed),
    Encoding(PublicDerNeed),
}
pub(crate) enum Candidate {
    Metadata(
        ValueNeed,
        crate::attributes::owned::resident::ValueCandidate,
    ),
    Encoding(PublicDerCandidate),
}
pub(crate) struct Owner {
    phase: Phase,
    public: Option<ReadStorage>,
    maximum: usize,

    handle: CK_OBJECT_HANDLE,
    epoch: u64,
    protection: ObservationProtection,
    prepaid: Credit,
    _credit: Credit,
}
impl Owner {
    pub(crate) fn pending(&self) -> bool {
        match &self.phase {
            Phase::Identity(read) => read.pending(),
            Phase::Public(read) => read.pending(),
            _ => false,
        }
    }
    pub(crate) fn complete(&self) -> bool {
        matches!(self.phase, Phase::Complete(_))
    }
    pub(crate) fn need(&self) -> Option<Need> {
        match &self.phase {
            Phase::Identity(read) => read.need().map(Need::Metadata),
            Phase::Public(read) => read.need().map(Need::Metadata),
            Phase::Encoding { need, .. } => Some(Need::Encoding(*need)),
            _ => None,
        }
    }
    pub(crate) fn attach(&mut self, candidate: Candidate) -> Result<()> {
        match candidate {
            Candidate::Metadata(need, value) => match &mut self.phase {
                Phase::Identity(read) => read.attach(need, value),
                Phase::Public(read) => read.attach(need, value),
                _ => Err(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::RsaObservationMetadataPhase,
                    ),
                )),
            },
            Candidate::Encoding(candidate) => {
                if self.need() != Some(Need::Encoding(candidate.need())) {
                    return Err(Error::Rejected(
                        crate::RejectionReason::ClassicalSignatures(
                            crate::ClassicalSignaturesRejection::RsaEncodingContinuationChanged,
                        ),
                    ));
                }
                let Phase::Encoding { values, .. } =
                    std::mem::replace(&mut self.phase, Phase::Stopped)
                else {
                    return Err(Error::Rejected(
                        crate::RejectionReason::ClassicalSignatures(
                            crate::ClassicalSignaturesRejection::RsaEncodingPhase,
                        ),
                    ));
                };
                self.phase = Phase::Prepared { values, candidate };
                Ok(())
            }
        }
    }
    pub(crate) fn advance(&mut self, session: &Session, access: &SessionAccess<'_>) -> Result<()> {
        loop {
            match &mut self.phase {
                Phase::Identity(read) => {
                    read.advance(session, access)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Public(read) => {
                    read.advance(session, access, self.handle)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Encoding { .. } | Phase::Complete(_) => return Ok(()),
                Phase::Prepared { .. } => {}
                Phase::Stopped => {
                    return Err(Error::Rejected(
                        crate::RejectionReason::ClassicalSignatures(
                            crate::ClassicalSignaturesRejection::RsaObservationStopped,
                        ),
                    ))
                }
            }
            self.phase = match std::mem::replace(&mut self.phase, Phase::Stopped) {
                Phase::Identity(read) => {
                    // First-stage provenance is observed for the original
                    // contract, but it is not the second-stage admission report.
                    drop(read.result()?);
                    let storage = self.public.take().ok_or(Error::Rejected(
                        crate::RejectionReason::ClassicalSignatures(
                            crate::ClassicalSignaturesRejection::RsaPublicPreparationAbsent,
                        ),
                    ))?;
                    Phase::Public(storage.bind_with_protection(
                        &mut self.prepaid,
                        recipe(self.maximum),
                        self.handle,
                        Some(self.epoch),
                        self.protection.duplicate()?,
                    )?)
                }
                Phase::Public(read) => {
                    let values = read.required_result(session, access)?;
                    let public = RsaSpki::new(
                        values.bytes(CKA_MODULUS)?,
                        values.bytes(CKA_PUBLIC_EXPONENT)?,
                    )?;
                    let length =
                        usize::try_from(der::Encode::encoded_len(&public).map_err(|_| {
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
                        values,
                        need: PublicDerNeed::new(length, false),
                    }
                }
                Phase::Prepared { values, candidate } => {
                    let public = RsaSpki::new(
                        values.bytes(CKA_MODULUS)?,
                        values.bytes(CKA_PUBLIC_EXPONENT)?,
                    )?;
                    let encoded = candidate.encode(&public)?.primary;

                    Phase::Complete(encoded)
                }
                _ => {
                    return Err(Error::Rejected(
                        crate::RejectionReason::ClassicalSignatures(
                            crate::ClassicalSignaturesRejection::RsaObservationCompletionPhase,
                        ),
                    ))
                }
            };
        }
    }
    pub(crate) fn result(self) -> Result<PublicDer> {
        match self.phase {
            Phase::Complete(public) => Ok(public),
            _ => Err(Error::Rejected(
                crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::RsaObservationIncomplete,
                ),
            )),
        }
    }
}
