// SPDX-License-Identifier: Apache-2.0
//! Compound fingerprint observation; every completed stage stays session-owned.
use super::*;
use crate::{
    attributes::owned::resident::{LegacyOwner, Recipe, ValueNeed},
    content_controls::owned::resident::ContentOwner,
    registry::ReadPermit,
    session::observation_protection::ObservationProtection,
    session::SessionAccess,
    symmetric::memory::Credit,
};

mod preparation;
mod runner;
pub(crate) use preparation::{prepare as prepare_candidate, Candidate};
pub(crate) use runner::observe;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Metadata {
    Material(CK_ULONG),
    After,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Need {
    Metadata { phase: Metadata, maximum: usize },
    PublicValue(ValueNeed),
    ProtectedCall { maximum: usize },
    SecretValue { length: usize },
}
impl Need {
    fn recipe(self, clarification: crate::AttributeClarification) -> Result<Recipe<'static>> {
        let Self::Metadata { phase, maximum } = self else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectContent(
                crate::ObjectContentRejection::FingerprintMetadataNeed,
            )));
        };
        let plan = AttributeReadPlan {
            maximum_bytes: maximum,
            clarification,
        };
        Ok(match phase {
            Metadata::Material(kind) => Recipe::Fingerprint {
                fields: material(kind).0,
                plan,
            },
            Metadata::After => Recipe::Fingerprint {
                fields: &FINGERPRINT_HEADER,
                plan,
            },
        })
    }
}
enum State {
    Header(LegacyOwner),
    NeedMaterial(Header),
    Material {
        header: Header,
        read: LegacyOwner,
        digest: ProtectedFingerprintHash,
    },
    NeedValue(DigestState),
    Value {
        digest: DigestState,
        read: ContentOwner,
    },
    NeedAfter(DigestState),
    After {
        digest: DigestState,
        read: LegacyOwner,
    },
    Complete(ProtectedContent),
    Stopped,
}
pub(crate) struct FingerprintOwner {
    state: State,
    read: AttributeReadPlan,
    handle: CK_OBJECT_HANDLE,
    authentication: Option<u64>,
    protection: ObservationProtection,
    _credit: Credit,
}
impl FingerprintOwner {
    pub(crate) fn bind(
        header: LegacyOwner,
        read: AttributeReadPlan,
        handle: CK_OBJECT_HANDLE,
        authentication: Option<u64>,
        reader: ReadPermit,
        prepaid: &mut Credit,
    ) -> Result<Self> {
        Self::bind_protected(
            header,
            read,
            handle,
            authentication,
            ObservationProtection::object(reader),
            prepaid,
        )
    }
    pub(crate) fn bind_protected(
        header: LegacyOwner,
        read: AttributeReadPlan,
        handle: CK_OBJECT_HANDLE,
        authentication: Option<u64>,
        protection: ObservationProtection,
        prepaid: &mut Credit,
    ) -> Result<Self> {
        Ok(Self {
            state: State::Header(header),
            read,
            handle,
            authentication,
            protection,
            _credit: prepaid.split(std::mem::size_of::<Self>())?,
        })
    }
    pub(crate) fn pending(&self) -> bool {
        match &self.state {
            State::Header(read) | State::Material { read, .. } | State::After { read, .. } => {
                read.pending()
            }
            State::Value { read, .. } => read.pending(),
            _ => false,
        }
    }
    pub(crate) fn complete(&self) -> bool {
        matches!(self.state, State::Complete(_))
    }
    pub(crate) fn need(&self) -> Option<Need> {
        match &self.state {
            State::Header(read) | State::Material { read, .. } | State::After { read, .. } => {
                read.need().map(Need::PublicValue)
            }
            State::Value { read, .. } => read.need().map(|length| Need::SecretValue { length }),
            State::NeedMaterial(header) => Some(Need::Metadata {
                phase: Metadata::Material(header.kind_value),
                maximum: header.remaining,
            }),
            State::NeedValue(digest) => Some(Need::ProtectedCall {
                maximum: digest.remaining,
            }),
            State::NeedAfter(digest) => Some(Need::Metadata {
                phase: Metadata::After,
                maximum: digest.remaining,
            }),
            _ => None,
        }
    }
    pub(crate) fn advance(
        &mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        handle: CK_OBJECT_HANDLE,
    ) -> Result<()> {
        if handle != self.handle {
            return Err(Error::Rejected(crate::RejectionReason::ObjectContent(
                crate::ObjectContentRejection::FingerprintSourceChanged,
            )));
        }
        // Never move a child out of the resident state while dispatching: an
        // unwind or unknown return must preserve the parent's pending marker.
        let completed = match &mut self.state {
            State::Header(read) | State::Material { read, .. } | State::After { read, .. } => {
                read.advance(session, access, handle)?;
                read.complete()
            }
            State::Value { read, .. } => {
                read.advance(session, access, handle)?;
                read.complete()
            }
            State::NeedMaterial(_)
            | State::NeedValue(_)
            | State::NeedAfter(_)
            | State::Complete(_) => return Ok(()),
            State::Stopped => {
                return Err(Error::Rejected(crate::RejectionReason::ObjectContent(
                    crate::ObjectContentRejection::FingerprintContinuationStopped,
                )))
            }
        };
        if !completed {
            return Ok(());
        }
        self.state = match std::mem::replace(&mut self.state, State::Stopped) {
            State::Header(read) => match read.fingerprint_result(session, access, |values| {
                Header::from_values(values, self.read.maximum_bytes)
            })? {
                Step::Continue(header) => State::NeedMaterial(header),
                Step::Complete(content) => State::Complete(content),
            },
            State::Material {
                header,
                read,
                digest,
            } => {
                match read.fingerprint_result(session, access, |values| {
                    DigestState::from_material_with_digest(header, values, digest)
                })? {
                    Step::Continue(digest) if digest.has_value() => State::NeedValue(digest),
                    Step::Continue(digest) => State::NeedAfter(digest),
                    Step::Complete(content) => State::Complete(content),
                }
            }
            State::Value { digest, read } => {
                match digest.accept_value(read.result(session, access, Ok)?)? {
                    Step::Continue(digest) => State::NeedAfter(digest),
                    Step::Complete(content) => State::Complete(content),
                }
            }
            State::After { digest, read } => {
                State::Complete(
                    read.fingerprint_result(session, access, |values| digest.finish(values))?,
                )
            }
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::ObjectContent(
                    crate::ObjectContentRejection::FingerprintCompletionPhase,
                )))
            }
        };
        Ok(())
    }
    pub(crate) fn attach(&mut self, need: Need, candidate: Candidate) -> Result<()> {
        if self.need() != Some(need) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectContent(
                crate::ObjectContentRejection::FingerprintPreparationChanged,
            )));
        }
        match (need, candidate) {
            (Need::PublicValue(need), Candidate::PublicValue(value)) => match &mut self.state {
                State::Header(read) | State::Material { read, .. } | State::After { read, .. } => {
                    read.attach(need, value)
                }
                _ => Err(Error::Rejected(crate::RejectionReason::ObjectContent(
                    crate::ObjectContentRejection::FingerprintPublicValuePhase,
                ))),
            },
            (Need::SecretValue { length }, Candidate::SecretValue(value)) => {
                match &mut self.state {
                    State::Value { read, .. } => read.attach(length, value),
                    _ => Err(Error::Rejected(crate::RejectionReason::ObjectContent(
                        crate::ObjectContentRejection::FingerprintProtectedValuePhase,
                    ))),
                }
            }
            (Need::Metadata { .. }, Candidate::Metadata(storage, digest, mut credit)) => {
                let read = storage.bind_with_protection(
                    &mut credit,
                    need.recipe(self.read.clarification)?,
                    self.handle,
                    self.authentication,
                    self.protection.duplicate()?,
                )?;
                self.state = match std::mem::replace(&mut self.state, State::Stopped) {
                    State::NeedMaterial(header) => State::Material {
                        header,
                        read,
                        digest: digest.ok_or(Error::Rejected(
                            crate::RejectionReason::ObjectContent(
                                crate::ObjectContentRejection::FingerprintDigestPreparation,
                            ),
                        ))?,
                    },
                    State::NeedAfter(digest) => State::After { digest, read },
                    _ => {
                        return Err(Error::Rejected(crate::RejectionReason::ObjectContent(
                            crate::ObjectContentRejection::FingerprintMetadataPhase,
                        )))
                    }
                };
                Ok(())
            }
            (Need::ProtectedCall { maximum }, Candidate::ProtectedCall(mut credit)) => {
                let read = ContentOwner::prepaid_protected(
                    &mut credit,
                    self.handle,
                    maximum,
                    self.authentication,
                    self.protection.duplicate()?,
                )?;
                let State::NeedValue(digest) = std::mem::replace(&mut self.state, State::Stopped)
                else {
                    return Err(Error::Rejected(crate::RejectionReason::ObjectContent(
                        crate::ObjectContentRejection::FingerprintProtectedCallPhase,
                    )));
                };
                self.state = State::Value { digest, read };
                Ok(())
            }
            _ => Err(Error::Rejected(crate::RejectionReason::ObjectContent(
                crate::ObjectContentRejection::FingerprintCandidateKind,
            ))),
        }
    }
    pub(crate) fn result<T>(
        mut self,
        session: &Session,
        access: &SessionAccess<'_>,
        finish: impl FnOnce(ProtectedContent) -> Result<T>,
    ) -> Result<T> {
        let State::Complete(content) = std::mem::replace(&mut self.state, State::Stopped) else {
            return Err(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::FingerprintObservationIncomplete,
                ),
            ));
        };
        // Both the final report and optional comparison are evaluated while the
        // parent's original observation protection covers all constituent stages.
        session.metadata_result(access, self.authentication, finish(content))
    }
}
