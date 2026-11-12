// SPDX-License-Identifier: Apache-2.0
//! Structural identity and explicitly selected history for a derivation key.
//!
//! This child performs no mechanism read, history-policy evaluation or native
//! derivation. Its enclosing operation determines their original ordering.
use super::{keys::BaseSpec, *};
use crate::{
    attributes::{
        owned::resident::{LegacyOwner, ReadStorage, Recipe, ValueNeed},
        RequiredAttributes,
    },
    session::{observation_protection::ObservationProtection, SessionAccess},
    symmetric::memory::Credit,
    Session,
};

#[derive(Clone, Copy)]
pub(super) enum Identity {
    Ec(AgreementCurve),
    Montgomery(MontgomeryDomain),
    Hkdf {
        kind: HkdfKeyType,
        length: usize,
    },
    IntroducedEc(AgreementCurve),
    Symmetric {
        algorithm: crate::SymmetricAlgorithm,
        hmac: Option<crate::HmacKeyType>,
    },
}
impl Identity {
    pub(super) fn from_base(base: &BaseSpec<'_>) -> Self {
        match base {
            BaseSpec::Ec(spec) => Self::Ec(spec.curve),
            BaseSpec::Montgomery(spec) => Self::Montgomery(spec.domain),
            BaseSpec::Hkdf(spec) => Self::Hkdf {
                kind: spec.kind,
                length: spec.length,
            },
        }
    }
    fn fields(self) -> &'static [CK_ATTRIBUTE_TYPE] {
        match self {
            Self::Ec(_) | Self::Montgomery(_) | Self::IntroducedEc(_) => {
                &[CKA_CLASS, CKA_KEY_TYPE, CKA_EC_PARAMS]
            }
            Self::Hkdf { .. } => &[CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE_LEN],
            Self::Symmetric { .. } => &[CKA_CLASS, CKA_KEY_TYPE],
        }
    }
    pub(super) fn validate(self, values: &RequiredAttributes) -> Result<()> {
        let ordinary = matches!(self, Self::IntroducedEc(_) | Self::Symmetric { .. });
        let integer = |attribute, expected| {
            if ordinary {
                return values.integer(attribute, expected);
            }
            let raw = values.bytes(attribute)?.try_into().map_err(|_| {
                Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::DerivationBaseIntegerEncoding,
                ))
            })?;
            if CK_ULONG::from_ne_bytes(raw) != expected {
                return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::DerivationBaseRequestedIdentityMismatch,
                )));
            }
            Ok(())
        };
        let (class, kind) = match self {
            Self::Ec(_) | Self::IntroducedEc(_) => (CKO_PRIVATE_KEY, CKK_EC),
            Self::Montgomery(_) => (CKO_PRIVATE_KEY, CKK_EC_MONTGOMERY),
            Self::Hkdf { kind, .. } => (CKO_SECRET_KEY, kind.raw()),
            Self::Symmetric { algorithm, hmac } => (CKO_SECRET_KEY, algorithm.key_type(hmac)?),
        };
        integer(CKA_CLASS, class)?;
        integer(CKA_KEY_TYPE, kind)?;
        let domain = match self {
            Self::Ec(curve) | Self::IntroducedEc(curve) => Some(curve.curve().domain().oid_der),
            Self::Montgomery(domain) => Some(domain.parameters_der()),
            Self::Hkdf { length, .. } => {
                integer(CKA_VALUE_LEN, crate::bounds::ck_length(length)?)?;
                None
            }
            // Optional CKA_VALUE_LEN evidence is supplied by ObjectAdmission,
            // not inferred from the requested algorithm/key-size selection.
            Self::Symmetric { .. } => None,
        };
        if let Some(domain) = domain {
            if values.bytes(CKA_EC_PARAMS)? != domain {
                return Err(Error::Rejected(if matches!(self, Self::IntroducedEc(_)) {
                    crate::RejectionReason::KeyDerivation(
                        crate::KeyDerivationRejection::IntroducedAgreementIdentityOrDomain,
                    )
                } else {
                    crate::RejectionReason::KeyDerivation(
                        crate::KeyDerivationRejection::DerivationBaseRequestedIdentityMismatch,
                    )
                }));
            }
        }
        Ok(())
    }
}
#[derive(Clone, Copy)]
pub(super) struct Spec {
    pub(super) identity: Identity,
    pub(super) maximum: usize,
    pub(super) history: HistoryObservationPlan,
}
impl Spec {
    fn identity_recipe(self) -> Recipe<'static> {
        Recipe::Required {
            fields: self.identity.fields(),
            maximum: self.maximum,
        }
    }
}
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b)
        .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
            crate::KeyDerivationRejection::DerivationObservationStorageSize,
        )))
}
pub(super) struct Initial {
    spec: Spec,
    identity: ReadStorage,
    history: Option<ReadStorage>,
}
impl Initial {
    pub(super) fn requested(spec: Spec) -> Result<usize> {
        let bytes = add(
            std::mem::size_of::<Owner>(),
            ReadStorage::requested(spec.identity_recipe())?,
        )?;
        if spec.history.field_iter().next().is_some() {
            add(
                bytes,
                ReadStorage::requested(Recipe::History(spec.history))?,
            )
        } else {
            Ok(bytes)
        }
    }
    pub(super) fn allocate(spec: Spec) -> Result<Self> {
        Ok(Self {
            spec,
            identity: ReadStorage::allocate(spec.identity_recipe())?,
            history: if spec.history.field_iter().next().is_some() {
                Some(ReadStorage::allocate(Recipe::History(spec.history))?)
            } else {
                None
            },
        })
    }
    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        add(
            add(
                std::mem::size_of::<Owner>(),
                self.identity.allocated_bytes()?,
            )?,
            self.history
                .as_ref()
                .map(ReadStorage::allocated_bytes)
                .transpose()?
                .unwrap_or(0),
        )
    }
    /// Mutation preparation already owns the source protection. Its two
    /// observation anchors are infallible Arc shares, created only after all
    /// accounting succeeds; no duplicate reader admission is performed.
    pub(super) fn bind_mutation_retained(
        candidate: &mut Option<Self>,
        handle: CK_OBJECT_HANDLE,
        epoch: u64,
        protection: &std::sync::Arc<crate::session::observation_protection::MutationProtection>,
        prepaid: &mut Credit,
    ) -> Result<Owner> {
        let prepared =
            candidate
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyDerivation(
                    crate::KeyDerivationRejection::ParentObservationPreparationAbsent,
                )))?;
        let history_bytes = prepared
            .history
            .as_ref()
            .map(ReadStorage::allocated_bytes)
            .transpose()?
            .unwrap_or(0);
        let identity_bytes = prepared.identity.allocated_bytes()?;
        let [credit, future, identity_credit] =
            prepaid.split_group([std::mem::size_of::<Owner>(), history_bytes, identity_bytes])?;
        let prepared = candidate
            .take()
            .expect("validated parent observation preparation");
        let identity = prepared.identity.into_prepaid(
            identity_credit,
            prepared.spec.identity_recipe(),
            handle,
            Some(epoch),
            ObservationProtection::mutation(protection),
        );
        Ok(Owner {
            phase: Phase::Identity(identity),
            spec: prepared.spec,
            history: prepared.history,
            handle,
            epoch,
            protection: ObservationProtection::mutation(protection),
            prepaid: future,
            _credit: credit,
        })
    }

    pub(super) fn bind(
        self,
        handle: CK_OBJECT_HANDLE,
        epoch: u64,
        protection: ObservationProtection,
        prepaid: &mut Credit,
    ) -> Result<Owner> {
        // Deferred history must outlive neither its reservation nor a failed
        // identity binding. Declare the credit before moving that storage.
        let future;
        let storage = self;
        let credit = prepaid.split(std::mem::size_of::<Owner>())?;
        future = prepaid.split(
            storage
                .history
                .as_ref()
                .map(ReadStorage::allocated_bytes)
                .transpose()?
                .unwrap_or(0),
        )?;
        let identity = storage.identity.bind_with_protection(
            prepaid,
            storage.spec.identity_recipe(),
            handle,
            Some(epoch),
            protection.duplicate()?,
        )?;
        Ok(Owner {
            phase: Phase::Identity(identity),
            spec: storage.spec,
            history: storage.history,
            handle,
            epoch,
            protection,
            prepaid: future,
            _credit: credit,
        })
    }
}
enum Phase {
    Identity(LegacyOwner),
    History(LegacyOwner),
    Complete(BaseProtection),
    Stopped,
}
pub(super) struct Owner {
    phase: Phase,
    spec: Spec,
    history: Option<ReadStorage>,
    handle: CK_OBJECT_HANDLE,
    epoch: u64,
    protection: ObservationProtection,
    prepaid: Credit,
    _credit: Credit,
}
impl Owner {
    pub(super) fn pending(&self) -> bool {
        match &self.phase {
            Phase::Identity(read) | Phase::History(read) => read.pending(),
            _ => false,
        }
    }
    pub(super) fn complete(&self) -> bool {
        matches!(self.phase, Phase::Complete(_))
    }
    pub(super) fn need(&self) -> Option<ValueNeed> {
        match &self.phase {
            Phase::Identity(read) | Phase::History(read) => read.need(),
            _ => None,
        }
    }
    pub(super) fn attach(
        &mut self,
        need: ValueNeed,
        value: crate::attributes::owned::resident::ValueCandidate,
    ) -> Result<()> {
        match &mut self.phase {
            Phase::Identity(read) | Phase::History(read) => read.attach(need, value),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::DerivationObservationAttachmentPhase,
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
                Phase::Identity(read) | Phase::History(read) => {
                    read.advance(session, access, self.handle)?;
                    if !read.complete() {
                        return Ok(());
                    }
                }
                Phase::Complete(_) => return Ok(()),
                Phase::Stopped => {
                    return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                        crate::KeyDerivationRejection::DerivationObservationStopped,
                    )))
                }
            }
            self.phase = match std::mem::replace(&mut self.phase, Phase::Stopped) {
                Phase::Identity(read) => {
                    self.spec
                        .identity
                        .validate(&read.required_result(session, access)?)?;
                    match self.history.take() {
                        Some(storage) => Phase::History(storage.bind_with_protection(
                            &mut self.prepaid,
                            Recipe::History(self.spec.history),
                            self.handle,
                            Some(self.epoch),
                            self.protection.duplicate()?,
                        )?),
                        None => Phase::Complete(history::snapshot(
                            self.spec.history,
                            &crate::attributes::ObservedAttributes::empty(),
                        )),
                    }
                }
                Phase::History(read) => {
                    Phase::Complete(read.history_result(session, access, self.spec.history)?)
                }
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                        crate::KeyDerivationRejection::DerivationObservationTransition,
                    )))
                }
            };
        }
    }
    pub(super) fn result(self) -> Result<BaseProtection> {
        match self.phase {
            Phase::Complete(value) => Ok(value),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::DerivationObservationIncomplete,
            ))),
        }
    }
}
