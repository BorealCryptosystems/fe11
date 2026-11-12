// SPDX-License-Identifier: Apache-2.0
//! Result views for the shared symmetric admission driver.
use super::{input::SymmetricInput, keys, OperationProgress};
use crate::{
    BaseProtection, IntroductionOrigin, ManagedObjectRef, MechanismObservationReport, Result,
    Session, SymmetricIntroductionSpec, SymmetricKey, SymmetricKeySpec,
};

pub(super) enum Publication {
    Ordinary,
    Introduced { view: IntroductionView },
}

#[derive(Clone, Copy)]
pub(super) enum IntroductionView {
    Symmetric,
    AesKek { usage: crate::KeyTransportUsage },
}

impl SymmetricInput {
    pub(super) fn aes_kek(spec: crate::AesKeyEncryptionSpec) -> Result<Self> {
        spec.validate()?;
        let crate::AesKeyEncryptionSpec {
            native_protection,
            history_observation,
            key,
            usage,
        } = spec;
        Self::introduction(
            SymmetricIntroductionSpec {
                native_protection,
                history_observation,
                key,
            },
            IntroductionView::AesKek { usage },
        )
    }

    pub(super) fn introduced_symmetric(spec: SymmetricIntroductionSpec) -> Result<Self> {
        let view = IntroductionView::Symmetric;
        Self::introduction(spec, view)
    }

    fn introduction(spec: SymmetricIntroductionSpec, view: IntroductionView) -> Result<Self> {
        spec.validate()?;
        let SymmetricIntroductionSpec {
            native_protection,
            history_observation,
            mut key,
        } = spec;
        // The introduction request owns these choices. The nested key supplies
        // identity, algorithm, usages and object/mechanism admission only.
        key.protection_request = native_protection;
        key.history = history_observation;
        Ok(Self {
            spec: key,
            publication: Publication::Introduced { view },
        })
    }
}

impl Publication {
    pub(super) fn finish(
        &mut self,
        _session: &Session,
        spec: &SymmetricKeySpec,
        managed: ManagedObjectRef,
        snapshot: BaseProtection,
        allowed: MechanismObservationReport,
        generated: bool,
    ) -> Result<OperationProgress> {
        match self {
            Self::Ordinary => {
                let invocation = if generated {
                    crate::GenerationInvocation::GeneratedByThisCall {
                        mechanism: spec.algorithm.generation(spec.hmac_key_type)? as u64,
                    }
                } else {
                    crate::GenerationInvocation::NotGeneratedByThisCall
                };
                let protection = keys::protection_snapshot(snapshot, invocation);
                Ok(OperationProgress::SymmetricKey(SymmetricKey {
                    managed,
                    algorithm: spec.algorithm,
                    protection,
                    allowed,
                }))
            }
            Self::Introduced { view } => {
                let origin = if generated {
                    IntroductionOrigin::Generated
                } else {
                    match snapshot.local {
                        crate::Observation::Observed(true) => IntroductionOrigin::ObservedLocal,
                        crate::Observation::Observed(false) => IntroductionOrigin::ObservedNonLocal,
                        _ => IntroductionOrigin::ObservedUnknown,
                    }
                };
                let observed = crate::transport::secret_keys::report(snapshot, origin)?;

                Ok(match *view {
                    IntroductionView::Symmetric => OperationProgress::IntroducedSymmetricKey(
                        crate::transport::secret_keys::finish_from_parts(
                            managed,
                            spec.algorithm,
                            observed,
                            allowed,
                        ),
                    ),
                    IntroductionView::AesKek { usage, .. } => {
                        OperationProgress::AesKeyEncryptionKey(
                            crate::AesKeyEncryptionKey::from_parts(
                                managed, usage, observed, allowed,
                            ),
                        )
                    }
                })
            }
        }
    }
}
