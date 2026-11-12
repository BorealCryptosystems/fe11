// SPDX-License-Identifier: Apache-2.0
use super::*;
use super::{
    introduced::Material,
    operations::{Output, ParameterPlan},
};
use crate::{Session, SymmetricKeySpec, TransportProtection};

/// Observations for one ECDH call from an introduced protected/exportable base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntroducedDerivationProvenance {
    path: DerivationPath,
    parent: TransportProtection,
    child: BaseProtection,
}
impl IntroducedDerivationProvenance {
    pub(super) fn new(kdf: EcdhKdf, parent: TransportProtection, child: BaseProtection) -> Self {
        Self {
            path: DerivationPath::Ecdh(kdf),
            parent,
            child,
        }
    }
    /// Exact ECDH KDF used by the single native call.
    pub fn path(&self) -> DerivationPath {
        self.path
    }
    /// Parent observations, including each exact historical absence category.
    pub fn parent(&self) -> TransportProtection {
        self.parent
    }
    /// Actual child observations; protection is not inferred from the request.
    pub fn child(&self) -> BaseProtection {
        self.child
    }
}
/// AES/HMAC result from an introduced agreement base, with requested native
/// protection attributes and separately reported observations.
pub struct IntroducedDerivedSymmetricKey {
    key: SymmetricKey,
    provenance: IntroducedDerivationProvenance,
}
impl IntroducedDerivedSymmetricKey {
    /// Use through symmetric operations that retain the key protection observations.
    pub fn key(&self) -> &SymmetricKey {
        &self.key
    }
    /// Exact parent/child observations and their propagation comparison.
    pub fn provenance(&self) -> &IntroducedDerivationProvenance {
        &self.provenance
    }
}
impl Session {
    fn derive_introduced_parts(
        &self,
        base: &Material,
        peer: &AgreementPeer,
        kdf: EcdhKdf,
        shared_data: &[u8],
        output: SymmetricKeySpec,
        child_observations: HistoryObservationPlan,
        diagnostics: &mut crate::error::ObjectCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<IntroducedDerivedSymmetricKey>> {
        if base.spec.key.curve != peer.curve {
            return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                crate::KeyDerivationRejection::AgreementCurveMismatch,
            )));
        }
        let params = ParameterPlan::ec(peer, kdf, shared_data)?;
        let parent = resident::ParentSelection::Introduced {
            shape: observation::Spec {
                identity: observation::Identity::IntroducedEc(base.spec.key.curve),
                maximum: base.spec.key.private_admission.metadata.maximum_bytes,
                history: base.spec.history_observation,
            },
            kdf,
        };
        self.derive_with(
            &base.managed,
            params,
            Output::Symmetric(output),
            parent,
            &child_observations,
            diagnostics,
            |managed, output, evidence| {
                let Output::Symmetric(spec) = output else {
                    return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                        crate::KeyDerivationRejection::IntroducedAgreementDestination,
                    )));
                };
                let resident::Provenance::Introduced(provenance) = evidence.provenance else {
                    return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                        crate::KeyDerivationRejection::IntroducedDerivationProvenanceKind,
                    )));
                };
                let output_observation::Evidence::Symmetric {
                    protection,
                    mechanisms,
                } = evidence.output
                else {
                    return Err(Error::Rejected(crate::RejectionReason::KeyDerivation(
                        crate::KeyDerivationRejection::IntroducedDerivationEvidenceKind,
                    )));
                };
                Ok(IntroducedDerivedSymmetricKey {
                    key: SymmetricKey {
                        managed,
                        algorithm: spec.algorithm,
                        protection,
                        allowed: mechanisms,
                    },
                    provenance,
                })
            },
        )
    }
    /// Derive an AES/HMAC key with an explicitly introduced agreement base.
    /// The caller selects native protection attributes; Fe11 does not impose them.
    /// Peer identity/authentication remains a protocol responsibility.
    pub fn derive_introduced_ecdh(
        &self,
        base: &IntroducedAgreementKey,
        peer: &AgreementPeer,
        kdf: EcdhKdf,
        shared_data: &[u8],
        output: SymmetricKeySpec,
        child_observations: HistoryObservationPlan,
    ) -> Result<crate::CreatedObjects<IntroducedDerivedSymmetricKey>> {
        let mut diagnostics = None;
        self.derive_introduced_parts(
            &base.inner,
            peer,
            kdf,
            shared_data,
            output,
            child_observations,
            &mut diagnostics,
        )
    }
}
