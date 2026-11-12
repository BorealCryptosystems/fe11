// SPDX-License-Identifier: Apache-2.0
//! Verification metadata prepared with the public import's complete candidate.
use super::{
    preparation::{PublicMaterial, VerificationInput},
    RsaMetadata, VerificationKey, VerificationProfile,
};
use crate::{
    crypto::{dsa::DsaMetadata, EdwardsCurve},
    symmetric::memory::Credit,
    EcCurve, Error, ManagedObjectRef, Result,
};

/// Borrowed descriptions survive retries; only private copies are discarded.
pub(crate) struct VerificationPublicationPlan<'a> {
    profiles: &'a [VerificationProfile],
    order: Option<&'a [u8]>,
    curve: Option<EcCurve>,
    edwards: Option<EdwardsCurve>,
    rsa: Option<RsaMetadata>,
    fingerprint: [u8; 32],
}
pub(crate) struct VerificationPublicationStorage {
    profiles: Vec<VerificationProfile>,
    order: Option<Vec<u8>>,
}
pub(crate) struct VerificationPublication {
    profiles: Vec<VerificationProfile>,
    dsa: Option<DsaMetadata>,
    curve: Option<EcCurve>,
    edwards: Option<EdwardsCurve>,
    rsa: Option<RsaMetadata>,
    fingerprint: [u8; 32],
    credit: Credit,
}
fn bytes(profiles: usize, order: usize) -> Result<usize> {
    profiles
        .checked_mul(std::mem::size_of::<VerificationProfile>())
        .and_then(|size| size.checked_add(order))
        .ok_or(Error::Rejected(crate::RejectionReason::PublicVerification(
            crate::PublicVerificationRejection::VerificationPublicationSize,
        )))
}
fn copy<T: Copy>(input: &[T]) -> Result<Vec<T>> {
    let mut output = Vec::new();
    output.try_reserve_exact(input.len()).map_err(|_| {
        Error::Rejected(crate::RejectionReason::PublicVerification(
            crate::PublicVerificationRejection::VerificationPublicationAllocation,
        ))
    })?;
    output.extend_from_slice(input);
    Ok(output)
}
impl<'a> VerificationPublicationPlan<'a> {
    pub(super) fn new(
        input: &VerificationInput<'a>,
        profiles: &'a [VerificationProfile],
        fingerprint: [u8; 32],
    ) -> Self {
        let (curve, edwards) = match input.material() {
            PublicMaterial::Weierstrass(curve) => (Some(curve), None),
            PublicMaterial::Edwards(curve) => (None, Some(curve)),
            _ => (None, None),
        };
        let (rsa, order) = match input {
            VerificationInput::Rsa(key) => (
                Some(RsaMetadata {
                    bits: key.bits,
                    exponent_class: key.exponent_class,
                }),
                None,
            ),
            VerificationInput::Dsa(key) => (None, Some(key.q)),
            VerificationInput::Curve(_) => (None, None),
        };
        Self {
            profiles,
            order,
            curve,
            edwards,
            rsa,
            fingerprint,
        }
    }
    pub(crate) fn requested_bytes(&self) -> Result<usize> {
        bytes(self.profiles.len(), self.order.map_or(0, <[u8]>::len))
    }
    pub(crate) fn allocate(&self) -> Result<VerificationPublicationStorage> {
        Ok(VerificationPublicationStorage {
            profiles: copy(self.profiles)?,
            order: self.order.map(copy).transpose()?,
        })
    }
    pub(crate) fn bind(
        &self,
        storage: VerificationPublicationStorage,
        credit: &mut Credit,
    ) -> Result<VerificationPublication> {
        let credit = credit.split(storage.allocated_bytes()?)?;
        Ok(VerificationPublication {
            profiles: storage.profiles,
            dsa: storage.order.map(|order| DsaMetadata { order }),
            curve: self.curve,
            edwards: self.edwards,
            rsa: self.rsa.clone(),
            fingerprint: self.fingerprint,
            credit,
        })
    }
}
impl VerificationPublicationStorage {
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        bytes(
            self.profiles.capacity(),
            self.order.as_ref().map_or(0, Vec::capacity),
        )
    }
}
impl VerificationPublication {
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        bytes(
            self.profiles.capacity(),
            self.dsa
                .as_ref()
                .map_or(0, |metadata| metadata.order.capacity()),
        )
    }

    /// Native publication and selected observations have completed. The result
    /// takes existing buffers and their credit; this final projection allocates
    /// nothing and cannot lose an already created object through a local error.
    pub(crate) fn finish(
        self,
        managed: ManagedObjectRef,
        mechanism_report: crate::MechanismObservationReport,
    ) -> VerificationKey {
        VerificationKey {
            edwards_encoding: None,
            managed,
            fingerprint: self.fingerprint,
            profiles: self.profiles,
            mechanism_report,
            curve: self.curve,
            edwards: self.edwards,
            rsa: self.rsa,
            dsa: self.dsa,
            _import_credit: Some(self.credit),
        }
    }
}
