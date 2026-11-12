// SPDX-License-Identifier: Apache-2.0
//! Historical public DSA only; no private scalar or signing operation.

use super::integer_key::bit_length;
use crate::{Error, Result};

use der::{
    asn1::{ObjectIdentifier, UintRef},
    Decode, Sequence,
};
use x509_cert::spki::SubjectPublicKeyInfoRef;

#[derive(Sequence)]
struct Domain<'a> {
    p: UintRef<'a>,
    q: UintRef<'a>,
    g: UintRef<'a>,
}
pub(super) struct DsaPublic<'a> {
    pub p: &'a [u8],
    pub q: &'a [u8],
    pub g: &'a [u8],
    pub y: &'a [u8],
}
#[derive(Clone)]
pub(super) struct DsaMetadata {
    pub order: Vec<u8>,
}

pub(super) fn dsa_der(bytes: &[u8]) -> Result<DsaPublic<'_>> {
    if bytes.is_empty() {
        return Err(Error::Rejected(
            crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::SpkiSize,
            ),
        ));
    }
    let spki = SubjectPublicKeyInfoRef::from_der(bytes).map_err(|_| {
        Error::Rejected(crate::RejectionReason::ClassicalSignatures(
            crate::ClassicalSignaturesRejection::DsaSpkiDer,
        ))
    })?;
    if !super::canonical::matches(&spki, bytes).map_err(|_| {
        Error::Rejected(crate::RejectionReason::ClassicalSignatures(
            crate::ClassicalSignaturesRejection::DsaSpkiEncoding,
        ))
    })? {
        return Err(Error::Rejected(
            crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::NoncanonicalDsaSpki,
            ),
        ));
    }
    if spki.algorithm.oid != ObjectIdentifier::new_unwrap("1.2.840.10040.4.1") {
        return Err(Error::Rejected(
            crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::DsaAlgorithm,
            ),
        ));
    }
    let domain = spki
        .algorithm
        .parameters
        .ok_or(Error::Rejected(
            crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::DsaDomainMissing,
            ),
        ))?
        .decode_as::<Domain>()
        .map_err(|_| {
            Error::Rejected(crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::DsaDomainDer,
            ))
        })?;
    let raw = spki.subject_public_key.as_bytes().ok_or(Error::Rejected(
        crate::RejectionReason::ClassicalSignatures(
            crate::ClassicalSignaturesRejection::DsaUnusedBits,
        ),
    ))?;
    let y = UintRef::from_der(raw).map_err(|_| {
        Error::Rejected(crate::RejectionReason::ClassicalSignatures(
            crate::ClassicalSignaturesRejection::DsaPublicInteger,
        ))
    })?;
    if !super::canonical::matches(&y, raw).map_err(|_| {
        Error::Rejected(crate::RejectionReason::ClassicalSignatures(
            crate::ClassicalSignaturesRejection::DsaPublicEncoding,
        ))
    })? {
        return Err(Error::Rejected(
            crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::NoncanonicalDsaPublicValue,
            ),
        ));
    }
    let (p, q, g, y) = (
        domain.p.as_bytes(),
        domain.q.as_bytes(),
        domain.g.as_bytes(),
        y.as_bytes(),
    );
    // Preserve checked integer-width validation without retaining unused metadata.
    bit_length(p)?;
    Ok(DsaPublic { p, q, g, y })
}
