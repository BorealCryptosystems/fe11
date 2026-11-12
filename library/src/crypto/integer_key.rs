// SPDX-License-Identifier: Apache-2.0
//! Canonical public RSA encoding. Mathematical key validity belongs to the native module.

use crate::{Error, Result};
use der::{
    asn1::{Null, ObjectIdentifier, UintRef},
    Decode, Encode, Sequence,
};
use x509_cert::spki::SubjectPublicKeyInfoRef;
mod encoding;
pub(crate) use encoding::RsaSpki;

/// Descriptive exponent range, separate from acceptance, hash profile and trust.
/// Neither range permits or rejects a native operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaExponentClass {
    /// The exponent satisfies 2^16 < e < 2^256, not a generation attestation.
    ModernBound,
    /// Exponent outside the stated interval; no usability or policy conclusion.
    OutsideModernBound,
}
#[derive(Sequence)]
struct RsaDer<'a> {
    modulus: UintRef<'a>,
    exponent: UintRef<'a>,
}
pub(crate) struct RsaPublic<'a> {
    pub modulus: &'a [u8],
    pub exponent: &'a [u8],
    pub bits: usize,
    pub exponent_class: RsaExponentClass,
}

/// Internal public DER owner: credit remains live throughout encoding and
/// observation. Publication transfers these public bytes to caller ownership.
pub(crate) struct PublicDer {
    bytes: Vec<u8>,
    _credit: crate::symmetric::memory::Credit,
}

/// Unpublished capacity for a borrowed public encoding or caller declaration.
/// This owner does not validate bytes. The enclosing operation's selected checks
/// determine provenance; admission measures capacity before copying or publishing.
pub(crate) struct PublicDerStorage {
    bytes: Vec<u8>,
}
impl PublicDerStorage {
    pub(crate) fn allocate(length: usize) -> Result<Self> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyEncoding(
                crate::KeyEncodingRejection::PublicDerAllocation,
            ))
        })?;
        Ok(Self { bytes })
    }

    pub(crate) fn allocated(&self) -> usize {
        self.bytes.capacity()
    }

    /// Encode only into already admitted storage. No allocation or credit wait
    /// occurs while the returned native attributes are being accepted.
    fn encode(
        mut self,
        value: &impl Encode,
        credit: crate::symmetric::memory::Credit,
    ) -> Result<PublicDer> {
        let length = usize::try_from(value.encoded_len().map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyEncoding(
                crate::KeyEncodingRejection::PublicDerLength,
            ))
        })?)
        .map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyEncoding(
                crate::KeyEncodingRejection::PublicDerWidth,
            ))
        })?;
        if length > self.bytes.capacity() {
            return Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
                crate::KeyEncodingRejection::PublicDerAllocation,
            )));
        }
        self.bytes.resize(length, 0);
        let encoded = value.encode_to_slice(&mut self.bytes).map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyEncoding(
                crate::KeyEncodingRejection::PublicDerEncoding,
            ))
        })?;
        if encoded.len() != length {
            return Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
                crate::KeyEncodingRejection::PublicDerLength,
            )));
        }
        Ok(PublicDer {
            bytes: self.bytes,
            _credit: credit,
        })
    }

    pub(crate) fn bind(
        mut self,
        source: &[u8],
        prepaid: &mut crate::symmetric::memory::Credit,
    ) -> Result<PublicDer> {
        if source.len() > self.bytes.capacity() {
            return Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
                crate::KeyEncodingRejection::PublicDerAllocation,
            )));
        }
        let credit = prepaid.split(self.bytes.capacity())?;
        self.bytes.extend_from_slice(source);
        Ok(PublicDer {
            bytes: self.bytes,
            _credit: credit,
        })
    }
}

/// Empty storage prepared outside coordination guards for a completed native
/// observation. It contains no attribute bytes, object handles or native frame.
pub(crate) struct PublicDerCandidate {
    need: PublicDerNeed,
    storage: PublicDerStorage,
    copies: Option<(PublicDerStorage, PublicDerStorage)>,
    credit: crate::symmetric::memory::Credit,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PublicDerNeed {
    length: usize,
    transport: bool,
}
impl PublicDerNeed {
    pub(crate) fn new(length: usize, transport: bool) -> Self {
        Self { length, transport }
    }
}
pub(crate) struct PublicDerSet {
    pub(crate) primary: PublicDer,
    pub(crate) transport: Option<(PublicDer, PublicDer)>,
}
pub(crate) enum PublicDerPreparation<T> {
    Ready(PublicDerCandidate),
    Redirect(T),
}
impl PublicDerCandidate {
    pub(crate) fn need(&self) -> PublicDerNeed {
        self.need
    }

    pub(crate) fn prepare<T>(
        need: PublicDerNeed,
        budget: &std::sync::Arc<crate::symmetric::memory::Budget>,
        admission: &crate::ResourceAdmission,
        before: impl FnMut() -> Result<Option<T>>,
    ) -> Result<PublicDerPreparation<T>> {
        Self::prepare_retaining(need, budget, 0, admission, before)
    }

    pub(crate) fn prepare_retaining<T>(
        need: PublicDerNeed,
        budget: &std::sync::Arc<crate::symmetric::memory::Budget>,
        retained_bytes: usize,
        admission: &crate::ResourceAdmission,
        mut before: impl FnMut() -> Result<Option<T>>,
    ) -> Result<PublicDerPreparation<T>> {
        use crate::symmetric::memory::ControlledReservation;
        let mut bytes = need
            .length
            .checked_mul(if need.transport { 3 } else { 1 })
            .ok_or(Error::Rejected(crate::RejectionReason::KeyEncoding(
                crate::KeyEncodingRejection::PublicDerWidth,
            )))?;
        loop {
            let mut credit = match budget.reserve_controlled_retaining(
                bytes,
                crate::session::lifecycle_diagnostics::Store::including(retained_bytes)?,
                admission,
                &mut before,
                || Ok(None),
            )? {
                ControlledReservation::Acquired(credit) => credit,
                ControlledReservation::Redirect(route) => {
                    return Ok(PublicDerPreparation::Redirect(route))
                }
            };
            let storage = PublicDerStorage::allocate(need.length)?;
            let copies = if need.transport {
                Some((
                    PublicDerStorage::allocate(need.length)?,
                    PublicDerStorage::allocate(need.length)?,
                ))
            } else {
                None
            };
            let mut actual = storage.allocated();
            if let Some((public, private)) = &copies {
                actual = actual
                    .checked_add(public.allocated())
                    .and_then(|n| n.checked_add(private.allocated()))
                    .ok_or(Error::Rejected(crate::RejectionReason::KeyEncoding(
                        crate::KeyEncodingRejection::PublicDerWidth,
                    )))?;
            }
            if actual > bytes {
                drop(copies);
                drop(storage);
                drop(credit);
                bytes = actual;
                continue;
            }
            credit.release(bytes - actual);
            return Ok(PublicDerPreparation::Ready(Self {
                need,
                storage,
                copies,
                credit,
            }));
        }
    }

    pub(crate) fn encode(self, value: &impl Encode) -> Result<PublicDerSet> {
        let length = usize::try_from(value.encoded_len().map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyEncoding(
                crate::KeyEncodingRejection::PublicDerLength,
            ))
        })?)
        .map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyEncoding(
                crate::KeyEncodingRejection::PublicDerWidth,
            ))
        })?;
        if length != self.need.length {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AdmissionPreparationChanged,
            )));
        }
        let Self {
            storage,
            copies,
            mut credit,
            ..
        } = self;
        let primary_credit = credit.split(storage.allocated())?;
        let primary = storage.encode(value, primary_credit)?;
        let transport = match copies {
            Some((public, private)) => Some((
                public.bind(&primary, &mut credit)?,
                private.bind(&primary, &mut credit)?,
            )),
            None => None,
        };
        Ok(PublicDerSet { primary, transport })
    }
}

impl PublicDer {
    pub(crate) fn allocated_bytes(&self) -> usize {
        self.bytes.capacity()
    }
    /// Terminal publication transfers the already admitted allocation to the
    /// caller. The enclosing operation retains its credit until retirement.
    pub(crate) fn take_bytes(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
impl std::ops::Deref for PublicDer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}
impl AsRef<[u8]> for PublicDer {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
impl<T: AsRef<[u8]> + ?Sized> PartialEq<T> for PublicDer {
    fn eq(&self, other: &T) -> bool {
        self.bytes.as_slice() == other.as_ref()
    }
}

/// Value view of a PKCS#11 unsigned big integer, without changing observed bytes.
/// Empty/all-zero inputs denote zero here; admissibility belongs to the module.
/// This is not appropriate for a caller-selected binary/encoding comparison.
pub(crate) fn unsigned_value(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|byte| *byte != 0) {
        Some(first) => &bytes[first..],
        None => &[0],
    }
}

pub(crate) fn bit_length(bytes: &[u8]) -> Result<usize> {
    let bytes = unsigned_value(bytes);
    bytes
        .len()
        .checked_mul(8)
        .and_then(|bits| bits.checked_sub(bytes[0].leading_zeros() as usize))
        .ok_or(Error::Rejected(crate::RejectionReason::KeyEncoding(
            crate::KeyEncodingRejection::UnsignedIntegerBitLength,
        )))
}
/// Decode canonical public material without imposing a mathematical key policy.
pub(crate) fn rsa_der(spki_der: &[u8]) -> Result<RsaPublic<'_>> {
    if spki_der.is_empty() {
        return Err(Error::Rejected(
            crate::RejectionReason::ClassicalSignatures(
                crate::ClassicalSignaturesRejection::SpkiSize,
            ),
        ));
    }
    let spki = SubjectPublicKeyInfoRef::from_der(spki_der).map_err(|_| {
        Error::Rejected(crate::RejectionReason::KeyEncoding(
            crate::KeyEncodingRejection::RsaSpkiDer,
        ))
    })?;
    if !super::canonical::matches(&spki, spki_der).map_err(|_| {
        Error::Rejected(crate::RejectionReason::KeyEncoding(
            crate::KeyEncodingRejection::RsaSpkiEncoding,
        ))
    })? {
        return Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
            crate::KeyEncodingRejection::NoncanonicalRsaSpki,
        )));
    }
    if spki.algorithm.oid != ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1") {
        return Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
            crate::KeyEncodingRejection::RsaSpkiAlgorithm,
        )));
    }
    spki.algorithm
        .parameters
        .ok_or(Error::Rejected(crate::RejectionReason::KeyEncoding(
            crate::KeyEncodingRejection::RsaNullParametersRequired,
        )))?
        .decode_as::<Null>()
        .map_err(|_| {
            Error::Rejected(crate::RejectionReason::KeyEncoding(
                crate::KeyEncodingRejection::RsaParameters,
            ))
        })?;
    let raw = spki.subject_public_key.as_bytes().ok_or(Error::Rejected(
        crate::RejectionReason::KeyEncoding(crate::KeyEncodingRejection::RsaUnusedBits),
    ))?;
    let key = RsaDer::from_der(raw).map_err(|_| {
        Error::Rejected(crate::RejectionReason::KeyEncoding(
            crate::KeyEncodingRejection::RsaPublicDer,
        ))
    })?;
    if !super::canonical::matches(&key, raw).map_err(|_| {
        Error::Rejected(crate::RejectionReason::KeyEncoding(
            crate::KeyEncodingRejection::RsaPublicEncoding,
        ))
    })? {
        return Err(Error::Rejected(crate::RejectionReason::KeyEncoding(
            crate::KeyEncodingRejection::NoncanonicalRsaPublicKey,
        )));
    }
    let (n, e) = (key.modulus.as_bytes(), key.exponent.as_bytes());
    let bits = bit_length(n)?;
    let modern = (e.len() > 3 || (e.len() == 3 && e > [1, 0, 0].as_slice())) && e.len() <= 32;
    Ok(RsaPublic {
        modulus: n,
        exponent: e,
        bits,
        exponent_class: if modern {
            RsaExponentClass::ModernBound
        } else {
            RsaExponentClass::OutsideModernBound
        },
    })
}
