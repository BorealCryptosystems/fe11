// SPDX-License-Identifier: Apache-2.0
//! Borrowed RSA SPKI encoding, without an intermediate PKCS#1 allocation.
use super::RsaDer;
use crate::{Error, Result};
use der::{
    asn1::{AnyRef, ObjectIdentifier, UintRef},
    Encode, EncodeValue, FixedTag, Length, Tag, Writer,
};
use x509_cert::spki::AlgorithmIdentifierRef;

/// The standard DER encoder still writes every tag, length and integer.
/// Only the BIT STRING's zero unused-bit octet is supplied by this wrapper.
struct RsaBits<'r, 'a>(&'r RsaDer<'a>);
impl FixedTag for RsaBits<'_, '_> {
    const TAG: Tag = Tag::BitString;
}
impl EncodeValue for RsaBits<'_, '_> {
    fn value_len(&self) -> der::Result<Length> {
        self.0.encoded_len()? + Length::ONE
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        writer.write_byte(0)?;
        self.0.encode(writer)
    }
}

pub(crate) struct RsaSpki<'a>(RsaDer<'a>);
impl<'a> RsaSpki<'a> {
    pub(crate) fn new(modulus: &'a [u8], exponent: &'a [u8]) -> Result<Self> {
        Ok(Self(RsaDer {
            modulus: UintRef::new(super::unsigned_value(modulus)).map_err(|_| {
                Error::Rejected(crate::RejectionReason::KeyEncoding(
                    crate::KeyEncodingRejection::RsaModulusEncoding,
                ))
            })?,
            exponent: UintRef::new(super::unsigned_value(exponent)).map_err(|_| {
                Error::Rejected(crate::RejectionReason::KeyEncoding(
                    crate::KeyEncodingRejection::RsaExponentEncoding,
                ))
            })?,
        }))
    }

    pub(crate) fn modulus_bits(&self) -> Result<usize> {
        super::bit_length(self.0.modulus.as_bytes())
    }

    fn algorithm() -> AlgorithmIdentifierRef<'static> {
        AlgorithmIdentifierRef {
            oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1"),
            parameters: Some(AnyRef::NULL),
        }
    }
}
impl FixedTag for RsaSpki<'_> {
    const TAG: Tag = Tag::Sequence;
}
impl EncodeValue for RsaSpki<'_> {
    fn value_len(&self) -> der::Result<Length> {
        Self::algorithm().encoded_len()? + RsaBits(&self.0).encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        Self::algorithm().encode(writer)?;
        RsaBits(&self.0).encode(writer)
    }
}
