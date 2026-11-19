// SPDX-License-Identifier: Apache-2.0
//! Public representation errors remain distinguishable without native execution.
use fe11::*;

#[test]
fn unsigned_array_requires_an_array_attribute() {
    let mut observation = FlatAttributeObservation {
        attribute: AttributeType::Standard(StandardAttribute::LABEL),
        calls: AttributeReadCalls::Size { code: 0 },
        value: FlatAttributeValue::SizeKnown { required: 0 },
    };
    assert!(matches!(
        observation.unsigned_values(),
        Err(Error::Rejected(RejectionReason::AttributeValues(
            AttributeValuesRejection::AttributeIsNotAnUnsignedArray
        )))
    ));
    // With an array identity, the next check correctly distinguishes missing
    // value bytes from a present, empty array; size alone does not supply bytes.
    observation.attribute = AttributeType::Standard(StandardAttribute::ALLOWED_MECHANISMS);
    assert!(matches!(
        observation.unsigned_values(),
        Err(Error::Rejected(RejectionReason::AttributeValues(
            AttributeValuesRejection::AttributeValueUnavailable
        )))
    ));
}

#[test]
fn dsa_digest_width_is_explicit() {
    assert!(DsaVerificationDigest::from_bytes(DsaVerificationHash::Sha1, &[0; 20]).is_ok());
    assert!(matches!(
        DsaVerificationDigest::from_bytes(DsaVerificationHash::Sha1, &[0; 19]),
        Err(Error::Rejected(RejectionReason::ClassicalSignatures(
            ClassicalSignaturesRejection::DsaDigestWidth
        )))
    ));
    assert!(DsaVerificationDigest::from_bytes(DsaVerificationHash::Sha1, &[0; 20]).is_ok());
}

#[test]
fn historical_digest_width_is_explicit() {
    assert!(HistoricalDigest::from_bytes(HistoricalHash::Sha1, &[0; 20]).is_ok());
    assert!(matches!(
        HistoricalDigest::from_bytes(HistoricalHash::Sha1, &[0; 19]),
        Err(Error::Rejected(RejectionReason::ClassicalSignatures(
            ClassicalSignaturesRejection::HistoricalDigestWidth
        )))
    ));
    assert!(HistoricalDigest::from_bytes(HistoricalHash::Sha1, &[0; 20]).is_ok());
}

#[test]
fn absent_general_mac_has_no_invented_mechanism() {
    let algorithm = NativeMacAlgorithm::AES_XCBC_MAC;
    assert_eq!(
        NativeMacParameters::Full(algorithm)
            .mechanism_number()
            .unwrap(),
        fe11_sys::CKM_AES_XCBC_MAC as u64
    );
    assert!(matches!(
        NativeMacParameters::General {
            algorithm,
            output_bytes: 8
        }
        .mechanism_number(),
        Err(Error::Unsupported(UnsupportedReason::NativeMac(
            NativeMacUnsupported::MacHasNoGeneralLengthVariant
        )))
    ));
    assert_eq!(
        NativeMacParameters::Full(algorithm)
            .mechanism_number()
            .unwrap(),
        fe11_sys::CKM_AES_XCBC_MAC as u64
    );
}
