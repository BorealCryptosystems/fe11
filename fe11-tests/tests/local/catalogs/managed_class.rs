// SPDX-License-Identifier: Apache-2.0
//! Standard selector membership and exact PKCS#11 identifier mapping.
use fe11::ManagedClass;

#[test]
fn members_and_native_identifiers() {
    let expected = [
        (ManagedClass::Certificate, fe11_sys::CKO_CERTIFICATE as u64),
        (ManagedClass::Data, fe11_sys::CKO_DATA as u64),
        (ManagedClass::DomainParameters, fe11_sys::CKO_DOMAIN_PARAMETERS as u64),
        (ManagedClass::HardwareFeature, fe11_sys::CKO_HW_FEATURE as u64),
        (ManagedClass::Mechanism, fe11_sys::CKO_MECHANISM as u64),
        (ManagedClass::OtpKey, fe11_sys::CKO_OTP_KEY as u64),
        (ManagedClass::PrivateKey, fe11_sys::CKO_PRIVATE_KEY as u64),
        (ManagedClass::Profile, fe11_sys::CKO_PROFILE as u64),
        (ManagedClass::PublicKey, fe11_sys::CKO_PUBLIC_KEY as u64),
        (ManagedClass::SecretKey, fe11_sys::CKO_SECRET_KEY as u64),
        (ManagedClass::Trust, fe11_sys::CKO_TRUST as u64),
        (ManagedClass::Validation, fe11_sys::CKO_VALIDATION as u64),
    ];
    assert_eq!(ManagedClass::ALL.len(), expected.len());
    for (member, identifier) in expected {
        assert_eq!(member.identifier(), identifier);
        assert_eq!(ManagedClass::ALL.iter().filter(|value| **value == member).count(),
            expected.iter().filter(|(value, _)| *value == member).count());
        assert_eq!(ManagedClass::from_identifier(identifier), Some(member));
    }
}
