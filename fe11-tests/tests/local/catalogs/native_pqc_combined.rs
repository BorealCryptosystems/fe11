// SPDX-License-Identifier: Apache-2.0
//! Standard selector membership and exact PKCS#11 identifier mapping.
use fe11::NativePqcCombined;

#[test]
fn members_and_native_identifiers() {
    let expected = [
        (NativePqcCombined::HASH_ML_DSA_SHA224, fe11_sys::CKM_HASH_ML_DSA_SHA224 as u64),
        (NativePqcCombined::HASH_ML_DSA_SHA256, fe11_sys::CKM_HASH_ML_DSA_SHA256 as u64),
        (NativePqcCombined::HASH_ML_DSA_SHA384, fe11_sys::CKM_HASH_ML_DSA_SHA384 as u64),
        (NativePqcCombined::HASH_ML_DSA_SHA3_224, fe11_sys::CKM_HASH_ML_DSA_SHA3_224 as u64),
        (NativePqcCombined::HASH_ML_DSA_SHA3_256, fe11_sys::CKM_HASH_ML_DSA_SHA3_256 as u64),
        (NativePqcCombined::HASH_ML_DSA_SHA3_384, fe11_sys::CKM_HASH_ML_DSA_SHA3_384 as u64),
        (NativePqcCombined::HASH_ML_DSA_SHA3_512, fe11_sys::CKM_HASH_ML_DSA_SHA3_512 as u64),
        (NativePqcCombined::HASH_ML_DSA_SHA512, fe11_sys::CKM_HASH_ML_DSA_SHA512 as u64),
        (NativePqcCombined::HASH_ML_DSA_SHAKE128, fe11_sys::CKM_HASH_ML_DSA_SHAKE128 as u64),
        (NativePqcCombined::HASH_ML_DSA_SHAKE256, fe11_sys::CKM_HASH_ML_DSA_SHAKE256 as u64),
        (NativePqcCombined::HASH_SLH_DSA_SHA224, fe11_sys::CKM_HASH_SLH_DSA_SHA224 as u64),
        (NativePqcCombined::HASH_SLH_DSA_SHA256, fe11_sys::CKM_HASH_SLH_DSA_SHA256 as u64),
        (NativePqcCombined::HASH_SLH_DSA_SHA384, fe11_sys::CKM_HASH_SLH_DSA_SHA384 as u64),
        (NativePqcCombined::HASH_SLH_DSA_SHA3_224, fe11_sys::CKM_HASH_SLH_DSA_SHA3_224 as u64),
        (NativePqcCombined::HASH_SLH_DSA_SHA3_256, fe11_sys::CKM_HASH_SLH_DSA_SHA3_256 as u64),
        (NativePqcCombined::HASH_SLH_DSA_SHA3_384, fe11_sys::CKM_HASH_SLH_DSA_SHA3_384 as u64),
        (NativePqcCombined::HASH_SLH_DSA_SHA3_512, fe11_sys::CKM_HASH_SLH_DSA_SHA3_512 as u64),
        (NativePqcCombined::HASH_SLH_DSA_SHA512, fe11_sys::CKM_HASH_SLH_DSA_SHA512 as u64),
        (NativePqcCombined::HASH_SLH_DSA_SHAKE128, fe11_sys::CKM_HASH_SLH_DSA_SHAKE128 as u64),
        (NativePqcCombined::HASH_SLH_DSA_SHAKE256, fe11_sys::CKM_HASH_SLH_DSA_SHAKE256 as u64),
    ];
    assert_eq!(NativePqcCombined::ALL.len(), expected.len());
    for (member, identifier) in expected {
        assert_eq!(member.mechanism_number(), identifier);
        assert_eq!(NativePqcCombined::ALL.iter().filter(|value| **value == member).count(),
            expected.iter().filter(|(value, _)| *value == member).count());
    }
}
