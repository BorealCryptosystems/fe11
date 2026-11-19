// SPDX-License-Identifier: Apache-2.0
//! Explicit RSA-PSS hash and MGF selectors shared by public fixtures.
use super::outcome::Failure;
use fe11::NativePssAlgorithm;

pub(super) struct Hash {
    pub number: u64,
    pub mgf: u64,
    pub combined: NativePssAlgorithm,
    pub bytes: usize,
}

pub(super) fn hash(name: &str) -> std::result::Result<Hash, Failure> {
    use fe11_sys::*;
    let (number, mgf, combined, bytes) = match name {
        "SHA1" => (
            CKM_SHA_1,
            CKG_MGF1_SHA1,
            NativePssAlgorithm::SHA1_RSA_PKCS_PSS,
            20,
        ),
        "SHA224" => (
            CKM_SHA224,
            CKG_MGF1_SHA224,
            NativePssAlgorithm::SHA224_RSA_PKCS_PSS,
            28,
        ),
        "SHA256" => (
            CKM_SHA256,
            CKG_MGF1_SHA256,
            NativePssAlgorithm::SHA256_RSA_PKCS_PSS,
            32,
        ),
        "SHA384" => (
            CKM_SHA384,
            CKG_MGF1_SHA384,
            NativePssAlgorithm::SHA384_RSA_PKCS_PSS,
            48,
        ),
        "SHA512" => (
            CKM_SHA512,
            CKG_MGF1_SHA512,
            NativePssAlgorithm::SHA512_RSA_PKCS_PSS,
            64,
        ),
        "SHA3_224" => (
            CKM_SHA3_224,
            CKG_MGF1_SHA3_224,
            NativePssAlgorithm::SHA3_224_RSA_PKCS_PSS,
            28,
        ),
        "SHA3_256" => (
            CKM_SHA3_256,
            CKG_MGF1_SHA3_256,
            NativePssAlgorithm::SHA3_256_RSA_PKCS_PSS,
            32,
        ),
        "SHA3_384" => (
            CKM_SHA3_384,
            CKG_MGF1_SHA3_384,
            NativePssAlgorithm::SHA3_384_RSA_PKCS_PSS,
            48,
        ),
        "SHA3_512" => (
            CKM_SHA3_512,
            CKG_MGF1_SHA3_512,
            NativePssAlgorithm::SHA3_512_RSA_PKCS_PSS,
            64,
        ),
        _ => return Err(Failure::Input("rsa_domain_hash")),
    };
    Ok(Hash {
        number: number as u64,
        mgf: mgf as u64,
        combined,
        bytes,
    })
}
