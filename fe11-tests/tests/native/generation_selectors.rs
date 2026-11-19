// SPDX-License-Identifier: Apache-2.0
//! Closed public generation selectors and attribute vocabulary.
use super::{generation_fixture::Generator, outcome::Failure};
use fe11::*;
pub fn generator(name: &str) -> std::result::Result<Generator, Failure> {
    match name {
        "CKM_AES_KEY_GEN" => Ok(Generator::Single(KeyGenerator::AES_KEY_GEN)),
        "CKM_DES2_KEY_GEN" => Ok(Generator::Single(KeyGenerator::DES2_KEY_GEN)),
        "CKM_DES3_KEY_GEN" => Ok(Generator::Single(KeyGenerator::DES3_KEY_GEN)),
        "CKM_DES_KEY_GEN" => Ok(Generator::Single(KeyGenerator::DES_KEY_GEN)),
        "CKM_DH_PKCS_PARAMETER_GEN" => Ok(Generator::Single(KeyGenerator::DH_PKCS_PARAMETER_GEN)),
        "CKM_DSA_PARAMETER_GEN" => Ok(Generator::Single(KeyGenerator::DSA_PARAMETER_GEN)),
        "CKM_GENERIC_SECRET_KEY_GEN" => Ok(Generator::Single(KeyGenerator::GENERIC_SECRET_KEY_GEN)),
        "CKM_DH_PKCS_KEY_PAIR_GEN" => Ok(Generator::Pair(KeyPairGenerator::DH_PKCS_KEY_PAIR_GEN)),
        "CKM_DSA_KEY_PAIR_GEN" => Ok(Generator::Pair(KeyPairGenerator::DSA_KEY_PAIR_GEN)),
        "CKM_EC_EDWARDS_KEY_PAIR_GEN" => {
            Ok(Generator::Pair(KeyPairGenerator::EC_EDWARDS_KEY_PAIR_GEN))
        }
        "CKM_EC_KEY_PAIR_GEN" => Ok(Generator::Pair(KeyPairGenerator::EC_KEY_PAIR_GEN)),
        "CKM_GOSTR3410_KEY_PAIR_GEN" => {
            Ok(Generator::Pair(KeyPairGenerator::GOSTR3410_KEY_PAIR_GEN))
        }
        "CKM_ML_DSA_KEY_PAIR_GEN" => Ok(Generator::Pair(KeyPairGenerator::ML_DSA_KEY_PAIR_GEN)),
        "CKM_ML_KEM_KEY_PAIR_GEN" => Ok(Generator::Pair(KeyPairGenerator::ML_KEM_KEY_PAIR_GEN)),
        "CKM_RSA_PKCS_KEY_PAIR_GEN" => Ok(Generator::Pair(KeyPairGenerator::RSA_PKCS_KEY_PAIR_GEN)),
        "CKM_SLH_DSA_KEY_PAIR_GEN" => Ok(Generator::Pair(KeyPairGenerator::SLH_DSA_KEY_PAIR_GEN)),
        _ => Err(Failure::Input("generation_selector")),
    }
}
pub fn attribute(name: &str) -> std::result::Result<StandardAttribute, Failure> {
    match name {
        "CKA_BASE" => Ok(StandardAttribute::BASE),
        "CKA_CLASS" => Ok(StandardAttribute::CLASS),
        "CKA_DECAPSULATE" => Ok(StandardAttribute::DECAPSULATE),
        "CKA_DECRYPT" => Ok(StandardAttribute::DECRYPT),
        "CKA_DERIVE" => Ok(StandardAttribute::DERIVE),
        "CKA_EC_PARAMS" => Ok(StandardAttribute::EC_PARAMS),
        "CKA_ENCAPSULATE" => Ok(StandardAttribute::ENCAPSULATE),
        "CKA_ENCRYPT" => Ok(StandardAttribute::ENCRYPT),
        "CKA_EXTRACTABLE" => Ok(StandardAttribute::EXTRACTABLE),
        "CKA_GOSTR3410_PARAMS" => Ok(StandardAttribute::GOSTR3410_PARAMS),
        "CKA_GOSTR3411_PARAMS" => Ok(StandardAttribute::GOSTR3411_PARAMS),
        "CKA_KEY_TYPE" => Ok(StandardAttribute::KEY_TYPE),
        "CKA_LABEL" => Ok(StandardAttribute::LABEL),
        "CKA_MODULUS_BITS" => Ok(StandardAttribute::MODULUS_BITS),
        "CKA_PARAMETER_SET" => Ok(StandardAttribute::PARAMETER_SET),
        "CKA_PRIME" => Ok(StandardAttribute::PRIME),
        "CKA_PRIME_BITS" => Ok(StandardAttribute::PRIME_BITS),
        "CKA_PRIVATE" => Ok(StandardAttribute::PRIVATE),
        "CKA_PUBLIC_EXPONENT" => Ok(StandardAttribute::PUBLIC_EXPONENT),
        "CKA_SENSITIVE" => Ok(StandardAttribute::SENSITIVE),
        "CKA_SIGN" => Ok(StandardAttribute::SIGN),
        "CKA_SUBPRIME" => Ok(StandardAttribute::SUBPRIME),
        "CKA_TOKEN" => Ok(StandardAttribute::TOKEN),
        "CKA_VALUE_LEN" => Ok(StandardAttribute::VALUE_LEN),
        "CKA_VERIFY" => Ok(StandardAttribute::VERIFY),
        "CKA_WRAP" => Ok(StandardAttribute::WRAP),
        "CKA_UNWRAP" => Ok(StandardAttribute::UNWRAP),
        _ => Err(Failure::Input("generation_attribute")),
    }
}
pub fn number(name: &str) -> std::result::Result<u64, Failure> {
    match name {
        "CKK_AES" => Ok(fe11_sys::CKK_AES as u64),
        "CKK_DES" => Ok(fe11_sys::CKK_DES as u64),
        "CKK_DES2" => Ok(fe11_sys::CKK_DES2 as u64),
        "CKK_DES3" => Ok(fe11_sys::CKK_DES3 as u64),
        "CKK_DH" => Ok(fe11_sys::CKK_DH as u64),
        "CKK_DSA" => Ok(fe11_sys::CKK_DSA as u64),
        "CKK_EC" => Ok(fe11_sys::CKK_EC as u64),
        "CKK_EC_EDWARDS" => Ok(fe11_sys::CKK_EC_EDWARDS as u64),
        "CKK_GENERIC_SECRET" => Ok(fe11_sys::CKK_GENERIC_SECRET as u64),
        "CKK_GOSTR3410" => Ok(fe11_sys::CKK_GOSTR3410 as u64),
        "CKK_ML_DSA" => Ok(fe11_sys::CKK_ML_DSA as u64),
        "CKK_ML_KEM" => Ok(fe11_sys::CKK_ML_KEM as u64),
        "CKK_RSA" => Ok(fe11_sys::CKK_RSA as u64),
        "CKK_SLH_DSA" => Ok(fe11_sys::CKK_SLH_DSA as u64),
        "CKO_DOMAIN_PARAMETERS" => Ok(fe11_sys::CKO_DOMAIN_PARAMETERS as u64),
        "CKO_PRIVATE_KEY" => Ok(fe11_sys::CKO_PRIVATE_KEY as u64),
        "CKO_PUBLIC_KEY" => Ok(fe11_sys::CKO_PUBLIC_KEY as u64),
        "CKO_SECRET_KEY" => Ok(fe11_sys::CKO_SECRET_KEY as u64),
        "CKP_ML_DSA_44" => Ok(fe11_sys::CKP_ML_DSA_44 as u64),
        "CKP_ML_DSA_65" => Ok(fe11_sys::CKP_ML_DSA_65 as u64),
        "CKP_ML_DSA_87" => Ok(fe11_sys::CKP_ML_DSA_87 as u64),
        "CKP_ML_KEM_1024" => Ok(fe11_sys::CKP_ML_KEM_1024 as u64),
        "CKP_ML_KEM_512" => Ok(fe11_sys::CKP_ML_KEM_512 as u64),
        "CKP_ML_KEM_768" => Ok(fe11_sys::CKP_ML_KEM_768 as u64),
        "CKP_SLH_DSA_SHA2_128F" => Ok(fe11_sys::CKP_SLH_DSA_SHA2_128F as u64),
        "CKP_SLH_DSA_SHA2_128S" => Ok(fe11_sys::CKP_SLH_DSA_SHA2_128S as u64),
        "CKP_SLH_DSA_SHA2_192F" => Ok(fe11_sys::CKP_SLH_DSA_SHA2_192F as u64),
        "CKP_SLH_DSA_SHA2_192S" => Ok(fe11_sys::CKP_SLH_DSA_SHA2_192S as u64),
        "CKP_SLH_DSA_SHA2_256F" => Ok(fe11_sys::CKP_SLH_DSA_SHA2_256F as u64),
        "CKP_SLH_DSA_SHA2_256S" => Ok(fe11_sys::CKP_SLH_DSA_SHA2_256S as u64),
        "CKP_SLH_DSA_SHAKE_128F" => Ok(fe11_sys::CKP_SLH_DSA_SHAKE_128F as u64),
        "CKP_SLH_DSA_SHAKE_128S" => Ok(fe11_sys::CKP_SLH_DSA_SHAKE_128S as u64),
        "CKP_SLH_DSA_SHAKE_192F" => Ok(fe11_sys::CKP_SLH_DSA_SHAKE_192F as u64),
        "CKP_SLH_DSA_SHAKE_192S" => Ok(fe11_sys::CKP_SLH_DSA_SHAKE_192S as u64),
        "CKP_SLH_DSA_SHAKE_256F" => Ok(fe11_sys::CKP_SLH_DSA_SHAKE_256F as u64),
        "CKP_SLH_DSA_SHAKE_256S" => Ok(fe11_sys::CKP_SLH_DSA_SHAKE_256S as u64),
        _ => Err(Failure::Input("generation_constant")),
    }
}
