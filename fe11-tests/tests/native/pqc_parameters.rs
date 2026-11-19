// SPDX-License-Identifier: Apache-2.0
//! Standard PQC parameter sets and their published encoding dimensions.
use super::outcome::Failure;
use fe11::NativePqcFamily;
use fe11_sys::*;
pub struct Parameters {
    pub family: NativePqcFamily,
    pub key_type: u64,
    pub set: u64,
    pub public_bytes: usize,
    pub private_bytes: usize,
    pub signature_bytes: usize,
}
impl Parameters {
    pub fn parse(name: &str) -> Result<Self, Failure> {
        let (family, key_type, set, public_bytes, private_bytes, signature_bytes) = match name {
            "ML-DSA-44" => (
                NativePqcFamily::MlDsa,
                CKK_ML_DSA,
                CKP_ML_DSA_44,
                1312,
                2560,
                2420,
            ),
            "ML-DSA-65" => (
                NativePqcFamily::MlDsa,
                CKK_ML_DSA,
                CKP_ML_DSA_65,
                1952,
                4032,
                3309,
            ),
            "ML-DSA-87" => (
                NativePqcFamily::MlDsa,
                CKK_ML_DSA,
                CKP_ML_DSA_87,
                2592,
                4896,
                4627,
            ),
            "SLH-DSA-SHA2-128s" => (
                NativePqcFamily::SlhDsa,
                CKK_SLH_DSA,
                CKP_SLH_DSA_SHA2_128S,
                32,
                64,
                7856,
            ),
            "SLH-DSA-SHA2-128f" => (
                NativePqcFamily::SlhDsa,
                CKK_SLH_DSA,
                CKP_SLH_DSA_SHA2_128F,
                32,
                64,
                17088,
            ),
            "SLH-DSA-SHA2-192s" => (
                NativePqcFamily::SlhDsa,
                CKK_SLH_DSA,
                CKP_SLH_DSA_SHA2_192S,
                48,
                96,
                16224,
            ),
            "SLH-DSA-SHA2-192f" => (
                NativePqcFamily::SlhDsa,
                CKK_SLH_DSA,
                CKP_SLH_DSA_SHA2_192F,
                48,
                96,
                35664,
            ),
            "SLH-DSA-SHA2-256s" => (
                NativePqcFamily::SlhDsa,
                CKK_SLH_DSA,
                CKP_SLH_DSA_SHA2_256S,
                64,
                128,
                29792,
            ),
            "SLH-DSA-SHA2-256f" => (
                NativePqcFamily::SlhDsa,
                CKK_SLH_DSA,
                CKP_SLH_DSA_SHA2_256F,
                64,
                128,
                49856,
            ),
            "SLH-DSA-SHAKE-128s" => (
                NativePqcFamily::SlhDsa,
                CKK_SLH_DSA,
                CKP_SLH_DSA_SHAKE_128S,
                32,
                64,
                7856,
            ),
            "SLH-DSA-SHAKE-128f" => (
                NativePqcFamily::SlhDsa,
                CKK_SLH_DSA,
                CKP_SLH_DSA_SHAKE_128F,
                32,
                64,
                17088,
            ),
            "SLH-DSA-SHAKE-192s" => (
                NativePqcFamily::SlhDsa,
                CKK_SLH_DSA,
                CKP_SLH_DSA_SHAKE_192S,
                48,
                96,
                16224,
            ),
            "SLH-DSA-SHAKE-192f" => (
                NativePqcFamily::SlhDsa,
                CKK_SLH_DSA,
                CKP_SLH_DSA_SHAKE_192F,
                48,
                96,
                35664,
            ),
            "SLH-DSA-SHAKE-256s" => (
                NativePqcFamily::SlhDsa,
                CKK_SLH_DSA,
                CKP_SLH_DSA_SHAKE_256S,
                64,
                128,
                29792,
            ),
            "SLH-DSA-SHAKE-256f" => (
                NativePqcFamily::SlhDsa,
                CKK_SLH_DSA,
                CKP_SLH_DSA_SHAKE_256F,
                64,
                128,
                49856,
            ),
            _ => return Err(Failure::Input("pqc_parameter_set")),
        };
        Ok(Self {
            family,
            key_type: key_type as u64,
            set: set as u64,
            public_bytes,
            private_bytes,
            signature_bytes,
        })
    }
}
