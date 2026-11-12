// SPDX-License-Identifier: Apache-2.0
//! FIPS204/205 sizes, PKCS#11 3.2 parameters, RFC9881/9909 OIDs.
use der::asn1::ObjectIdentifier;
use fe11_sys::*;

/// The three standardized FIPS204 parameter sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlDsaParameterSet {
    /// ML-DSA-44, security category2.
    MlDsa44,
    /// ML-DSA-65, security category3.
    MlDsa65,
    /// ML-DSA-87, security category5.
    MlDsa87,
}

/// The twelve standardized FIPS205 parameter sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlhDsaParameterSet {
    /// SHA2-128s.
    Sha2_128s,
    /// SHA2-128f.
    Sha2_128f,
    /// SHA2-192s.
    Sha2_192s,
    /// SHA2-192f.
    Sha2_192f,
    /// SHA2-256s.
    Sha2_256s,
    /// SHA2-256f.
    Sha2_256f,
    /// SHAKE-128s.
    Shake128s,
    /// SHAKE-128f.
    Shake128f,
    /// SHAKE-192s.
    Shake192s,
    /// SHAKE-192f.
    Shake192f,
    /// SHAKE-256s.
    Shake256s,
    /// SHAKE-256f.
    Shake256f,
}

/// Pure-signature catalogue. KEM, prehash and historical aliases are separate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqcAlgorithm {
    /// FIPS204 ML-DSA.
    MlDsa(MlDsaParameterSet),
    /// FIPS205 stateless SLH-DSA.
    SlhDsa(SlhDsaParameterSet),
}

pub(super) struct Description {
    pub parameter: CK_ULONG,
    pub public_length: usize,
    pub signature_length: usize,
    pub oid: ObjectIdentifier,
    pub name: &'static str,
    pub engine_name: &'static [u8],
}

impl PqcAlgorithm {
    /// All fifteen supported parameter sets, with no inference of module support.
    pub const ALL: [Self; 15] = [
        Self::MlDsa(MlDsaParameterSet::MlDsa44),
        Self::MlDsa(MlDsaParameterSet::MlDsa65),
        Self::MlDsa(MlDsaParameterSet::MlDsa87),
        Self::SlhDsa(SlhDsaParameterSet::Sha2_128s),
        Self::SlhDsa(SlhDsaParameterSet::Sha2_128f),
        Self::SlhDsa(SlhDsaParameterSet::Sha2_192s),
        Self::SlhDsa(SlhDsaParameterSet::Sha2_192f),
        Self::SlhDsa(SlhDsaParameterSet::Sha2_256s),
        Self::SlhDsa(SlhDsaParameterSet::Sha2_256f),
        Self::SlhDsa(SlhDsaParameterSet::Shake128s),
        Self::SlhDsa(SlhDsaParameterSet::Shake128f),
        Self::SlhDsa(SlhDsaParameterSet::Shake192s),
        Self::SlhDsa(SlhDsaParameterSet::Shake192f),
        Self::SlhDsa(SlhDsaParameterSet::Shake256s),
        Self::SlhDsa(SlhDsaParameterSet::Shake256f),
    ];

    /// Exact NIST algorithm name.
    pub fn name(self) -> &'static str {
        self.description().name
    }

    /// Length of the raw public key in bytes, also the native mechanism size unit.
    pub fn public_key_length(self) -> usize {
        self.description().public_length
    }

    /// Exact raw signature length in bytes.
    pub fn signature_length(self) -> usize {
        self.description().signature_length
    }

    /// RFC9881/RFC9909 pure-signature and public-key object identifier.
    pub fn oid(self) -> ObjectIdentifier {
        self.description().oid
    }

    pub(super) fn key_type(self) -> CK_KEY_TYPE {
        match self {
            Self::MlDsa(_) => CKK_ML_DSA,
            Self::SlhDsa(_) => CKK_SLH_DSA,
        }
    }

    pub(super) fn generation_mechanism(self) -> CK_MECHANISM_TYPE {
        match self {
            Self::MlDsa(_) => CKM_ML_DSA_KEY_PAIR_GEN,
            Self::SlhDsa(_) => CKM_SLH_DSA_KEY_PAIR_GEN,
        }
    }

    pub(super) fn signature_mechanism(self) -> CK_MECHANISM_TYPE {
        match self {
            Self::MlDsa(_) => CKM_ML_DSA,
            Self::SlhDsa(_) => CKM_SLH_DSA,
        }
    }

    pub(super) fn description(self) -> Description {
        use MlDsaParameterSet::*;
        use SlhDsaParameterSet::*;
        // PKCS#11 interleaves SHA2/SHAKE, while PKIX groups by hash family.
        // Keep those two normative numberings explicit and independent.
        let (parameter, public_length, signature_length, oid, name, engine_name) = match self {
            Self::MlDsa(MlDsa44) => (
                CKP_ML_DSA_44,
                1312,
                2420,
                "2.16.840.1.101.3.4.3.17",
                "ML-DSA-44",
                b"ML-DSA-44\0".as_slice(),
            ),
            Self::MlDsa(MlDsa65) => (
                CKP_ML_DSA_65,
                1952,
                3309,
                "2.16.840.1.101.3.4.3.18",
                "ML-DSA-65",
                b"ML-DSA-65\0".as_slice(),
            ),
            Self::MlDsa(MlDsa87) => (
                CKP_ML_DSA_87,
                2592,
                4627,
                "2.16.840.1.101.3.4.3.19",
                "ML-DSA-87",
                b"ML-DSA-87\0".as_slice(),
            ),
            Self::SlhDsa(Sha2_128s) => (
                CKP_SLH_DSA_SHA2_128S,
                32,
                7856,
                "2.16.840.1.101.3.4.3.20",
                "SLH-DSA-SHA2-128s",
                b"SLH-DSA-SHA2-128s\0".as_slice(),
            ),
            Self::SlhDsa(Sha2_128f) => (
                CKP_SLH_DSA_SHA2_128F,
                32,
                17088,
                "2.16.840.1.101.3.4.3.21",
                "SLH-DSA-SHA2-128f",
                b"SLH-DSA-SHA2-128f\0".as_slice(),
            ),
            Self::SlhDsa(Sha2_192s) => (
                CKP_SLH_DSA_SHA2_192S,
                48,
                16224,
                "2.16.840.1.101.3.4.3.22",
                "SLH-DSA-SHA2-192s",
                b"SLH-DSA-SHA2-192s\0".as_slice(),
            ),
            Self::SlhDsa(Sha2_192f) => (
                CKP_SLH_DSA_SHA2_192F,
                48,
                35664,
                "2.16.840.1.101.3.4.3.23",
                "SLH-DSA-SHA2-192f",
                b"SLH-DSA-SHA2-192f\0".as_slice(),
            ),
            Self::SlhDsa(Sha2_256s) => (
                CKP_SLH_DSA_SHA2_256S,
                64,
                29792,
                "2.16.840.1.101.3.4.3.24",
                "SLH-DSA-SHA2-256s",
                b"SLH-DSA-SHA2-256s\0".as_slice(),
            ),
            Self::SlhDsa(Sha2_256f) => (
                CKP_SLH_DSA_SHA2_256F,
                64,
                49856,
                "2.16.840.1.101.3.4.3.25",
                "SLH-DSA-SHA2-256f",
                b"SLH-DSA-SHA2-256f\0".as_slice(),
            ),
            Self::SlhDsa(Shake128s) => (
                CKP_SLH_DSA_SHAKE_128S,
                32,
                7856,
                "2.16.840.1.101.3.4.3.26",
                "SLH-DSA-SHAKE-128s",
                b"SLH-DSA-SHAKE-128s\0".as_slice(),
            ),
            Self::SlhDsa(Shake128f) => (
                CKP_SLH_DSA_SHAKE_128F,
                32,
                17088,
                "2.16.840.1.101.3.4.3.27",
                "SLH-DSA-SHAKE-128f",
                b"SLH-DSA-SHAKE-128f\0".as_slice(),
            ),
            Self::SlhDsa(Shake192s) => (
                CKP_SLH_DSA_SHAKE_192S,
                48,
                16224,
                "2.16.840.1.101.3.4.3.28",
                "SLH-DSA-SHAKE-192s",
                b"SLH-DSA-SHAKE-192s\0".as_slice(),
            ),
            Self::SlhDsa(Shake192f) => (
                CKP_SLH_DSA_SHAKE_192F,
                48,
                35664,
                "2.16.840.1.101.3.4.3.29",
                "SLH-DSA-SHAKE-192f",
                b"SLH-DSA-SHAKE-192f\0".as_slice(),
            ),
            Self::SlhDsa(Shake256s) => (
                CKP_SLH_DSA_SHAKE_256S,
                64,
                29792,
                "2.16.840.1.101.3.4.3.30",
                "SLH-DSA-SHAKE-256s",
                b"SLH-DSA-SHAKE-256s\0".as_slice(),
            ),
            Self::SlhDsa(Shake256f) => (
                CKP_SLH_DSA_SHAKE_256F,
                64,
                49856,
                "2.16.840.1.101.3.4.3.31",
                "SLH-DSA-SHAKE-256f",
                b"SLH-DSA-SHAKE-256f\0".as_slice(),
            ),
        };
        Description {
            parameter,
            public_length,
            signature_length,
            oid: ObjectIdentifier::new(oid).expect("static standardized OID"),
            name,
            engine_name,
        }
    }
}


