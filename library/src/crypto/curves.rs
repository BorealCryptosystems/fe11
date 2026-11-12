// SPDX-License-Identifier: Apache-2.0
// Named-curve encoding metadata from SP800-186, RFC5639 and SEC2-v2.
// Each domain records its coordinate width and DER object identifier.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Closed named short-Weierstrass curve catalogue, with fixed verified domains.
pub enum WeierstrassCurve {
    /// NIST P-256.
    P256,
    /// NIST P-384.
    P384,
    /// NIST P-521.
    P521,
    /// RFC5639 brainpoolP256r1; no implied FIPS approval.
    BrainpoolP256,
    /// RFC5639 brainpoolP384r1; no implied FIPS approval.
    BrainpoolP384,
    /// RFC5639 brainpoolP512r1; no implied FIPS approval.
    BrainpoolP512,
    /// SEC2 secp256k1; no implied FIPS approval.
    Secp256k1,
}
pub(super) struct Domain {
    pub width: usize,
    pub oid_der: &'static [u8],

}
impl WeierstrassCurve {
    pub(super) fn domain(self) -> Domain {
        match self {
            Self::P256 => Domain {
                width: 32,
                oid_der: &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],

            },
            Self::P384 => Domain {
                width: 48,
                oid_der: &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22],

            },
            Self::P521 => Domain {
                width: 66,
                oid_der: &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23],

            },
            Self::BrainpoolP256 => Domain {
                width: 32,
                oid_der: &[0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07],

            },
            Self::BrainpoolP384 => Domain {
                width: 48,
                oid_der: &[0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b],

            },
            Self::BrainpoolP512 => Domain {
                width: 64,
                oid_der: &[0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d],

            },
            Self::Secp256k1 => Domain {
                width: 32,
                oid_der: &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a],

            },
        }
    }
}
