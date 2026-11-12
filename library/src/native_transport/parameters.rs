// SPDX-License-Identifier: Apache-2.0
//! Map typed transport parameter selections to their native mechanism numbers.

use super::*;

impl NativeTransportMechanism {
    /// Exact PKCS#11 identifier.
    pub fn mechanism_number(self) -> u64 {
        self.kind as u64
    }
}

impl NativeTransportMechanism {
    /// CKM_AES_CTS with its 16-byte IV.
    pub const AES_CTS: Self = Self {
        kind: CKM_AES_CTS,
        bytes: 16,
        optional: false,
    };

    /// CKM_BATON_WRAP; no parameter.
    pub const BATON_WRAP: Self = Self {
        kind: CKM_BATON_WRAP,
        bytes: 0,
        optional: true,
    };

    /// CKM_JUNIPER_WRAP; no parameter.
    pub const JUNIPER_WRAP: Self = Self {
        kind: CKM_JUNIPER_WRAP,
        bytes: 0,
        optional: true,
    };

    /// CKM_RSA_PKCS_TPM_1_1; no parameter.
    pub const RSA_PKCS_TPM_1_1: Self = Self {
        kind: CKM_RSA_PKCS_TPM_1_1,
        bytes: 0,
        optional: true,
    };

    /// CKM_RSA_PKCS_OAEP_TPM_1_1; no parameter.
    pub const RSA_PKCS_OAEP_TPM_1_1: Self = Self {
        kind: CKM_RSA_PKCS_OAEP_TPM_1_1,
        bytes: 0,
        optional: true,
    };

    /// CKM_RSA_PKCS; no parameter.
    pub const RSA_PKCS: Self = Self {
        kind: CKM_RSA_PKCS,
        bytes: 0,
        optional: true,
    };

    /// CKM_RSA_X_509; no parameter.
    pub const RSA_X_509: Self = Self {
        kind: CKM_RSA_X_509,
        bytes: 0,
        optional: true,
    };

    /// CKM_KEY_WRAP_LYNKS; no parameter.
    pub const KEY_WRAP_LYNKS: Self = Self {
        kind: CKM_KEY_WRAP_LYNKS,
        bytes: 0,
        optional: true,
    };

    /// CKM_SKIPJACK_WRAP; no parameter.
    pub const SKIPJACK_WRAP: Self = Self {
        kind: CKM_SKIPJACK_WRAP,
        bytes: 0,
        optional: true,
    };

    /// CKM_RC4; no parameter.
    pub const RC4: Self = Self {
        kind: CKM_RC4,
        bytes: 0,
        optional: true,
    };

    /// CKM_DES_ECB; no parameter.
    pub const DES_ECB: Self = Self {
        kind: CKM_DES_ECB,
        bytes: 0,
        optional: true,
    };

    /// CKM_DES3_ECB; no parameter.
    pub const DES3_ECB: Self = Self {
        kind: CKM_DES3_ECB,
        bytes: 0,
        optional: true,
    };

    /// CKM_CDMF_ECB; no parameter.
    pub const CDMF_ECB: Self = Self {
        kind: CKM_CDMF_ECB,
        bytes: 0,
        optional: true,
    };

    /// CKM_CAST_ECB; no parameter.
    pub const CAST_ECB: Self = Self {
        kind: CKM_CAST_ECB,
        bytes: 0,
        optional: true,
    };

    /// CKM_CAST3_ECB; no parameter.
    pub const CAST3_ECB: Self = Self {
        kind: CKM_CAST3_ECB,
        bytes: 0,
        optional: true,
    };

    /// CKM_CAST5_ECB; no parameter.
    pub const CAST5_ECB: Self = Self {
        kind: CKM_CAST5_ECB,
        bytes: 0,
        optional: true,
    };

    /// CKM_CAST128_ECB; no parameter.
    pub const CAST128_ECB: Self = Self {
        kind: CKM_CAST128_ECB,
        bytes: 0,
        optional: true,
    };

    /// CKM_IDEA_ECB; no parameter.
    pub const IDEA_ECB: Self = Self {
        kind: CKM_IDEA_ECB,
        bytes: 0,
        optional: true,
    };

    /// CKM_CAMELLIA_ECB; no parameter.
    pub const CAMELLIA_ECB: Self = Self {
        kind: CKM_CAMELLIA_ECB,
        bytes: 0,
        optional: true,
    };

    /// CKM_ARIA_ECB; no parameter.
    pub const ARIA_ECB: Self = Self {
        kind: CKM_ARIA_ECB,
        bytes: 0,
        optional: true,
    };

    /// CKM_SEED_ECB; no parameter.
    pub const SEED_ECB: Self = Self {
        kind: CKM_SEED_ECB,
        bytes: 0,
        optional: true,
    };

    /// CKM_AES_ECB; no parameter.
    pub const AES_ECB: Self = Self {
        kind: CKM_AES_ECB,
        bytes: 0,
        optional: true,
    };

    /// CKM_GOST28147_ECB; no parameter.
    pub const GOST28147_ECB: Self = Self {
        kind: CKM_GOST28147_ECB,
        bytes: 0,
        optional: true,
    };

    /// CKM_NULL; no parameter.
    pub const NULL: Self = Self {
        kind: CKM_NULL,
        bytes: 0,
        optional: true,
    };

    /// CKM_DES_CBC; exact 8-byte parameter.
    pub const DES_CBC: Self = Self {
        kind: CKM_DES_CBC,
        bytes: 8,
        optional: false,
    };

    /// CKM_DES_CBC_PAD; exact 8-byte parameter.
    pub const DES_CBC_PAD: Self = Self {
        kind: CKM_DES_CBC_PAD,
        bytes: 8,
        optional: false,
    };

    /// CKM_DES3_CBC; exact 8-byte parameter.
    pub const DES3_CBC: Self = Self {
        kind: CKM_DES3_CBC,
        bytes: 8,
        optional: false,
    };

    /// CKM_DES3_CBC_PAD; exact 8-byte parameter.
    pub const DES3_CBC_PAD: Self = Self {
        kind: CKM_DES3_CBC_PAD,
        bytes: 8,
        optional: false,
    };

    /// CKM_CDMF_CBC; exact 8-byte parameter.
    pub const CDMF_CBC: Self = Self {
        kind: CKM_CDMF_CBC,
        bytes: 8,
        optional: false,
    };

    /// CKM_CDMF_CBC_PAD; exact 8-byte parameter.
    pub const CDMF_CBC_PAD: Self = Self {
        kind: CKM_CDMF_CBC_PAD,
        bytes: 8,
        optional: false,
    };

    /// CKM_CAST_CBC; exact 8-byte parameter.
    pub const CAST_CBC: Self = Self {
        kind: CKM_CAST_CBC,
        bytes: 8,
        optional: false,
    };

    /// CKM_CAST_CBC_PAD; exact 8-byte parameter.
    pub const CAST_CBC_PAD: Self = Self {
        kind: CKM_CAST_CBC_PAD,
        bytes: 8,
        optional: false,
    };

    /// CKM_CAST3_CBC; exact 8-byte parameter.
    pub const CAST3_CBC: Self = Self {
        kind: CKM_CAST3_CBC,
        bytes: 8,
        optional: false,
    };

    /// CKM_CAST3_CBC_PAD; exact 8-byte parameter.
    pub const CAST3_CBC_PAD: Self = Self {
        kind: CKM_CAST3_CBC_PAD,
        bytes: 8,
        optional: false,
    };

    /// CKM_CAST5_CBC; exact 8-byte parameter.
    pub const CAST5_CBC: Self = Self {
        kind: CKM_CAST5_CBC,
        bytes: 8,
        optional: false,
    };

    /// CKM_CAST5_CBC_PAD; exact 8-byte parameter.
    pub const CAST5_CBC_PAD: Self = Self {
        kind: CKM_CAST5_CBC_PAD,
        bytes: 8,
        optional: false,
    };

    /// CKM_CAST128_CBC; exact 8-byte parameter.
    pub const CAST128_CBC: Self = Self {
        kind: CKM_CAST128_CBC,
        bytes: 8,
        optional: false,
    };

    /// CKM_CAST128_CBC_PAD; exact 8-byte parameter.
    pub const CAST128_CBC_PAD: Self = Self {
        kind: CKM_CAST128_CBC_PAD,
        bytes: 8,
        optional: false,
    };

    /// CKM_IDEA_CBC; exact 8-byte parameter.
    pub const IDEA_CBC: Self = Self {
        kind: CKM_IDEA_CBC,
        bytes: 8,
        optional: false,
    };

    /// CKM_IDEA_CBC_PAD; exact 8-byte parameter.
    pub const IDEA_CBC_PAD: Self = Self {
        kind: CKM_IDEA_CBC_PAD,
        bytes: 8,
        optional: false,
    };

    /// CKM_BLOWFISH_CBC; exact 8-byte parameter.
    pub const BLOWFISH_CBC: Self = Self {
        kind: CKM_BLOWFISH_CBC,
        bytes: 8,
        optional: false,
    };

    /// CKM_BLOWFISH_CBC_PAD; exact 8-byte parameter.
    pub const BLOWFISH_CBC_PAD: Self = Self {
        kind: CKM_BLOWFISH_CBC_PAD,
        bytes: 8,
        optional: false,
    };

    /// CKM_AES_CBC; exact 16-byte parameter.
    pub const AES_CBC: Self = Self {
        kind: CKM_AES_CBC,
        bytes: 16,
        optional: false,
    };

    /// CKM_AES_CBC_PAD; exact 16-byte parameter.
    pub const AES_CBC_PAD: Self = Self {
        kind: CKM_AES_CBC_PAD,
        bytes: 16,
        optional: false,
    };

    /// CKM_AES_OFB; exact 16-byte parameter.
    pub const AES_OFB: Self = Self {
        kind: CKM_AES_OFB,
        bytes: 16,
        optional: false,
    };

    /// CKM_AES_CFB64; exact 16-byte parameter.
    pub const AES_CFB64: Self = Self {
        kind: CKM_AES_CFB64,
        bytes: 16,
        optional: false,
    };

    /// CKM_AES_CFB8; exact 16-byte parameter.
    pub const AES_CFB8: Self = Self {
        kind: CKM_AES_CFB8,
        bytes: 16,
        optional: false,
    };

    /// CKM_AES_CFB128; exact 16-byte parameter.
    pub const AES_CFB128: Self = Self {
        kind: CKM_AES_CFB128,
        bytes: 16,
        optional: false,
    };

    /// CKM_AES_CFB1; exact 16-byte parameter.
    pub const AES_CFB1: Self = Self {
        kind: CKM_AES_CFB1,
        bytes: 16,
        optional: false,
    };

    /// CKM_AES_XTS; exact 16-byte parameter.
    pub const AES_XTS: Self = Self {
        kind: CKM_AES_XTS,
        bytes: 16,
        optional: false,
    };

    /// CKM_CAMELLIA_CBC; exact 16-byte parameter.
    pub const CAMELLIA_CBC: Self = Self {
        kind: CKM_CAMELLIA_CBC,
        bytes: 16,
        optional: false,
    };

    /// CKM_CAMELLIA_CBC_PAD; exact 16-byte parameter.
    pub const CAMELLIA_CBC_PAD: Self = Self {
        kind: CKM_CAMELLIA_CBC_PAD,
        bytes: 16,
        optional: false,
    };

    /// CKM_ARIA_CBC; exact 16-byte parameter.
    pub const ARIA_CBC: Self = Self {
        kind: CKM_ARIA_CBC,
        bytes: 16,
        optional: false,
    };

    /// CKM_ARIA_CBC_PAD; exact 16-byte parameter.
    pub const ARIA_CBC_PAD: Self = Self {
        kind: CKM_ARIA_CBC_PAD,
        bytes: 16,
        optional: false,
    };

    /// CKM_SEED_CBC; exact 16-byte parameter.
    pub const SEED_CBC: Self = Self {
        kind: CKM_SEED_CBC,
        bytes: 16,
        optional: false,
    };

    /// CKM_SEED_CBC_PAD; exact 16-byte parameter.
    pub const SEED_CBC_PAD: Self = Self {
        kind: CKM_SEED_CBC_PAD,
        bytes: 16,
        optional: false,
    };

    /// CKM_TWOFISH_CBC; exact 16-byte parameter.
    pub const TWOFISH_CBC: Self = Self {
        kind: CKM_TWOFISH_CBC,
        bytes: 16,
        optional: false,
    };

    /// CKM_TWOFISH_CBC_PAD; exact 16-byte parameter.
    pub const TWOFISH_CBC_PAD: Self = Self {
        kind: CKM_TWOFISH_CBC_PAD,
        bytes: 16,
        optional: false,
    };

    /// CKM_AES_KEY_WRAP; exact 8-byte parameter, optionally omitted.
    pub const AES_KEY_WRAP: Self = Self {
        kind: CKM_AES_KEY_WRAP,
        bytes: 8,
        optional: true,
    };

    /// CKM_AES_KEY_WRAP_PAD; exact 8-byte parameter, optionally omitted.
    pub const AES_KEY_WRAP_PAD: Self = Self {
        kind: CKM_AES_KEY_WRAP_PAD,
        bytes: 8,
        optional: true,
    };

    /// CKM_AES_KEY_WRAP_PKCS7; exact 8-byte parameter, optionally omitted.
    pub const AES_KEY_WRAP_PKCS7: Self = Self {
        kind: CKM_AES_KEY_WRAP_PKCS7,
        bytes: 8,
        optional: true,
    };

    /// CKM_GOST28147; exact 8-byte parameter, optionally omitted.
    pub const GOST28147: Self = Self {
        kind: CKM_GOST28147,
        bytes: 8,
        optional: true,
    };

    /// CKM_GOST28147_KEY_WRAP; exact 8-byte parameter, optionally omitted.
    pub const GOST28147_KEY_WRAP: Self = Self {
        kind: CKM_GOST28147_KEY_WRAP,
        bytes: 8,
        optional: true,
    };

    /// CKM_AES_KEY_WRAP_KWP; exact 4-byte parameter, optionally omitted.
    pub const AES_KEY_WRAP_KWP: Self = Self {
        kind: CKM_AES_KEY_WRAP_KWP,
        bytes: 4,
        optional: true,
    };

    /// All closed fixed-layout selections, including standard aliases.
    pub const ALL: &'static [Self] = &[
        Self::RSA_PKCS,
        Self::AES_CTS,
        Self::BATON_WRAP,
        Self::JUNIPER_WRAP,
        Self::RSA_PKCS_TPM_1_1,
        Self::RSA_PKCS_OAEP_TPM_1_1,
        Self::RSA_X_509,
        Self::KEY_WRAP_LYNKS,
        Self::SKIPJACK_WRAP,
        Self::RC4,
        Self::DES_ECB,
        Self::DES3_ECB,
        Self::CDMF_ECB,
        Self::CAST_ECB,
        Self::CAST3_ECB,
        Self::CAST5_ECB,
        Self::CAST128_ECB,
        Self::IDEA_ECB,
        Self::CAMELLIA_ECB,
        Self::ARIA_ECB,
        Self::SEED_ECB,
        Self::AES_ECB,
        Self::GOST28147_ECB,
        Self::NULL,
        Self::DES_CBC,
        Self::DES_CBC_PAD,
        Self::DES3_CBC,
        Self::DES3_CBC_PAD,
        Self::CDMF_CBC,
        Self::CDMF_CBC_PAD,
        Self::CAST_CBC,
        Self::CAST_CBC_PAD,
        Self::CAST3_CBC,
        Self::CAST3_CBC_PAD,
        Self::CAST5_CBC,
        Self::CAST5_CBC_PAD,
        Self::CAST128_CBC,
        Self::CAST128_CBC_PAD,
        Self::IDEA_CBC,
        Self::IDEA_CBC_PAD,
        Self::BLOWFISH_CBC,
        Self::BLOWFISH_CBC_PAD,
        Self::AES_CBC,
        Self::AES_CBC_PAD,
        Self::AES_OFB,
        Self::AES_CFB64,
        Self::AES_CFB8,
        Self::AES_CFB128,
        Self::AES_CFB1,
        Self::AES_XTS,
        Self::CAMELLIA_CBC,
        Self::CAMELLIA_CBC_PAD,
        Self::ARIA_CBC,
        Self::ARIA_CBC_PAD,
        Self::SEED_CBC,
        Self::SEED_CBC_PAD,
        Self::TWOFISH_CBC,
        Self::TWOFISH_CBC_PAD,
        Self::AES_KEY_WRAP,
        Self::AES_KEY_WRAP_PAD,
        Self::AES_KEY_WRAP_PKCS7,
        Self::GOST28147,
        Self::GOST28147_KEY_WRAP,
        Self::AES_KEY_WRAP_KWP,
    ];
}
