// SPDX-License-Identifier: Apache-2.0
//! Key-profile wire tags, interpreted with the enclosing record family.
//!
//! These are Fe11 record tags, not PKCS#11 mechanism identifiers or security
//! policies. Digest, classic-cipher and recovery families have their own tag
//! adapters. Do not validate an unclassified descriptor through this table:
//! family-specific validation preserves the established refusal order.
pub(in crate::advanced) const NATIVE_KEY_TYPE: u8 = 1;
pub(in crate::advanced) const AES128: u8 = 2;
pub(in crate::advanced) const AES192: u8 = 3;
pub(in crate::advanced) const AES256: u8 = 4;
pub(in crate::advanced) const HMAC_SHA256: u8 = 5;
pub(in crate::advanced) const HMAC_SHA384: u8 = 6;
pub(in crate::advanced) const HMAC_SHA512: u8 = 7;
/// Fixed SHA-256/MGF1-SHA256/salt32 selection of the convenience message facade.
pub(in crate::advanced) const RSA_PSS_SHA256: u8 = 8;
/// Explicit PSS parameters carried in each message; no implicit default.
pub(in crate::advanced) const RSA_PSS_SELECTED: u8 = 9;
/// Dual tags10/11/12 carry explicit hash/MAC selection for AES128/192/256.
/// Tags 2/3/4 select SHA-256 explicitly with AES128/192/256.
pub(in crate::advanced) const DUAL_SELECTION_OFFSET: u8 = 8;
pub(in crate::advanced) const DUAL_AES128_SELECTED: u8 = 10;
pub(in crate::advanced) const DUAL_AES256_SELECTED: u8 = 12;
