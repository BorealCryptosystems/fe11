// SPDX-License-Identifier: Apache-2.0
//! OpenSSL declarations missing from openssl-sys 0.9.117.
//!
//! Signatures and initialization bits are taken from the OpenSSL 3.5 public
//! headers (crypto.h, evp.h, params.h and x509.h). This module adds no wrappers
//! that initialize a default context or select an application provider.
pub(crate) use openssl_sys::*;
use std::ffi::{c_char, c_int, c_long, c_ulong, c_void};

pub(crate) const INIT_NO_LOAD_CONFIG: u64 = 0x0000_0080;
pub(crate) const INIT_NO_ATEXIT: u64 = 0x0008_0000;

// Opaque implementation handles never cross the component ABI. Their names
// differ from openssl-sys exports to keep these missing declarations explicit.
pub(crate) enum KeyManagement {}
pub(crate) enum SignatureMethod {}

extern "C" {
    pub(crate) fn EVP_KEYMGMT_fetch(
        context: *mut OSSL_LIB_CTX,
        algorithm: *const c_char,
        properties: *const c_char,
    ) -> *mut KeyManagement;
    pub(crate) fn EVP_KEYMGMT_free(method: *mut KeyManagement);
    pub(crate) fn EVP_SIGNATURE_fetch(
        context: *mut OSSL_LIB_CTX,
        algorithm: *const c_char,
        properties: *const c_char,
    ) -> *mut SignatureMethod;
    pub(crate) fn EVP_SIGNATURE_free(method: *mut SignatureMethod);
    pub(crate) fn OPENSSL_init_crypto(options: u64, settings: *const c_void) -> c_int;
    pub(crate) fn OPENSSL_thread_stop_ex(context: *mut OSSL_LIB_CTX);
    pub(crate) fn OPENSSL_thread_stop();
    pub(crate) fn OpenSSL_version_num() -> c_ulong;
    pub(crate) fn d2i_PUBKEY_ex(
        key: *mut *mut EVP_PKEY,
        input: *mut *const u8,
        length: c_long,
        context: *mut OSSL_LIB_CTX,
        properties: *const c_char,
    ) -> *mut EVP_PKEY;
    pub(crate) fn EVP_DigestVerifyInit_ex(
        digest_context: *mut EVP_MD_CTX,
        key_context: *mut *mut EVP_PKEY_CTX,
        digest: *const c_char,
        context: *mut OSSL_LIB_CTX,
        properties: *const c_char,
        key: *mut EVP_PKEY,
        parameters: *const OSSL_PARAM,
    ) -> c_int;
    pub(crate) fn EVP_PKEY_CTX_set_rsa_mgf1_md_name(
        context: *mut EVP_PKEY_CTX,
        name: *const c_char,
        properties: *const c_char,
    ) -> c_int;
    pub(crate) fn OSSL_PARAM_construct_utf8_string(
        name: *const c_char,
        buffer: *mut c_char,
        length: usize,
    ) -> OSSL_PARAM;
    pub(crate) fn OSSL_PARAM_construct_int(name: *const c_char, value: *mut c_int) -> OSSL_PARAM;
    pub(crate) fn EVP_MD_get_size(method: *const EVP_MD) -> c_int;
    pub(crate) fn EVP_MD_xof(method: *const EVP_MD) -> c_int;
}
