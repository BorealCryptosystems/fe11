// SPDX-License-Identifier: Apache-2.0
//! Exact HMAC/CMAC parameters on the shared synchronous session fixture.
pub use super::object_owner::Owner;
use fe11::*;

impl Owner {
    pub fn import_mac(
        &self,
        bytes: &[u8],
        algorithm: NativeMacAlgorithm,
    ) -> Result<NativeObjectRef> {
        self.import_mac_usages(bytes, algorithm, true, true)
    }

    pub fn import_mac_usages(
        &self,
        bytes: &[u8],
        algorithm: NativeMacAlgorithm,
        sign: bool,
        verify: bool,
    ) -> Result<NativeObjectRef> {
        let key_type = if matches!(
            algorithm,
            NativeMacAlgorithm::AES_CMAC | NativeMacAlgorithm::AES_MAC
        ) {
            fe11_sys::CKK_AES
        } else if matches!(
            algorithm,
            NativeMacAlgorithm::DES3_CMAC | NativeMacAlgorithm::DES3_MAC
        ) {
            if bytes.len() == 16 {
                fe11_sys::CKK_DES2
            } else {
                fe11_sys::CKK_DES3
            }
        } else if algorithm == NativeMacAlgorithm::DES_MAC {
            fe11_sys::CKK_DES
        } else {
            fe11_sys::CKK_GENERIC_SECRET
        };
        self.import_secret_usages(
            bytes,
            key_type,
            [
                (StandardAttribute::SIGN, sign),
                (StandardAttribute::VERIFY, verify),
            ],
        )
    }

    pub fn compute(
        &self,
        key: &NativeObjectRef,
        algorithm: NativeMacAlgorithm,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
        capacity: usize,
    ) -> Result<NativeMac> {
        match self {
            Self::Session(session) => session.compute_native_mac(
                key,
                NativeMacParameters::Full(algorithm),
                route,
                parts,
                limits,
                capacity,
                None,
            ),
            Self::Advanced(session) => session.compute_native_mac(
                key,
                NativeMacParameters::Full(algorithm),
                route,
                parts,
                limits,
                capacity,
                None,
            ),
        }
    }

    pub fn verify(
        &self,
        key: &NativeObjectRef,
        algorithm: NativeMacAlgorithm,
        route: MessageRoute,
        parts: &[&[u8]],
        tag: &[u8],
        limits: InputLimits,
    ) -> Result<()> {
        match self {
            Self::Session(session) => session.verify_native_mac(
                key,
                NativeMacParameters::Full(algorithm),
                route,
                parts,
                tag,
                limits,
                None,
            ),
            Self::Advanced(session) => session.verify_native_mac(
                key,
                NativeMacParameters::Full(algorithm),
                route,
                parts,
                tag,
                limits,
                None,
            ),
        }
    }
}
