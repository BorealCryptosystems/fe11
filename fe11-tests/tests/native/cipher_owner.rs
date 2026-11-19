// SPDX-License-Identifier: Apache-2.0
//! Both public cipher facades with identical explicit key references and limits.
use super::object_owner::Owner;
use fe11::*;

impl Owner {
    pub fn encrypt(
        &self,
        key: &NativeObjectRef,
        parameters: CipherParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<Ciphertext> {
        match self {
            Self::Session(session) => session.encrypt_cipher(
                CipherKeyReference::Secret(key),
                parameters,
                route,
                parts,
                limits,
            ),
            Self::Advanced(session) => session.encrypt_cipher(
                CipherKeyReference::Secret(key),
                parameters,
                route,
                parts,
                limits,
            ),
        }
    }

    pub fn decrypt(
        &self,
        key: &NativeObjectRef,
        parameters: CipherParameters<'_>,
        route: MessageRoute,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<UnauthenticatedCipherPlaintext> {
        match self {
            Self::Session(session) => session.decrypt_cipher(
                CipherKeyReference::Secret(key),
                parameters,
                route,
                parts,
                limits,
            ),
            Self::Advanced(session) => session.decrypt_cipher(
                CipherKeyReference::Secret(key),
                parameters,
                route,
                parts,
                limits,
            ),
        }
    }
}
