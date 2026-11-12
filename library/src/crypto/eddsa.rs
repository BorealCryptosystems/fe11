// SPDX-License-Identifier: Apache-2.0
//! Explicit Edwards instances and shared native signing/verification sequences.
mod parameters;

use crate::{Result, Session};
use fe11_sys::*;
pub use parameters::{EdDsaParameters, EdDsaVariant};
impl Session {
    pub(super) fn eddsa_sign_native_with_context(
        &self,
        s: &crate::session::SessionAccess<'_>,
        object: CK_OBJECT_HANDLE,
        ed448: bool,
        parameters: super::native_signature::SignatureParameters<'_>,
        parts: &[&[u8]],
        multipart: bool,
        access: crate::managed::ObjectAccess,
        authentication: Option<&mut crate::session::PreparedContextLogin<'_>>,
        prepared: super::native_signature::storage::Storage,
        diagnostics: &mut crate::crypto::ClassicalDiagnostics,
    ) -> Result<crate::SecretBytes> {
        use super::native_signature::SignatureOutput;
        self.entry(s)?;
        access.check(&self.snapshot)?;
        let result = self.sign_native_frame(
            s,
            object,
            CKM_EDDSA,
            parameters,
            SignatureOutput::ExactLength(if ed448 { 114 } else { 64 }),
            parts,
            multipart,
            authentication,
            prepared,
            diagnostics,
        );
        access.result(self, s, result)
    }
}


