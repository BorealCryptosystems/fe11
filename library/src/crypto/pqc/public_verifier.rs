// SPDX-License-Identifier: Apache-2.0
//! Exact PQC framing with an explicitly selected independent software component.

use super::{PqcAlgorithm, PqcHash, PqcPublicKey, PqcSignatureMode, PqcSignatureParameters};
use crate::{
    crypto::public_verifier::{failure, Context},
    SecretBytes,
};
use fe11_verify_engine_api as api;

fn identifier(terminated: &'static [u8]) -> &'static [u8] {
    terminated.strip_suffix(&[0]).unwrap_or(terminated)
}

pub(super) struct PublicKey<'a> {
    raw: SecretBytes,
    context: &'a Context,
    algorithm: PqcAlgorithm,
}

impl<'a> PublicKey<'a> {
    pub(super) fn new(
        context: &'a Context,
        public: &PqcPublicKey,
    ) -> Result<Self, crate::RejectionReason> {
        Self::from_validated(context, public.algorithm(), public.as_raw())
    }

    pub(super) fn from_validated(
        context: &'a Context,
        algorithm: PqcAlgorithm,
        bytes: &[u8],
    ) -> Result<Self, crate::RejectionReason> {
        let mut raw = SecretBytes::new(bytes.len()).map_err(|_| {
            crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcPublicAllocation,
            )
        })?;
        raw.as_mut_slice().copy_from_slice(bytes);
        Ok(Self {
            raw,
            context,
            algorithm,
        })
    }

    pub(super) fn prepare(
        &self,
        signature: &PqcSignatureParameters,
    ) -> Result<PreparedVerification<'_>, crate::RejectionReason> {
        let bytes = signature.context();
        if bytes.len() > 255 {
            return Err(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcPublicContextBound,
            ));
        }
        let mut context = SecretBytes::new(bytes.len()).map_err(|_| {
            crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcPublicContextAllocation,
            )
        })?;
        context.as_mut_slice().copy_from_slice(bytes);
        let input = match signature.mode() {
            PqcSignatureMode::Pure => VerificationInput::Pure { context },
            PqcSignatureMode::Prehashed(hash) => VerificationInput::Prehashed { hash, context },
            PqcSignatureMode::HashMessage(hash) => {
                // Establish the exact digest capability before verifying the message
                // could run. Hashing empty input has no PKCS#11 or key side effect;
                // it does not replace the later hash of the caller's message.
                prehash(self.context, hash, &[])?;
                VerificationInput::HashMessage { hash, context }
            }
        };
        let prepared = PreparedVerification { key: self, input };
        let request = prepared.request();
        // SAFETY: all names, key bytes and context belong to the live prepared
        // owner; the component does not retain pointers after the synchronous call.
        unsafe { self.context.engine().probe(&request) }.map_err(failure)?;
        Ok(prepared)
    }
}

/// Parameters, key bytes and component lease stay owned until verification.
pub(super) struct PreparedVerification<'a> {
    key: &'a PublicKey<'a>,
    input: VerificationInput,
}

enum VerificationInput {
    Pure { context: SecretBytes },
    Prehashed { hash: PqcHash, context: SecretBytes },
    HashMessage { hash: PqcHash, context: SecretBytes },
}

pub(super) fn prehash(
    context: &Context,
    hash: PqcHash,
    message: &[u8],
) -> Result<SecretBytes, crate::RejectionReason> {
    context
        .engine()
        .digest(
            identifier(hash.engine_name()),
            hash.output_length(),
            matches!(hash, PqcHash::Shake128 | PqcHash::Shake256),
            message,
        )
        .map_err(failure)
}

fn frame(
    hash: PqcHash,
    context: &[u8],
    digest: &[u8],
) -> Result<SecretBytes, crate::RejectionReason> {
    if context.len() > 255 || digest.len() != hash.output_length() {
        return Err(crate::RejectionReason::PostQuantumKeys(
            crate::PostQuantumKeysRejection::PqcPublicPrehashFramingBounds,
        ));
    }
    let oid = hash.der_oid();
    let mut framed =
        SecretBytes::new(2 + context.len() + oid.len() + digest.len()).map_err(|_| {
            crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcPublicPrehashFramingAllocation,
            )
        })?;
    let bytes = framed.as_mut_slice();
    bytes[0] = 1;
    bytes[1] = context.len() as u8;
    bytes[2..2 + context.len()].copy_from_slice(context);
    let offset = 2 + context.len();
    bytes[offset..offset + oid.len()].copy_from_slice(&oid);
    bytes[offset + oid.len()..].copy_from_slice(digest);
    Ok(framed)
}

impl PreparedVerification<'_> {
    fn request(&self) -> api::VerificationRequest {
        let (context, encoding) = match &self.input {
            VerificationInput::Pure { context } => (api::Bytes::from_slice(context.as_slice()), 1),
            VerificationInput::Prehashed { .. } | VerificationInput::HashMessage { .. } => {
                (api::Bytes::EMPTY, 0)
            }
        };
        api::VerificationRequest {
            algorithm: api::Bytes::from_slice(identifier(
                self.key.algorithm.description().engine_name,
            )),
            key_format: api::key_format::RAW_PUBLIC,
            key: api::Bytes::from_slice(self.key.raw.as_slice()),
            scheme: api::scheme::PQC,
            digest: api::Bytes::EMPTY,
            mgf_digest: api::Bytes::EMPTY,
            salt_length: 0,
            context,
            message_encoding: encoding,
        }
    }

    pub(super) fn verify(
        self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, crate::RejectionReason> {
        if signature.len() != self.key.algorithm.signature_length() {
            return Err(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcPublicVerificationBounds,
            ));
        }
        let framed = match &self.input {
            VerificationInput::Pure { .. } => None,
            VerificationInput::Prehashed { hash, context } => {
                Some(frame(*hash, context.as_slice(), message)?)
            }
            VerificationInput::HashMessage { hash, context } => {
                let digest = prehash(self.key.context, *hash, message)?;
                Some(frame(*hash, context.as_slice(), digest.as_slice())?)
            }
        };
        let message = framed.as_ref().map_or(message, |owned| owned.as_slice());
        let request = self.request();
        // SAFETY: the key, context bytes and optional FIPS frame remain live and
        // immutable throughout this call. HASH framing is never applied twice.
        unsafe {
            self.key
                .context
                .engine()
                .verify(&request, message, signature)
        }
        .map_err(failure)
    }
}
