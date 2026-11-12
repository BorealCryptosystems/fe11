// SPDX-License-Identifier: Apache-2.0
//! Associate checkpoint key roles with their recorded signature parameters.
//! Bindings describe required identities without acquiring destination key possession.

use super::*;

impl Descriptor {
    pub(in crate::advanced::record) fn keys(
        self,
        keys: &KeyBindings<'_>,
        limits: Limits,
    ) -> Result<()> {
        let cipher = matches!(
            self.family,
            Family::MessageEncrypt
                | Family::MessageDecrypt
                | Family::DigestEncrypt
                | Family::DecryptDigest
                | Family::SignEncrypt
                | Family::DecryptVerify
        );
        let auth = matches!(
            self.family,
            Family::MessageSign
                | Family::MessageVerify
                | Family::SignEncrypt
                | Family::DecryptVerify
        );
        if keys.cipher.is_some() != cipher
            || keys.authentication.is_some() != auth
            || self.size > limits.bytes
        {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::RecordProfileKeyRoles,
            )));
        }
        if cipher {
            let k = keys.cipher.unwrap();
            let stream_aead = crate::symmetric::poly1305::is_stream_aead(self.mechanism);
            let native_message_key =
                matches!(self.family, Family::MessageEncrypt | Family::MessageDecrypt)
                    && self.profile == profile::NATIVE_KEY_TYPE;
            if native_message_key {
                if self.size != 0 {
                    return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                        crate::CheckpointFormatRejection::RecordNativeAeadKeyProfile,
                    )));
                }
                // A native reference has no required class/type observation.
                // Preserve any recorded description for destination comparison;
                // algorithm compatibility remains the native module's decision.
            } else if stream_aead {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecordStreamAeadKeyProfile,
                )));
            } else if k.class != Some(CKO_SECRET_KEY as u64)
                || k.key_type != Some(CKK_AES as u64)
                || !(profile::AES128..=profile::AES256).contains(
                    &crate::advanced::dual::authentication::cipher_profile(self)?,
                )
                || self.size != 0
            {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecordAesProfile,
                )));
            }
            if !stream_aead
                && self.mechanism != CKM_AES_GCM as u64
                && !(matches!(self.family, Family::MessageEncrypt | Family::MessageDecrypt)
                    && self.mechanism == CKM_AES_CCM as u64)
                && !(self.dual() && crate::advanced::dual::cipher::non_aead(self.mechanism))
            {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecordCipherMechanism,
                )));
            }
        } else if self.family == Family::Digest {
            crate::advanced::digest::DigestSelection::from_descriptor(self)?;
        } else if !matches!(self.family, Family::MessageSign | Family::MessageVerify) {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::RecordOperationFamily,
            )));
        }
        if auth {
            let k = keys.authentication.unwrap();
            if matches!(
                self.profile,
                profile::RSA_PSS_SHA256 | profile::RSA_PSS_SELECTED
            ) {
                if k.class
                    != Some(if self.family == Family::MessageSign {
                        CKO_PRIVATE_KEY as u64
                    } else {
                        CKO_PUBLIC_KEY as u64
                    })
                    || k.key_type != Some(CKK_RSA as u64)
                    || self.profile == profile::RSA_PSS_SHA256
                        && self.mechanism != CKM_SHA256_RSA_PKCS_PSS as u64
                    || self.size == 0
                {
                    return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                        crate::CheckpointFormatRejection::RecordRsaProfile,
                    )));
                }
            } else if self.dual() {
                // The message hash binds the exact HMAC key type below. Check
                // the role here without inferring a SHA-256 default.
                if k.class != Some(CKO_SECRET_KEY as u64) {
                    return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                        crate::CheckpointFormatRejection::RecordDualMacClass,
                    )));
                }
            } else {
                let (kind, key_type, size) = match self.profile {
                    profile::HMAC_SHA256 => (CKM_SHA256_HMAC, CKK_SHA256_HMAC, 32),
                    profile::HMAC_SHA384 => (CKM_SHA384_HMAC, CKK_SHA384_HMAC, 48),
                    profile::HMAC_SHA512 => (CKM_SHA512_HMAC, CKK_SHA512_HMAC, 64),
                    _ => {
                        return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                            crate::CheckpointFormatRejection::RecordMacProfile,
                        )))
                    }
                };
                if k.class != Some(CKO_SECRET_KEY as u64)
                    || !matches!(k.key_type,Some(x) if x==CKK_GENERIC_SECRET as u64||x==key_type as u64)
                    || !self.dual() && (self.mechanism != kind as u64 || self.size != size)
                {
                    return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                        crate::CheckpointFormatRejection::RecordMacKey,
                    )));
                }
            }
        }
        if self.family != Family::Digest && self.validation_requested
            || !self.dual() && self.active_flags != 0
        {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::RecordDescriptorFlags,
            )));
        }
        Ok(())
    }

    pub(in crate::advanced::record) fn signature_parameters(
        self,
        p: &super::super::Parameters<'_>,
    ) -> Result<()> {
        if p.digest_output.is_some()
            || p.cipher_extension.is_some()
            || p.digest_extension.is_some()
            || p.signature.is_some()
            || p.message_init.is_some()
            || p.counter_bits.is_some()
            || p.nonce.is_some()
            || p.aad.is_some()
            || p.digest_oid.is_some()
            || p.iv_generator.is_some()
            || p.iv_fixed_bits.is_some()
            || p.iv_initial.is_some()
        {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::RecordSignatureParameterFamily,
            )));
        }
        let valid = if matches!(
            self.profile,
            profile::RSA_PSS_SHA256 | profile::RSA_PSS_SELECTED
        ) {
            p.tag_bits == 0 && crate::advanced::messages::pss::record_parameters(self, p).is_ok()
        } else {
            Some(p.tag_bits)
                == u32::try_from(self.size)
                    .ok()
                    .and_then(|size| size.checked_mul(8))
                && p.hash.is_none()
                && p.mgf.is_none()
                && p.salt.is_none()
        };
        if !valid {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::RecordSignatureParameters,
            )));
        }
        Ok(())
    }
}
