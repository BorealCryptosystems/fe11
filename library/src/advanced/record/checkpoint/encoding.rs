// SPDX-License-Identifier: Apache-2.0
//! Encode and decode checkpoint descriptors using the persistent wire layout.
//! Typed profiles are converted at this boundary rather than used as raw phase tags.

use super::*;

impl Descriptor {
    pub(in crate::advanced) fn symmetric_profile(
        algorithm: crate::SymmetricAlgorithm,
    ) -> Result<u8> {
        use crate::SymmetricAlgorithm::*;
        // HMAC profile tags identify the MAC hash, not its key byte count.
        // Restoration separately binds the actual native key/reference.
        Ok(match algorithm {
            Aes128 => profile::AES128,
            Aes192 => profile::AES192,
            Aes256 => profile::AES256,
            HmacSha256 { .. } => profile::HMAC_SHA256,
            HmacSha384 { .. } => profile::HMAC_SHA384,
            HmacSha512 { .. } => profile::HMAC_SHA512,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::CheckpointSymmetricProfile,
                )))
            }
        })
    }

    pub(in crate::advanced) fn write(&self, w: &mut Writer<'_>) -> Result<()> {
        if self.digest_bits.is_some()
            && (self.family != Family::Digest || self.cipher_options.is_some())
        {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::DigestParametersOnAnotherRecordFamily,
            )));
        }
        if !self.family.is_cipher() && self.cipher_options.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::CipherOptionsOnAnotherRecordFamily,
            )));
        }
        w.u8(self.family.wire())?;
        w.u8(self.profile)?;
        self.phase.write_phase(w)?;
        w.u64(self.mechanism)?;
        w.u64(self.size as u64)?;
        w.u64(self.active_flags)?;
        w.u8(u8::from(self.validation_requested))?;
        w.u32(u32::try_from(self.carried_messages).map_err(|_| {
            Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::RecordCarriedPrefixWidth,
            ))
        })?)?;
        self.input.write(w)?;
        if let Some(bits) = self.digest_bits {
            w.u8(OptionsTag::DigestBits.wire())?;
            return w.u64(bits);
        }
        match self.cipher_options {
            Some(CipherOptions::CcmDataLength { bytes }) => {
                w.u8(OptionsTag::CcmDataLength.wire())?;
                w.u64(bytes)
            }
            None => w.u8(OptionsTag::None.wire()),
            Some(CipherOptions::ChaChaIetfBytes) => w.u8(OptionsTag::ChaChaIetfBytes.wire()),
            Some(CipherOptions::GcmWithoutIvBits) => w.u8(OptionsTag::GcmWithoutIvBits.wire()),
            Some(CipherOptions::TokenIv { generated }) => {
                w.u8(OptionsTag::TokenIv.wire())?;
                w.u8(u8::from(generated))
            }
            Some(CipherOptions::Stream { counter }) => {
                w.u8(OptionsTag::Stream.wire())?;
                w.u8(counter.bits() as u8)?;
                w.bytes(counter.bytes())
            }
            Some(CipherOptions::Rc2 { effective_bits }) => {
                w.u8(OptionsTag::Rc2.wire())?;
                w.u64(effective_bits)
            }
            Some(CipherOptions::Rc5 { word_bytes, rounds }) => {
                w.u8(OptionsTag::Rc5.wire())?;
                w.u64(word_bytes)?;
                w.u64(rounds)
            }
        }
    }

    pub(in crate::advanced) fn read(r: &mut Reader<'_>) -> Result<Self> {
        let family = Family::from_wire(r.u8()?)?;
        let profile = r.u8()?;
        let phase = Function::read_phase(r)?;
        let mechanism = r.u64()?;
        let size = usize::try_from(r.u64()?).map_err(|_| {
            Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::RecordSignatureCapacity,
            ))
        })?;
        let active_flags = r.u64()?;
        let validation_requested = r.boolean(crate::RejectionReason::CheckpointFormat(
            crate::CheckpointFormatRejection::RecordValidationRequest,
        ))?;
        let carried_messages = r.u32()? as usize;
        let input = crate::advanced::input::InputState::read(r)?;
        let mut digest_bits = None;
        let cipher_options = match OptionsTag::from_wire(r.u8()?)? {
            OptionsTag::CcmDataLength => Some(CipherOptions::CcmDataLength { bytes: r.u64()? }),
            OptionsTag::None => None,
            OptionsTag::DigestBits => {
                digest_bits = Some(r.u64()?);
                None
            }
            OptionsTag::ChaChaIetfBytes => Some(CipherOptions::ChaChaIetfBytes),
            OptionsTag::GcmWithoutIvBits => Some(CipherOptions::GcmWithoutIvBits),
            OptionsTag::Rc2 => Some(CipherOptions::Rc2 {
                effective_bits: r.u64()?,
            }),
            OptionsTag::Rc5 => Some(CipherOptions::Rc5 {
                word_bytes: r.u64()?,
                rounds: r.u64()?,
            }),
            OptionsTag::Stream => {
                let bits = r.u8()? as u64;
                let bytes = r.bytes(8)?;
                Some(CipherOptions::Stream {
                    counter: StreamCounter::from_wire(bits, bytes)?,
                })
            }
            OptionsTag::TokenIv => Some(CipherOptions::TokenIv {
                generated: r.boolean(crate::RejectionReason::CheckpointFormat(
                    crate::CheckpointFormatRejection::RecordTokenIvDirection,
                ))?,
            }),
        };
        if digest_bits.is_some() && family != Family::Digest {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::DigestParametersOnAnotherRecordFamily,
            )));
        }
        if !family.is_cipher() && cipher_options.is_some() {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointFormat(
                crate::CheckpointFormatRejection::CipherOptionsOnAnotherRecordFamily,
            )));
        }
        Ok(Self {
            input,
            family,
            profile,
            phase,
            mechanism,
            size,
            active_flags,
            validation_requested,
            carried_messages,
            cipher_options,
            digest_bits,
        })
    }
}
