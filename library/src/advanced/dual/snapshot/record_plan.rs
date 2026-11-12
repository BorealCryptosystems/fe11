// SPDX-License-Identifier: Apache-2.0
//! Borrowed dual reconstruction: no retained IV or fragment table before admission.
use super::{Authentication, DualStorage, Mode, Parameters, PreparedDual, Shape, Storage};
use crate::advanced::{capture_parts, record};
use crate::{
    bounds,
    symmetric::{
        cipher::CipherFrame,
        memory::{Credit, UnboundBuffer},
    },
    AeadNonce, DualCipher, Error, Result,
};
use fe11_sys::{CKM_AES_GCM, CK_GCM_PARAMS};
use std::{mem::size_of, sync::Arc};

enum CipherRecipe<'a> {
    Classic(DualCipher<'static>),
    Gcm {
        iv: &'a [u8],
        aad: &'a [u8],
        tag_bits: u64,
    },
}

pub(in crate::advanced) struct RecordPlan<'a> {
    descriptor: record::Descriptor,
    message: record::Message<'a>,
    cipher: CipherRecipe<'a>,
    shape: Shape,
    projection: Projection,
}
enum Projection {
    Checkpoint { pending: bool },
    Fresh,
}

impl<'a> RecordPlan<'a> {
    pub(in crate::advanced) fn new(
        descriptor: record::Descriptor,
        messages: &record::Messages<'a>,
        ceilings: crate::CryptoLimits,
        pending: bool,
    ) -> Result<Self> {
        Self::with_projection(
            descriptor,
            messages,
            ceilings,
            Projection::Checkpoint { pending },
        )
    }
    pub(in crate::advanced) fn recovery(
        descriptor: record::Descriptor,
        messages: &record::Messages<'a>,
        ceilings: crate::CryptoLimits,
    ) -> Result<Self> {
        Self::with_projection(descriptor, messages, ceilings, Projection::Fresh)
    }
    fn with_projection(
        descriptor: record::Descriptor,
        messages: &record::Messages<'a>,
        ceilings: crate::CryptoLimits,
        projection: Projection,
    ) -> Result<Self> {
        let message = messages.iter().next().ok_or(Error::Rejected(
            crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::ReconstructionDualMessage,
            ),
        ))??;
        let authentication = Authentication::from_record(descriptor, &message)?;
        let input = crate::InputLimits {
            maximum_parts: ceilings.maximum_parts,
            maximum_total_bytes: ceilings.maximum_total_bytes,
        }
        .validate_lengths(
            ceilings,
            message.fragments.len(),
            message.fragments.iter().map(|part| part.map(<[u8]>::len)),
        )?;
        let mode = match descriptor.family {
            record::Family::DigestEncrypt => Mode::DigestEncrypt,
            record::Family::DecryptDigest => Mode::DecryptDigest,
            record::Family::SignEncrypt => Mode::SignEncrypt,
            record::Family::DecryptVerify => Mode::DecryptVerify,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::ReconstructionDualMode,
                )))
            }
        };
        let nonce = match projection {
            Projection::Checkpoint { .. } => message.params.nonce,
            Projection::Fresh => message.params.iv_initial,
        }
        .ok_or(Error::Rejected(crate::RejectionReason::CombinedOperations(
            crate::CombinedOperationsRejection::ReconstructionDualNonce,
        )))?;
        let (cipher, native_bytes, cipher_bytes) = if descriptor.mechanism == CKM_AES_GCM as u64 {
            let aad = message.params.aad.ok_or(Error::Rejected(
                crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::ReconstructionDualAad,
                ),
            ))?;
            let generator = message.params.iv_generator.unwrap_or(0);
            let fixed_bits = message.params.iv_fixed_bits.unwrap_or(0);
            let tag_bits = message.params.tag_bits as u64;
            AeadNonce::validate_gcm_dimensions(
                crate::symmetric::AeadParameterLayout::Classic,
                nonce.len(),
                aad.len(),
                fixed_bits,
                generator,
                tag_bits,
            )?;
            if generator != 0 || fixed_bits != 0 {
                return Err(Error::Rejected(
                    crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::ClassicGcmDoesNotGenerateAnIv,
                    ),
                ));
            }
            bounds::ck_length(nonce.len())?;
            let bytes = nonce
                .len()
                .checked_mul(3)
                .and_then(|n| n.checked_add(aad.len()))
                .ok_or(Error::Rejected(
                    crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::DualCipherStorageSize,
                    ),
                ))?;
            (
                CipherRecipe::Gcm {
                    iv: nonce,
                    aad,
                    tag_bits,
                },
                size_of::<CK_GCM_PARAMS>(),
                bytes,
            )
        } else {
            let cipher = CipherFrame::record_request(
                descriptor.mechanism,
                nonce,
                message.params.counter_bits,
            )?;
            let native = CipherFrame::native_parameter_bytes(&cipher);
            let bytes = CipherFrame::allocation_bytes(&cipher)?;
            (CipherRecipe::Classic(cipher), native, bytes)
        };
        if input
            .checked_add(message.params.aad.map_or(0, <[u8]>::len))
            .and_then(|n| n.checked_add(nonce.len()))
            .and_then(|n| {
                n.checked_add(if mode.mac() {
                    authentication.length()
                } else {
                    0
                })
            })
            .map_or(true, |n| n > ceilings.maximum_total_bytes)
        {
            return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualContextCeiling,
            )));
        }
        if matches!(projection, Projection::Fresh) {
            super::super::output_bounds(
                input,
                mode.decrypt(),
                descriptor.mechanism,
                (message.params.tag_bits as usize).div_ceil(8),
            )?;
        }
        let expected = if mode == Mode::DecryptVerify {
            message.tag_or_signature
        } else {
            None
        };
        let fragments = message.fragments.len();
        let parts = fragments.max(1);
        let storage = DualStorage::for_dimensions(
            mode,
            authentication,
            fragments,
            input,
            expected,
            native_bytes,
            cipher_bytes,
        )?;
        let shape = Shape {
            mode,
            authentication,
            parts,
            fragments,
            input,
            auth_capacity: authentication.length(),
            metadata: storage.metadata,
            total: storage
                .total
                .checked_add(capture_parts::Storage::temporary_bytes(parts)?)
                .ok_or(Error::Rejected(crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::DualSnapshotAccounting,
                )))?,
        };
        Ok(Self {
            descriptor,
            message,
            cipher,
            shape,
            projection,
        })
    }

    pub(in crate::advanced) fn allocation_bytes(&self) -> usize {
        self.shape.total
    }

    pub(in crate::advanced) fn allocate(&self, prepaid: &mut Credit) -> Result<Storage> {
        // The complete graph is admitted before the retained GCM IV is copied.
        let parameters = match &self.cipher {
            CipherRecipe::Classic(cipher) => Parameters::for_dual(cipher, prepaid)?,
            CipherRecipe::Gcm { iv, aad, tag_bits } => {
                let cipher = DualCipher::Gcm {
                    nonce: AeadNonce::Gcm {
                        iv: Arc::from(*iv),
                        generator: 0,
                        fixed_bits: 0,
                        tag_bits: *tag_bits,
                    },
                    aad,
                };
                Parameters::for_dual(&cipher, prepaid)?
            }
        }
        .allocate()?;
        let output = self.shape.input.checked_add(32).ok_or(Error::Rejected(
            crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualOutputOverflow,
            ),
        ))?;
        let parts = if self.shape.fragments == 0 {
            capture_parts::Storage::allocate_lengths(
                std::iter::once(0),
                std::iter::empty(),
                output,
            )?
        } else {
            capture_parts::Storage::allocate_fallible(
                self.shape.fragments,
                self.message.fragments.iter().map(|p| p.map(<[u8]>::len)),
                self.shape.fragments,
                self.message.fragments.iter().map(|p| p.map(<[u8]>::len)),
                output,
            )?
        };
        Ok(Storage {
            shape: self.shape,
            parameters,
            parts,
            extra: UnboundBuffer::allocate(self.shape.auth_capacity)?,
            completion_diagnostic: crate::error::CompletionStorage::allocate()?,
            metadata_credit: None,
        })
    }

    pub(in crate::advanced) fn bind(
        self,
        storage: Storage,
        prepaid: &mut Credit,
    ) -> Result<PreparedDual> {
        let mut body = storage.bind(prepaid)?.body;
        // Fill directly from the immutable record; do not allocate a second IV owner.
        body.cipher.fill_record_bytes(
            self.descriptor.mechanism,
            match self.projection {
                Projection::Checkpoint { .. } => self.message.params.nonce,
                Projection::Fresh => self.message.params.iv_initial,
            }
            .ok_or(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::ReconstructionDualNonce,
            )))?,
            self.message.params.aad.unwrap_or(&[]),
        )?;
        for (index, source) in self.message.fragments.iter().enumerate() {
            let source = source?;
            let target = body.inputs.get_mut(index).ok_or(Error::Rejected(
                crate::RejectionReason::CheckpointCapture(
                    crate::CheckpointCaptureRejection::DualSnapshotShapeChanged,
                ),
            ))?;
            if target.as_slice().len() != source.len() {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                    crate::CheckpointCaptureRejection::DualSnapshotShapeChanged,
                )));
            }
            target.as_mut().copy_from_slice(source);
        }
        if self.shape.mode == Mode::DecryptVerify {
            let expected = self.message.tag_or_signature.ok_or(Error::Rejected(
                crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::DualAuthenticationOwner,
                ),
            ))?;
            if expected.len() != body.auth.as_slice().len() {
                return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::DualFullMacLength,
                )));
            }
            body.auth.as_mut().copy_from_slice(expected);
        }
        *body.auth_length = bounds::ck_length(self.shape.authentication.length())?;
        match self.projection {
            Projection::Checkpoint { pending } => {
                PreparedDual::finish_record(body, self.descriptor, &self.message, pending)
            }
            Projection::Fresh => Ok(body),
        }
    }
}
