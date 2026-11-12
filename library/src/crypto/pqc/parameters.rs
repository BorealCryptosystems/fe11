// SPDX-License-Identifier: Apache-2.0

use super::{PqcAlgorithm, PqcHash};
use crate::{Error, Result, SecretBytes};
use fe11_sys::*;

pub(super) fn validate_message(
    limits: crate::InputLimits,
    module: crate::CryptoLimits,
    length: usize,
) -> Result<()> {
    // Validate the common per-call/module budgets. A pure PQC request owns one
    // complete message. The caller-selected total ceiling applies before any
    // owned copy; there is no additional library-defined fragment ceiling.
    limits.validate(module, &[])?;
    crate::bounds::ck_length(length)?;
    if limits.maximum_parts < 1 || length > limits.maximum_total_bytes {
        return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
            crate::PostQuantumKeysRejection::PqcMessageCeiling,
        )));
    }
    Ok(())
}

/// Explicit native hedging requirement. No implicit downgrade or Default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqcHedging {
    /// Token may choose a hedged or deterministic signature.
    Preferred,
    /// Require the hedged variant, or retain the native refusal.
    Required,
    /// Require the deterministic variant, or retain the native refusal.
    DeterministicRequired,
}

/// Explicit input semantics; native dispatch never converts between modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqcSignatureMode {
    /// Original message, pure ML-DSA or SLH-DSA.
    Pure,
    /// Already hashed message, using CKM_HASH_ML_DSA or CKM_HASH_SLH_DSA.
    Prehashed(PqcHash),
    /// Original message, hashed by the module's combined mechanism.
    HashMessage(PqcHash),
}

impl PqcSignatureMode {
    pub(super) fn mechanism_type(self, algorithm: PqcAlgorithm) -> Result<CK_MECHANISM_TYPE> {
        Ok(match self {
            Self::Pure => algorithm.signature_mechanism(),
            Self::Prehashed(_) => match algorithm {
                PqcAlgorithm::MlDsa(_) => CKM_HASH_ML_DSA,
                PqcAlgorithm::SlhDsa(_) => CKM_HASH_SLH_DSA,
            },
            Self::HashMessage(hash) => hash.signature_mechanism(algorithm)?,
        })
    }
}

/// Owned parameters for an explicitly selected ML-DSA/SLH-DSA signature mode.
pub struct PqcSignatureParameters {
    context: SecretBytes,
    hedging: PqcHedging,
    mode: PqcSignatureMode,
}

impl PqcSignatureParameters {
    /// Own a context of0to255bytes and the explicitly selected hedging policy.
    /// A nonempty general-purpose context is not the PKIX profile.
    pub fn pure(context: &[u8], hedging: PqcHedging) -> Result<Self> {
        Self::new(PqcSignatureMode::Pure, context, hedging)
    }

    /// Choose the input semantics, binary context and hedging requirement.
    /// External SHAKE prehashes return `Error::Unsupported` in the strict 3.2
    /// profile: no standardized native hash identifier exists. Combined SHAKE
    /// mechanisms remain selectable, subject to the module's capabilities.
    pub fn new(mode: PqcSignatureMode, context: &[u8], hedging: PqcHedging) -> Result<Self> {
        if context.len() > 255 {
            return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcContextLength,
            )));
        }
        if let PqcSignatureMode::Prehashed(hash) = mode {
            hash.digest_mechanism()?;
        }
        if let PqcSignatureMode::HashMessage(hash) = mode {
            hash.combined_mechanisms()?;
        }
        let mut owned = SecretBytes::new(context.len())?;
        owned.as_mut_slice().copy_from_slice(context);
        Ok(Self {
            context: owned,
            hedging,
            mode,
        })
    }

    /// Pure PKIX profile with an empty context and an explicit hedging policy.
    pub fn pkix(hedging: PqcHedging) -> Result<Self> {
        Self::pure(&[], hedging)
    }

    /// Borrow the exact context, without adding a string terminator or decoding.
    pub fn context(&self) -> &[u8] {
        self.context.as_slice()
    }

    /// The requested hedging policy, not a claim about provider execution.
    pub fn hedging(&self) -> PqcHedging {
        self.hedging
    }

    /// Exact input semantics, never inferred from the input length.
    pub fn mode(&self) -> PqcSignatureMode {
        self.mode
    }

    pub(super) fn validate_input(&self, length: usize) -> Result<()> {
        if let PqcSignatureMode::Prehashed(hash) = self.mode {
            if length != hash.output_length() {
                return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                    crate::PostQuantumKeysRejection::PqcPrehashLength,
                )));
            }
        }
        Ok(())
    }

    pub(super) fn mechanism_type(&self, algorithm: PqcAlgorithm) -> Result<CK_MECHANISM_TYPE> {
        self.mode.mechanism_type(algorithm)
    }

    pub(super) fn native_hedging(&self) -> CK_HEDGE_TYPE {
        match self.hedging {
            PqcHedging::Preferred => CKH_HEDGE_PREFERRED,
            PqcHedging::Required => CKH_HEDGE_REQUIRED,
            PqcHedging::DeterministicRequired => CKH_DETERMINISTIC_REQUIRED,
        }
    }
}

pub(super) struct NativeParameters {
    descriptor: NativeDescriptor,
    _context: SecretBytes,
}

enum NativeDescriptor {
    Pure(Box<CK_SIGN_ADDITIONAL_CONTEXT>),
    HashMessage {
        hash: PqcHash,
        descriptor: Box<CK_SIGN_ADDITIONAL_CONTEXT>,
    },
    Prehashed(Box<CK_HASH_SIGN_ADDITIONAL_CONTEXT>),
}

impl NativeParameters {
    /// Known native storage before allocation; actual capacity is checked by
    /// the preparing owner before any parameter is handed to the module.
    pub(super) fn requested_bytes(parameters: &PqcSignatureParameters) -> Result<usize> {
        let descriptor = match parameters.mode() {
            PqcSignatureMode::Pure | PqcSignatureMode::HashMessage(_) => {
                std::mem::size_of::<CK_SIGN_ADDITIONAL_CONTEXT>()
            }
            PqcSignatureMode::Prehashed(_) => {
                std::mem::size_of::<CK_HASH_SIGN_ADDITIONAL_CONTEXT>()
            }
        };
        descriptor
            .checked_add(parameters.context().len())
            .ok_or(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcNativeParameterStorage,
            )))
    }
    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        let descriptor = match &self.descriptor {
            NativeDescriptor::Pure(_) | NativeDescriptor::HashMessage { .. } => {
                std::mem::size_of::<CK_SIGN_ADDITIONAL_CONTEXT>()
            }
            NativeDescriptor::Prehashed(_) => {
                std::mem::size_of::<CK_HASH_SIGN_ADDITIONAL_CONTEXT>()
            }
        };
        descriptor
            .checked_add(self._context.allocated_bytes())
            .ok_or(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcNativeParameterStorage,
            )))
    }
    /// Compare only owned descriptors and buffers, never follow a pointer
    /// returned by the module. Call only after a synchronous classified return.
    pub(super) fn unchanged(
        &self,
        mechanism: &CK_MECHANISM,
        algorithm: PqcAlgorithm,
        expected: &PqcSignatureParameters,
    ) -> bool {
        if expected.mechanism_type(algorithm).ok() != Some(mechanism.mechanism)
            || self._context.as_slice() != expected.context()
        {
            return false;
        }
        let context_pointer = if self._context.len() == 0 {
            std::ptr::null_mut()
        } else {
            self._context.as_slice().as_ptr().cast_mut()
        };
        let context_length = self._context.len() as CK_ULONG;
        let message_matches = |descriptor: &CK_SIGN_ADDITIONAL_CONTEXT| {
            descriptor.hedgeVariant == expected.native_hedging()
                && descriptor.pContext == context_pointer
                && descriptor.ulContextLen == context_length
                && mechanism.pParameter
                    == (descriptor as *const CK_SIGN_ADDITIONAL_CONTEXT)
                        .cast_mut()
                        .cast()
                && mechanism.ulParameterLen as usize
                    == std::mem::size_of::<CK_SIGN_ADDITIONAL_CONTEXT>()
        };
        match (&self.descriptor, expected.mode()) {
            (NativeDescriptor::Pure(descriptor), PqcSignatureMode::Pure) => {
                message_matches(descriptor)
            }
            (
                NativeDescriptor::HashMessage { hash, descriptor },
                PqcSignatureMode::HashMessage(expected_hash),
            ) => *hash == expected_hash && message_matches(descriptor),
            (NativeDescriptor::Prehashed(descriptor), PqcSignatureMode::Prehashed(hash)) => {
                descriptor.hedgeVariant == expected.native_hedging()
                    && descriptor.pContext == context_pointer
                    && descriptor.ulContextLen == context_length
                    && hash.digest_mechanism().ok() == Some(descriptor.hash)
                    && mechanism.pParameter
                        == (&**descriptor as *const CK_HASH_SIGN_ADDITIONAL_CONTEXT)
                            .cast_mut()
                            .cast()
                    && mechanism.ulParameterLen as usize
                        == std::mem::size_of::<CK_HASH_SIGN_ADDITIONAL_CONTEXT>()
            }
            _ => false,
        }
    }

    /// Allocate the complete descriptor graph with an empty context. The
    /// preparing owner measures actual capacity before binding caller bytes.
    pub(super) fn allocate(parameters: &PqcSignatureParameters) -> Result<Self> {
        let mut context = SecretBytes::new(parameters.context().len())?;
        let pointer = if context.len() == 0 {
            std::ptr::null_mut()
        } else {
            context.as_mut_slice().as_mut_ptr()
        };
        let length = crate::bounds::ck_length(context.len())?;
        let message_descriptor = || {
            Box::new(CK_SIGN_ADDITIONAL_CONTEXT {
                hedgeVariant: parameters.native_hedging(),
                pContext: pointer,
                ulContextLen: length,
            })
        };
        // The context bound is checked before allocation; its 0..255 length
        // fits every PKCS#11 CK_ULONG ABI.
        let descriptor = match parameters.mode {
            PqcSignatureMode::Pure => NativeDescriptor::Pure(message_descriptor()),
            PqcSignatureMode::HashMessage(hash) => NativeDescriptor::HashMessage {
                hash,
                descriptor: message_descriptor(),
            },
            PqcSignatureMode::Prehashed(hash) => {
                NativeDescriptor::Prehashed(Box::new(CK_HASH_SIGN_ADDITIONAL_CONTEXT {
                    hedgeVariant: parameters.native_hedging(),
                    pContext: pointer,
                    ulContextLen: length,
                    hash: hash.digest_mechanism()?,
                }))
            }
        };
        Ok(Self {
            descriptor,
            _context: context,
        })
    }

    pub(super) fn bind_context(&mut self, parameters: &PqcSignatureParameters) {
        self._context
            .as_mut_slice()
            .copy_from_slice(parameters.context());
    }

    pub(super) fn mechanism(&mut self, algorithm: super::PqcAlgorithm) -> Result<CK_MECHANISM> {
        let (mechanism, pointer, length) = match &mut self.descriptor {
            NativeDescriptor::Pure(descriptor) => (
                algorithm.signature_mechanism(),
                (&mut **descriptor as *mut CK_SIGN_ADDITIONAL_CONTEXT).cast(),
                std::mem::size_of::<CK_SIGN_ADDITIONAL_CONTEXT>(),
            ),
            NativeDescriptor::HashMessage { hash, descriptor } => (
                hash.signature_mechanism(algorithm)?,
                (&mut **descriptor as *mut CK_SIGN_ADDITIONAL_CONTEXT).cast(),
                std::mem::size_of::<CK_SIGN_ADDITIONAL_CONTEXT>(),
            ),
            NativeDescriptor::Prehashed(descriptor) => (
                match algorithm {
                    PqcAlgorithm::MlDsa(_) => CKM_HASH_ML_DSA,
                    PqcAlgorithm::SlhDsa(_) => CKM_HASH_SLH_DSA,
                },
                (&mut **descriptor as *mut CK_HASH_SIGN_ADDITIONAL_CONTEXT).cast(),
                std::mem::size_of::<CK_HASH_SIGN_ADDITIONAL_CONTEXT>(),
            ),
        };
        Ok(CK_MECHANISM {
            mechanism,
            pParameter: pointer,
            // Fixed native structure, verified against the pinned C header.
            ulParameterLen: length as CK_ULONG,
        })
    }
}
