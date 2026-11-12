// SPDX-License-Identifier: Apache-2.0
//! Exact stream-cipher counter/nonce tuples and stable native pointers.
use super::memory::Buffer;

use crate::{Error, Result};
use fe11_sys::*;

/// Native ChaCha20/Salsa20 selections without authentication.
///
/// The caller supplies exact counter and nonce bytes and must prevent reuse
/// under the same key. No nonce generation, counter reset or MAC is implicit.
/// Parameters are copied into owned buffers before native initialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamCipherParameters {
    /// ChaCha20: 64-bit nonce and 64-bit initial counter.
    ChaCha20 {
        /// Exact native counter bytes, not a host-endian integer conversion.
        counter: [u8; 8],
        /// Exact nonce; uniqueness under the encryption key is caller-owned.
        nonce: [u8; 8],
    },
    /// ChaCha20Ietf: 96-bit nonce and 32-bit initial counter.
    ChaCha20Ietf {
        /// Exact native counter bytes, not a host-endian integer conversion.
        counter: [u8; 4],
        /// Exact nonce; uniqueness under the encryption key is caller-owned.
        nonce: [u8; 12],
    },
    /// XChaCha20: 192-bit nonce and 64-bit initial counter.
    XChaCha20 {
        /// Exact native counter bytes, not a host-endian integer conversion.
        counter: [u8; 8],
        /// Exact nonce; uniqueness under the encryption key is caller-owned.
        nonce: [u8; 24],
    },
    /// Salsa20: 64-bit nonce and 64-bit initial counter.
    Salsa20 {
        /// Exact native counter bytes, not a host-endian integer conversion.
        counter: [u8; 8],
        /// Exact nonce; uniqueness under the encryption key is caller-owned.
        nonce: [u8; 8],
    },
    /// XSalsa20: 192-bit nonce and 64-bit initial counter.
    XSalsa20 {
        /// Exact native counter bytes, not a host-endian integer conversion.
        counter: [u8; 8],
        /// Exact nonce; uniqueness under the encryption key is caller-owned.
        nonce: [u8; 24],
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StreamCounter {
    Bits32([u8; 4]),
    Bits64([u8; 8]),
}
impl StreamCounter {
    pub(crate) fn bytes(&self) -> &[u8] {
        match self {
            Self::Bits32(v) => v,
            Self::Bits64(v) => v,
        }
    }
    pub(crate) fn bits(self) -> u64 {
        (self.bytes().len() * 8) as u64
    }
    pub(crate) fn from_wire(bits: u64, bytes: &[u8]) -> Result<Self> {
        match bits {
            32 => Ok(Self::Bits32(bytes.try_into().map_err(|_| {
                Error::Rejected(crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::Value32BitStreamCounterLength,
                ))
            })?)),
            64 => Ok(Self::Bits64(bytes.try_into().map_err(|_| {
                Error::Rejected(crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::Value64BitStreamCounterLength,
                ))
            })?)),
            _ => Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::StreamCounterWidth,
                ),
            )),
        }
    }
}
impl StreamCipherParameters {
    /// Exact mechanism identifier, without asserting that a module supports it.
    pub fn mechanism_number(self) -> u64 {
        self.kind() as u64
    }
    pub(crate) fn kind(self) -> CK_MECHANISM_TYPE {
        match self {
            Self::ChaCha20 { .. } | Self::ChaCha20Ietf { .. } | Self::XChaCha20 { .. } => {
                CKM_CHACHA20
            }
            Self::Salsa20 { .. } | Self::XSalsa20 { .. } => CKM_SALSA20,
        }
    }
    pub(crate) fn nonce(&self) -> &[u8] {
        match self {
            Self::ChaCha20 { nonce, .. } => nonce,
            Self::ChaCha20Ietf { nonce, .. } => nonce,
            Self::XChaCha20 { nonce, .. } => nonce,
            Self::Salsa20 { nonce, .. } => nonce,
            Self::XSalsa20 { nonce, .. } => nonce,
        }
    }
    pub(crate) fn counter(self) -> StreamCounter {
        match self {
            Self::ChaCha20 { counter, .. } => StreamCounter::Bits64(counter),
            Self::ChaCha20Ietf { counter, .. } => StreamCounter::Bits32(counter),
            Self::XChaCha20 { counter, .. } => StreamCounter::Bits64(counter),
            Self::Salsa20 { counter, .. } => StreamCounter::Bits64(counter),
            Self::XSalsa20 { counter, .. } => StreamCounter::Bits64(counter),
        }
    }
    pub(crate) fn output_bounds(self, input: usize) -> Result<(usize, usize)> {
        // PKCS#11 3.2 table 256: the IETF variant has a 32-bit block counter
        // addressing 64-byte blocks. Native code handles the initial counter.
        if matches!(self, Self::ChaCha20Ietf { .. }) && input as u128 > (1u128 << 38) {
            return Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::Chacha20IetfMessageLength,
                ),
            ));
        }
        Ok((input, input))
    }
    pub(crate) fn native_bytes(self) -> usize {
        if self.kind() == CKM_CHACHA20 {
            std::mem::size_of::<CK_CHACHA20_PARAMS>()
        } else {
            std::mem::size_of::<CK_SALSA20_PARAMS>()
        }
    }
    pub(crate) fn from_record(
        kind: CK_MECHANISM_TYPE,
        counter: StreamCounter,
        nonce: &[u8],
    ) -> Result<Self> {
        Ok(match (kind, counter, nonce.len()) {
            (CKM_CHACHA20, StreamCounter::Bits64(counter), 8) => Self::ChaCha20 {
                counter,
                nonce: nonce.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::StreamNonceWidth,
                    ))
                })?,
            },
            (CKM_CHACHA20, StreamCounter::Bits32(counter), 12) => Self::ChaCha20Ietf {
                counter,
                nonce: nonce.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::StreamNonceWidth,
                    ))
                })?,
            },
            (CKM_CHACHA20, StreamCounter::Bits64(counter), 24) => Self::XChaCha20 {
                counter,
                nonce: nonce.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::StreamNonceWidth,
                    ))
                })?,
            },
            (CKM_SALSA20, StreamCounter::Bits64(counter), 8) => Self::Salsa20 {
                counter,
                nonce: nonce.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::StreamNonceWidth,
                    ))
                })?,
            },
            (CKM_SALSA20, StreamCounter::Bits64(counter), 24) => Self::XSalsa20 {
                counter,
                nonce: nonce.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::StreamNonceWidth,
                    ))
                })?,
            },
            _ => {
                return Err(Error::Rejected(
                    crate::RejectionReason::SymmetricParameters(
                        crate::SymmetricParametersRejection::StreamMechanismCounterNonceTuple,
                    ),
                ))
            }
        })
    }
}
enum NativeDescriptor {
    ChaCha(Box<CK_CHACHA20_PARAMS>),
    Salsa(Box<CK_SALSA20_PARAMS>),
}
/// Retains both the descriptor and its separately allocated counter. The nonce
/// belongs to the enclosing CipherFrame, whose lifetime encloses every call.
pub(crate) struct StreamFrame {
    native: NativeDescriptor,
    counter: Buffer,
    expected_counter: StreamCounter,
    nonce_bits: u64,
}
impl crate::symmetric::memory::RetainedStorage for StreamFrame {
    fn retain_credits(&self, retained: &mut crate::symmetric::memory::RetainedBytes) -> Result<()> {
        self.counter.retain_credit(retained)
    }
}

impl StreamFrame {
    /// Bind already admitted counter storage; the nonce points into the same
    /// enclosing frame and neither allocation moves after descriptor creation.
    pub(crate) fn from_counter(
        selection: StreamCipherParameters,
        nonce: *mut u8,
        mut counter: Buffer,
    ) -> Result<Self> {
        let expected_counter = selection.counter();
        if counter.capacity() != expected_counter.bytes().len() {
            return Err(Error::Rejected(
                crate::RejectionReason::SymmetricParameters(
                    crate::SymmetricParametersRejection::StreamSnapshotCounterWidth,
                ),
            ));
        }
        counter.as_mut().copy_from_slice(expected_counter.bytes());
        let nonce_bits = (selection.nonce().len() * 8) as u64;
        let native = if selection.kind() == CKM_CHACHA20 {
            NativeDescriptor::ChaCha(Box::new(CK_CHACHA20_PARAMS {
                pBlockCounter: counter.as_mut().as_mut_ptr(),
                blockCounterBits: expected_counter.bits() as CK_ULONG,
                pNonce: nonce,
                ulNonceBits: nonce_bits as CK_ULONG,
            }))
        } else {
            NativeDescriptor::Salsa(Box::new(CK_SALSA20_PARAMS {
                pBlockCounter: counter.as_mut().as_mut_ptr(),
                pNonce: nonce,
                ulNonceBits: nonce_bits as CK_ULONG,
            }))
        };
        Ok(Self {
            native,
            counter,
            expected_counter,
            nonce_bits,
        })
    }
    pub(crate) fn kind(&self) -> CK_MECHANISM_TYPE {
        match self.native {
            NativeDescriptor::ChaCha(_) => CKM_CHACHA20,
            NativeDescriptor::Salsa(_) => CKM_SALSA20,
        }
    }
    pub(crate) fn counter(&self) -> StreamCounter {
        self.expected_counter
    }
    pub(crate) fn descriptor(&mut self) -> (*mut std::ffi::c_void, CK_ULONG) {
        match &mut self.native {
            NativeDescriptor::ChaCha(p) => (
                (&mut **p as *mut CK_CHACHA20_PARAMS).cast(),
                std::mem::size_of::<CK_CHACHA20_PARAMS>() as CK_ULONG,
            ),
            NativeDescriptor::Salsa(p) => (
                (&mut **p as *mut CK_SALSA20_PARAMS).cast(),
                std::mem::size_of::<CK_SALSA20_PARAMS>() as CK_ULONG,
            ),
        }
    }
    pub(crate) fn unchanged(&mut self, nonce: *mut u8) -> bool {
        if self.counter.as_slice() != self.expected_counter.bytes() {
            return false;
        }
        let counter_pointer = self.counter.as_mut().as_mut_ptr();
        // Packed native fields are read by value; replaced pointers are only
        // compared, never followed. The separate expected counter is immutable.
        match &self.native {
            NativeDescriptor::ChaCha(p) => {
                p.pBlockCounter == counter_pointer
                    && p.blockCounterBits as u64 == self.expected_counter.bits()
                    && p.pNonce == nonce
                    && p.ulNonceBits as u64 == self.nonce_bits
            }
            NativeDescriptor::Salsa(p) => {
                p.pBlockCounter == counter_pointer
                    && p.pNonce == nonce
                    && p.ulNonceBits as u64 == self.nonce_bits
            }
        }
    }
}
