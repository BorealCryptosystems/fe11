// SPDX-License-Identifier: Apache-2.0
//! Owned allocation erasure for the exact inline SHA2/SHA3 implementations.
use super::HashAlgorithm;

use crate::{Result, SecretBytes};
use sha2::{
    digest::{FixedOutputReset, Output},
    Digest,
};
use std::{
    mem::{size_of, MaybeUninit},
    sync::atomic::{compiler_fence, Ordering},
};

// Private: never use this owner for a type with secret-bearing suballocations.
// SHA2 0.10.9 / SHA3 0.10.9 CoreWrapper, core, block buffer and output size are inline.
struct OwnedState<T>(Box<MaybeUninit<T>>);
impl<T> OwnedState<T> {
    fn new(value: T) -> Self {
        Self(Box::new(MaybeUninit::new(value)))
    }
    fn get(&mut self) -> &mut T {
        // SAFETY: constructed initialized, never accessed after Drop begins.
        unsafe { self.0.assume_init_mut() }
    }
}
struct Wipe {
    address: *mut u8,
    length: usize,
}
impl Drop for Wipe {
    fn drop(&mut self) {
        for offset in 0..self.length {
            // SAFETY: allocation remains live through this guard; raw writes also
            // initialize padding without constructing references to uninitialized bytes.
            unsafe { self.address.add(offset).write_volatile(0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}
impl<T> Drop for OwnedState<T> {
    fn drop(&mut self) {
        let _wipe = Wipe {
            address: self.0.as_mut_ptr().cast(),
            length: size_of::<T>(),
        };
        // SAFETY: initialized T, destroyed exactly once. Wipe runs even if T's
        // destructor unwinds, before Box<MaybeUninit<T>> deallocates. No T is
        // accessed/dropped after erasure. Internal compiler/provider copies are not covered.
        unsafe { std::ptr::drop_in_place(self.0.as_mut_ptr()) };
    }
}

pub(super) fn hash_owned(algorithm: HashAlgorithm, parts: &[&[u8]]) -> Result<SecretBytes> {
    fn run<D: Digest + FixedOutputReset>(parts: &[&[u8]]) -> Result<SecretBytes> {
        let mut state = OwnedState::new(D::new());
        for part in parts {
            Digest::update(state.get(), part);
        }
        let mut output = OwnedState::new(Output::<D>::default());
        FixedOutputReset::finalize_into_reset(state.get(), output.get());
        let mut bytes = SecretBytes::new(output.get().len())?;
        bytes.as_mut_slice().copy_from_slice(output.get());
        Ok(bytes)
    }
    let bytes = match algorithm {
        HashAlgorithm::Sha224 => run::<sha2::Sha224>(parts)?,
        HashAlgorithm::Sha256 => run::<sha2::Sha256>(parts)?,
        HashAlgorithm::Sha384 => run::<sha2::Sha384>(parts)?,
        HashAlgorithm::Sha512 => run::<sha2::Sha512>(parts)?,
        HashAlgorithm::Sha3_224 => run::<sha3::Sha3_224>(parts)?,
        HashAlgorithm::Sha3_256 => run::<sha3::Sha3_256>(parts)?,
        HashAlgorithm::Sha3_384 => run::<sha3::Sha3_384>(parts)?,
        HashAlgorithm::Sha3_512 => run::<sha3::Sha3_512>(parts)?,
    };
    Ok(bytes)
}

/// Exact owned heap state used by `hash`, excluding its result. Hash states and
/// digest arrays are inline in the pinned dependency versions documented above.
pub(super) fn working_bytes(algorithm: HashAlgorithm) -> usize {
    fn bytes<D: Digest>() -> usize {
        size_of::<D>() + size_of::<Output<D>>()
    }
    match algorithm {
        HashAlgorithm::Sha224 => bytes::<sha2::Sha224>(),
        HashAlgorithm::Sha256 => bytes::<sha2::Sha256>(),
        HashAlgorithm::Sha384 => bytes::<sha2::Sha384>(),
        HashAlgorithm::Sha512 => bytes::<sha2::Sha512>(),
        HashAlgorithm::Sha3_224 => bytes::<sha3::Sha3_224>(),
        HashAlgorithm::Sha3_256 => bytes::<sha3::Sha3_256>(),
        HashAlgorithm::Sha3_384 => bytes::<sha3::Sha3_384>(),
        HashAlgorithm::Sha3_512 => bytes::<sha3::Sha3_512>(),
    }
}
