// SPDX-License-Identifier: Apache-2.0
//! Checked ABI representations and component-owned output storage.
use crate::{Failure, Result};
use fe11_verify_engine_api::{Bytes, OwnedBytes};
use std::{ffi::CString, slice};
use zeroize::Zeroize;

/// The caller supplies the readable allocation; shape checks alone cannot prove
/// that an arbitrary native pointer denotes mapped or initialized storage.
pub(crate) unsafe fn bytes<'a>(input: Bytes) -> Result<&'a [u8]> {
    if input.length > isize::MAX as usize {
        return Err(Failure::InvalidRequest);
    }
    if input.length == 0 {
        return Ok(&[]);
    }
    if input.pointer.is_null() {
        return Err(Failure::InvalidRequest);
    }
    // SAFETY: the synchronous ABI caller guarantees this readable allocation
    // and its lifetime. Null and Rust slice size constraints were checked above.
    Ok(unsafe { slice::from_raw_parts(input.pointer, input.length) })
}

pub(crate) unsafe fn name(input: Bytes) -> Result<CString> {
    // SAFETY: inherited from this function's ABI input contract.
    let input = unsafe { bytes(input) }?;
    if input.is_empty() || input.contains(&0) || std::str::from_utf8(input).is_err() {
        return Err(Failure::InvalidRequest);
    }
    let length = input.len().checked_add(1).ok_or(Failure::InvalidRequest)?;
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(length)
        .map_err(|_| Failure::Allocation)?;
    owned.extend_from_slice(input);
    owned.push(0);
    // The only NUL was appended above. This conversion reuses the allocation.
    CString::from_vec_with_nul(owned).map_err(|_| Failure::InvalidRequest)
}

/// Initializes the full allocation so Drop can wipe capacity, including bytes
/// outside the published view. This owner never copies its buffer implicitly.
pub(crate) struct Buffer {
    storage: Vec<u8>,
    length: usize,
}

impl Buffer {
    pub(crate) fn new(length: usize) -> Result<Self> {
        let mut storage = Vec::new();
        storage
            .try_reserve_exact(length)
            .map_err(|_| Failure::Allocation)?;
        storage.resize(storage.capacity(), 0);
        Ok(Self { storage, length })
    }

    pub(crate) fn copy_from(input: &[u8]) -> Result<Self> {
        let mut buffer = Self::new(input.len())?;
        buffer.as_mut_slice().copy_from_slice(input);
        Ok(buffer)
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.storage[..self.length]
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.storage[..self.length]
    }

    pub(crate) fn publish(self) -> OwnedBytes {
        let bytes = Bytes::from_slice(self.as_slice());
        OwnedBytes {
            owner: Box::into_raw(Box::new(self)).cast(),
            bytes,
        }
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        self.storage.as_mut_slice().zeroize();
    }
}

/// Reads a structure only after checking its exact ABI size and alignment.
/// Mapping, initialization and validity for a shared borrow remain caller duties.
pub(crate) unsafe fn request<'a, T>(pointer: *const T, size: usize) -> Result<&'a T> {
    if size != std::mem::size_of::<T>()
        || pointer.is_null()
        || pointer as usize % std::mem::align_of::<T>() != 0
    {
        return Err(Failure::InvalidRequest);
    }
    // SAFETY: caller guarantees a live initialized object, checked representation
    // size/alignment; the reference cannot escape a synchronous engine operation.
    Ok(unsafe { &*pointer })
}

pub(crate) fn output_is_aligned<T>(pointer: *mut T) -> bool {
    !pointer.is_null() && pointer as usize % std::mem::align_of::<T>() == 0
}

pub(crate) unsafe fn release(owner: *mut std::ffi::c_void) {
    if !owner.is_null() {
        // SAFETY: caller returns exactly once the unmodified owner produced by
        // Buffer::publish. The allocation is freed by the same component runtime.
        drop(unsafe { Box::from_raw(owner.cast::<Buffer>()) });
    }
}
