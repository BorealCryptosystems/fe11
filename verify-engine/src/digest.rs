// SPDX-License-Identifier: Apache-2.0
//! Whole-message hashing in the explicitly selected private provider.
use crate::{boundary, context::PROPERTIES, native, Context, Failure, Result};
use fe11_verify_engine_api::DigestRequest;
use std::ptr;

struct Method<'a> {
    raw: *mut native::EVP_MD,
    _context: &'a Context,
}

impl Drop for Method<'_> {
    fn drop(&mut self) {
        // SAFETY: unique fetched method reference, freed before its context.
        unsafe { native::EVP_MD_free(self.raw) };
    }
}

struct Operation<'a> {
    raw: *mut native::EVP_MD_CTX,
    _method: &'a Method<'a>,
}

impl Drop for Operation<'_> {
    fn drop(&mut self) {
        // SAFETY: the operation owns this context and outlives every update call.
        unsafe { native::EVP_MD_CTX_free(self.raw) };
    }
}

/// Input pointers obey the synchronous component ABI contract.
pub(crate) unsafe fn calculate(request: &DigestRequest) -> Result<boundary::Buffer> {
    // SAFETY: these views remain within the caller's synchronous invocation.
    let (name, message) = unsafe {
        (
            boundary::name(request.algorithm)?,
            boundary::bytes(request.message)?,
        )
    };
    let xof = match request.xof {
        0 => false,
        1 => true,
        _ => return Err(Failure::InvalidRequest),
    };
    let context = Context::new()?;
    // SAFETY: explicit live context and terminated names. The provider is private.
    let method = Method {
        raw: unsafe {
            native::EVP_MD_fetch(context.raw(), name.as_ptr(), PROPERTIES.as_ptr().cast())
        },
        _context: &context,
    };
    if method.raw.is_null() {
        return Err(Failure::Unavailable);
    }
    // SAFETY: fetched method remains alive for all metadata reads.
    if unsafe { native::EVP_MD_xof(method.raw) != 0 } != xof {
        return Err(Failure::InvalidRequest);
    }
    if !xof {
        let width = unsafe { native::EVP_MD_get_size(method.raw) };
        if width <= 0 || usize::try_from(width).ok() != Some(request.output_length) {
            return Err(Failure::InvalidRequest);
        }
    }
    // This is an ABI allocation bound, not a cryptographic policy or a hidden
    // digest-size quota. XOF length is selected by the caller.
    if request.output_length > isize::MAX as usize {
        return Err(Failure::InvalidRequest);
    }
    let operation = Operation {
        raw: unsafe { native::EVP_MD_CTX_new() },
        _method: &method,
    };
    if operation.raw.is_null() {
        return Err(Failure::Allocation);
    }
    // SAFETY: local owners keep the method, context and message alive; no ENGINE
    // or application default context participates in this operation.
    if unsafe { native::EVP_DigestInit_ex(operation.raw, method.raw, ptr::null_mut()) } != 1
        || unsafe {
            native::EVP_DigestUpdate(operation.raw, message.as_ptr().cast(), message.len())
        } != 1
    {
        return Err(Failure::Engine);
    }
    let mut output = boundary::Buffer::new(request.output_length)?;
    if xof {
        // SAFETY: owned output is writable for the exact selected XOF length.
        if unsafe {
            native::EVP_DigestFinalXOF(
                operation.raw,
                output.as_mut_slice().as_mut_ptr(),
                request.output_length,
            )
        } != 1
        {
            return Err(Failure::Engine);
        }
    } else {
        let mut length = 0;
        // SAFETY: allocation equals the fixed width reported by the fetched
        // method; length is a separate aligned output slot.
        if unsafe {
            native::EVP_DigestFinal_ex(
                operation.raw,
                output.as_mut_slice().as_mut_ptr(),
                &mut length,
            )
        } != 1
            || usize::try_from(length).ok() != Some(request.output_length)
        {
            return Err(Failure::Engine);
        }
    }
    Ok(output)
}
