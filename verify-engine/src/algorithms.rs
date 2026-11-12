// SPDX-License-Identifier: Apache-2.0
//! Keyless availability checks. Fetching methods cannot validate a future key.
use crate::{boundary, context::PROPERTIES, native, Context, Failure, Result};
use fe11_verify_engine_api::VerificationAlgorithms;
use std::ptr;

/// Even a partially fulfilled request releases its methods before its context.
struct Methods<'a> {
    _context: &'a Context,
    key: *mut native::KeyManagement,
    signature: *mut native::SignatureMethod,
    digest: *mut native::EVP_MD,
    mgf_digest: *mut native::EVP_MD,
}

impl Drop for Methods<'_> {
    fn drop(&mut self) {
        // SAFETY: each successful fetch supplied one owned reference; these
        // destructors accept null. The borrowed private context remains alive.
        unsafe {
            native::EVP_MD_free(self.mgf_digest);
            native::EVP_MD_free(self.digest);
            native::EVP_SIGNATURE_free(self.signature);
            native::EVP_KEYMGMT_free(self.key);
        }
    }
}

pub(crate) unsafe fn check(request: &VerificationAlgorithms) -> Result<()> {
    // SAFETY: descriptor storage is immutable and readable throughout the call.
    let key = unsafe { boundary::name(request.key_algorithm) }?;
    let signature = unsafe { boundary::name(request.signature_algorithm) }?;
    let mut digests = [None, None];
    for (slot, name) in digests.iter_mut().zip([request.digest, request.mgf_digest]) {
        if name.length != 0 {
            *slot = Some(unsafe { boundary::name(name) }?);
        }
    }
    let context = Context::new()?;
    let mut methods = Methods {
        _context: &context,
        key: ptr::null_mut(),
        signature: ptr::null_mut(),
        digest: ptr::null_mut(),
        mgf_digest: ptr::null_mut(),
    };
    // SAFETY: terminated names, a live private context and a fixed property query.
    // No default application context, key allocation or operation is requested.
    methods.key = unsafe {
        native::EVP_KEYMGMT_fetch(context.raw(), key.as_ptr(), PROPERTIES.as_ptr().cast())
    };
    if methods.key.is_null() {
        return Err(Failure::Unavailable);
    }
    methods.signature = unsafe {
        native::EVP_SIGNATURE_fetch(
            context.raw(),
            signature.as_ptr(),
            PROPERTIES.as_ptr().cast(),
        )
    };
    if methods.signature.is_null() {
        return Err(Failure::Unavailable);
    }
    for (slot, name) in [&mut methods.digest, &mut methods.mgf_digest]
        .into_iter()
        .zip(&digests)
    {
        if let Some(name) = name {
            *slot = unsafe {
                native::EVP_MD_fetch(context.raw(), name.as_ptr(), PROPERTIES.as_ptr().cast())
            };
            if slot.is_null() {
                return Err(Failure::Unavailable);
            }
        }
    }
    Ok(())
}
