// SPDX-License-Identifier: Apache-2.0
//! Optional Fe11 verification engine. The C ABI exposes whole synchronous requests;
//! no OpenSSL object, Rust collection or allocator contract escapes this image.
//!
//! The loader must pin the image before using the returned table. OpenSSL is
//! private to this component; its exports and local bindings must be inspected
//! in the final distribution. Source-level context isolation alone is insufficient.
#![deny(unsafe_op_in_unsafe_fn)]

mod algorithms;
mod boundary;
mod context;
mod digest;
mod native;
mod verification;

use context::Context;
use fe11_verify_engine_api as api;
use std::{ffi::c_void, mem::size_of, panic::catch_unwind};

#[derive(Clone, Copy)]
enum Failure {
    InvalidRequest,
    Unavailable,
    Engine,
    Allocation,
}

type Result<T> = std::result::Result<T, Failure>;

impl Failure {
    fn status(self) -> u32 {
        match self {
            Self::InvalidRequest => api::status::INVALID_REQUEST,
            Self::Unavailable => api::status::UNAVAILABLE,
            Self::Engine => api::status::ENGINE_FAILURE,
            Self::Allocation => api::status::ALLOCATION_FAILURE,
        }
    }
}

/// Keep unwinding inside this Rust runtime. Allocation aborts and native faults
/// are not recoverable status codes; no promise of process isolation is made.
fn dispatch(action: impl FnOnce() -> Result<()> + std::panic::UnwindSafe) -> u32 {
    match catch_unwind(action) {
        Ok(Ok(())) => api::status::OK,
        Ok(Err(failure)) => failure.status(),
        Err(_) => api::status::ENGINE_FAILURE,
    }
}

unsafe extern "C" fn information(output: *mut api::Information, size: usize) -> u32 {
    if size != size_of::<api::Information>() || !boundary::output_is_aligned(output) {
        return api::status::INVALID_REQUEST;
    }
    // SAFETY: caller provides disjoint writable storage of this checked shape.
    unsafe { output.write(std::mem::zeroed()) };
    dispatch(|| {
        let _context = Context::new()?;
        let value = api::Information {
            abi_version: api::ABI_VERSION,
            structure_size: size_of::<api::Information>() as u32,
            // Cargo supplies the inherited package version. Check the ABI's
            // u32 components instead of truncating or duplicating the manifest.
            implementation_version: [
                env!("CARGO_PKG_VERSION_MAJOR")
                    .parse()
                    .map_err(|_| Failure::Engine)?,
                env!("CARGO_PKG_VERSION_MINOR")
                    .parse()
                    .map_err(|_| Failure::Engine)?,
                env!("CARGO_PKG_VERSION_PATCH")
                    .parse()
                    .map_err(|_| Failure::Engine)?,
            ],
            // SAFETY: the private library was initialized by Context::new.
            openssl_version: unsafe { native::OpenSSL_version_num() } as u64,
        };
        unsafe { output.write(value) };
        Ok(())
    })
}

unsafe extern "C" fn verification_algorithms(
    request: *const api::VerificationAlgorithms,
    size: usize,
) -> u32 {
    dispatch(|| {
        // SAFETY: the caller owns readable descriptors for this synchronous call.
        let request = unsafe { boundary::request(request, size) }?;
        unsafe { algorithms::check(request) }
    })
}

unsafe extern "C" fn probe(request: *const api::VerificationRequest, size: usize) -> u32 {
    dispatch(|| {
        // SAFETY: validated ABI shape, caller's synchronous readable allocation.
        let request = unsafe { boundary::request(request, size) }?;
        unsafe { verification::run(request, None) }?;
        Ok(())
    })
}

unsafe extern "C" fn verify(
    request: *const api::VerificationRequest,
    size: usize,
    message: api::Bytes,
    signature: api::Bytes,
    output: *mut u32,
) -> u32 {
    if !boundary::output_is_aligned(output) {
        return api::status::INVALID_REQUEST;
    }
    // SAFETY: caller provides a writable aligned slot disjoint from all inputs.
    unsafe { output.write(0) };
    dispatch(|| {
        let (request, message, signature) = unsafe {
            (
                boundary::request(request, size)?,
                boundary::bytes(message)?,
                boundary::bytes(signature)?,
            )
        };
        let verified = unsafe { verification::run(request, Some((message, signature))) }?;
        unsafe { output.write(u32::from(verified)) };
        Ok(())
    })
}

unsafe extern "C" fn digest(
    request: *const api::DigestRequest,
    size: usize,
    output: *mut api::OwnedBytes,
) -> u32 {
    if !boundary::output_is_aligned(output) {
        return api::status::INVALID_REQUEST;
    }
    unsafe { output.write(api::OwnedBytes::EMPTY) };
    dispatch(|| {
        let request = unsafe { boundary::request(request, size) }?;
        let bytes = unsafe { digest::calculate(request) }?;
        // Publish only after every fallible native operation has completed.
        unsafe { output.write(bytes.publish()) };
        Ok(())
    })
}

unsafe extern "C" fn release(owner: *mut c_void) {
    // SAFETY: exact owner returned by this image, surrendered once by the caller.
    // Buffer destruction only wipes/frees its allocation and cannot unwind.
    unsafe { boundary::release(owner) };
}

/// Obtain this component's exact ABI table without initializing OpenSSL.
///
/// # Safety
/// `output` must denote aligned, writable storage for `Interface`. The caller
/// pins this image before invoking the table and obeys every function's pointer
/// and ownership contract in fe11-verify-engine-api. Unknown ABI versions and
/// sizes are rejected without accessing the proposed output storage.
#[export_name = "Fe11_VerifyEngine_GetInterface"]
pub unsafe extern "C" fn get_interface(
    version: u32,
    output: *mut api::Interface,
    size: usize,
) -> u32 {
    if version != api::ABI_VERSION
        || size != size_of::<api::Interface>()
        || !boundary::output_is_aligned(output)
    {
        return api::status::INVALID_REQUEST;
    }
    let interface = api::Interface {
        structure_size: size_of::<api::Interface>() as u32,
        abi_version: api::ABI_VERSION,
        information: Some(information),
        probe: Some(probe),
        verification_algorithms: Some(verification_algorithms),
        verify: Some(verify),
        digest: Some(digest),
        release: Some(release),
    };
    // SAFETY: checked shape; the caller guarantees the writable allocation.
    unsafe { output.write(interface) };
    api::status::OK
}
