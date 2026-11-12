// SPDX-License-Identifier: Apache-2.0
//! Synchronous requests and exactly-once release by the originating allocator.
use super::{loading::Image, VerifyEngine};
use crate::{Error, Result, SecretBytes};
use fe11_verify_engine_api as api;
use std::mem::size_of;

pub(super) fn check_status(status: u32) -> Result<()> {
    match status {
        api::status::OK => Ok(()),
        api::status::INVALID_REQUEST => {
            Err(Error::Rejected(crate::RejectionReason::VerificationEngine(
                crate::VerificationEngineRejection::VerificationEngineInvalidRequest,
            )))
        }
        api::status::UNAVAILABLE => {
            Err(Error::Rejected(crate::RejectionReason::VerificationEngine(
                crate::VerificationEngineRejection::VerificationEngineCapabilityUnavailable,
            )))
        }
        api::status::ENGINE_FAILURE => {
            Err(Error::Rejected(crate::RejectionReason::VerificationEngine(
                crate::VerificationEngineRejection::VerificationEngineOperationFailed,
            )))
        }
        api::status::ALLOCATION_FAILURE => {
            Err(Error::Rejected(crate::RejectionReason::VerificationEngine(
                crate::VerificationEngineRejection::VerificationEngineAllocationFailed,
            )))
        }
        _ => Err(Error::Rejected(crate::RejectionReason::VerificationEngine(
            crate::VerificationEngineRejection::VerificationEngineUnknownStatus,
        ))),
    }
}

/// Own the returned allocation even if later status/shape validation fails.
/// Holding the originating image also binds release to the same allocator.
struct Output<'a> {
    bytes: api::OwnedBytes,
    release: api::Release,
    _image: &'a Image,
}

impl Output<'_> {
    fn copy(&self, expected_length: usize) -> Result<SecretBytes> {
        self.check_shape(expected_length)?;
        let mut output = SecretBytes::new(expected_length)?;
        self.copy_into(output.as_mut_slice())?;
        Ok(output)
    }

    fn check_shape(&self, expected_length: usize) -> Result<()> {
        if self.bytes.owner.is_null()
            || self.bytes.bytes.length != expected_length
            || expected_length > isize::MAX as usize
            || (expected_length != 0 && self.bytes.bytes.pointer.is_null())
        {
            return Err(Error::Rejected(crate::RejectionReason::VerificationEngine(
                crate::VerificationEngineRejection::VerificationEngineOutputShape,
            )));
        }
        Ok(())
    }

    fn copy_into(&self, output: &mut [u8]) -> Result<()> {
        self.check_shape(output.len())?;
        if !output.is_empty() {
            // SAFETY: the trusted component ABI guarantees an immutable readable
            // view until release. Checked shape/size prevent null and oversized
            // slices; the owner below remains live throughout this copy.
            let bytes =
                unsafe { std::slice::from_raw_parts(self.bytes.bytes.pointer, output.len()) };
            output.copy_from_slice(bytes);
        }
        Ok(())
    }
}

impl Drop for Output<'_> {
    fn drop(&mut self) {
        if !self.bytes.owner.is_null() {
            // SAFETY: exact opaque owner returned by this component, consumed
            // only here. It is never reconstructed with the Fe11 allocator.
            unsafe { (self.release)(self.bytes.owner) };
        }
    }
}

impl VerifyEngine {
    /// The request's pointer fields must remain immutable/readable until return.
    /// Construction of those descriptors stays inside typed verifier adapters.
    pub(crate) unsafe fn probe(&self, request: &api::VerificationRequest) -> Result<()> {
        let function = self.lease.image.table.probe.ok_or(Error::Rejected(
            crate::RejectionReason::VerificationEngine(
                crate::VerificationEngineRejection::VerificationEngineProbeUnavailable,
            ),
        ))?;
        // SAFETY: inherited input contract and disjoint initialized request;
        // the image is process-pinned and this lease owns its function table.
        check_status(unsafe { function(request, size_of::<api::VerificationRequest>()) })
    }

    /// Same request contract as probe; no private native proof is issued here.
    pub(crate) unsafe fn verify(
        &self,
        request: &api::VerificationRequest,
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        let function = self.lease.image.table.verify.ok_or(Error::Rejected(
            crate::RejectionReason::VerificationEngine(
                crate::VerificationEngineRejection::VerificationEngineVerificationUnavailable,
            ),
        ))?;
        let mut verified = 0;
        // SAFETY: all data are borrowed through a synchronous call, the aligned
        // output is disjoint, and the component retains none of these pointers.
        check_status(unsafe {
            function(
                request,
                size_of::<api::VerificationRequest>(),
                api::Bytes::from_slice(message),
                api::Bytes::from_slice(signature),
                &mut verified,
            )
        })?;
        match verified {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Rejected(crate::RejectionReason::VerificationEngine(
                crate::VerificationEngineRejection::VerificationEngineVerificationResult,
            ))),
        }
    }

    pub(crate) fn digest(
        &self,
        algorithm: &[u8],
        output_length: usize,
        xof: bool,
        message: &[u8],
    ) -> Result<SecretBytes> {
        self.digest_output(algorithm, output_length, xof, message)?
            .copy(output_length)
    }

    fn digest_output(
        &self,
        algorithm: &[u8],
        output_length: usize,
        xof: bool,
        message: &[u8],
    ) -> Result<Output<'_>> {
        let image = &self.lease.image;
        let function = image.table.digest.ok_or(Error::Rejected(
            crate::RejectionReason::VerificationEngine(
                crate::VerificationEngineRejection::VerificationEngineDigestUnavailable,
            ),
        ))?;
        let release = image.table.release.ok_or(Error::Rejected(
            crate::RejectionReason::VerificationEngine(
                crate::VerificationEngineRejection::VerificationEngineReleaseUnavailable,
            ),
        ))?;
        let request = api::DigestRequest {
            algorithm: api::Bytes::from_slice(algorithm),
            output_length,
            xof: u32::from(xof),
            message: api::Bytes::from_slice(message),
        };
        let mut output = Output {
            bytes: api::OwnedBytes::EMPTY,
            release,
            _image: image,
        };
        // SAFETY: exact request with live immutable slices; the return owner is
        // guarded before status interpretation or allocation of the Fe11 copy.
        check_status(unsafe {
            function(&request, size_of::<api::DigestRequest>(), &mut output.bytes)
        })?;
        Ok(output)
    }
}
