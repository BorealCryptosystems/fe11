// SPDX-License-Identifier: Apache-2.0
//! C ABI for the optional Fe11 verification engine, independent of PKCS#11 tables.
//!
//! All requests are synchronous: no input pointer is retained after return. The caller
//! pins the component image before invoking anything other than GetInterface.
//! Inputs stay initialized, immutable and readable for their full lengths until
//! return; output slots are aligned, exclusively writable and disjoint from inputs.
//! Integer representations accept all bit patterns and
//! are validated by the callee. The calling thread must not reenter this engine
//! during a request. Calls from different threads are independent. No Rust
//! allocation crosses the ownership boundary: an owned byte view is released by
//! the originating component. The caller never reconstructs or frees that owner.
#![no_std]
use core::ffi::c_void;

// This table exposes public verification services. Version and exact table
// size are checked before either side consumes any service fields.
/// Version of the public component ABI.
pub const ABI_VERSION: u32 = 2;
/// NUL-terminated exported discovery symbol.
pub const ENTRY_POINT: &[u8] = b"Fe11_VerifyEngine_GetInterface\0";

/// Service completion and failure codes.
pub mod status {
    /// The service completed; a verification verdict is reported separately.
    pub const OK: u32 = 0;
    /// The request representation or parameter combination was refused.
    pub const INVALID_REQUEST: u32 = 1;
    /// A required implementation or exact preparation is unavailable.
    pub const UNAVAILABLE: u32 = 2;
    /// The engine failed while executing the request.
    pub const ENGINE_FAILURE: u32 = 3;
    /// A required allocation failed.
    pub const ALLOCATION_FAILURE: u32 = 4;
}
/// Public-key representation codes.
pub mod key_format {
    /// Complete DER-encoded SubjectPublicKeyInfo.
    pub const SPKI_DER: u32 = 1;
    /// Algorithm-specific raw public-key bytes.
    pub const RAW_PUBLIC: u32 = 2;
}
/// Signature verification scheme codes.
pub mod scheme {
    /// RSA PKCS#1 v1.5 signature verification with an explicit digest.
    pub const RSA_PKCS1: u32 = 1;
    /// RSA-PSS verification with explicit digest, MGF1 digest and salt length.
    pub const RSA_PSS: u32 = 2;
    /// Digest-based signature scheme; the supplied engine accepts EC public keys.
    pub const DIGEST_SIGNATURE: u32 = 3;
    /// Pure Ed25519 or Ed448 verification.
    pub const PURE_EDDSA: u32 = 4;
    /// ML-DSA or SLH-DSA verification with explicit message framing.
    pub const PQC: u32 = 5;
    /// Explicit RFC8032 instance, context and original-message input.
    pub const EDDSA: u32 = 6;
}
/// Instance codes for scheme::EDDSA in VerificationRequest::message_encoding.
/// The ABI layout is unchanged; older engines may reject the added scheme.
pub mod eddsa_instance {
    /// Pure Ed25519 with an empty context.
    pub const ED25519: u32 = 1;
    /// Ed25519ctx with the supplied context.
    pub const ED25519_CONTEXT: u32 = 2;
    /// Ed25519ph with original-message input and the supplied context.
    pub const ED25519_PREHASH: u32 = 3;
    /// Ed448 with the supplied context.
    pub const ED448: u32 = 4;
    /// Ed448ph with original-message input and the supplied context.
    pub const ED448_PREHASH: u32 = 5;
}
/// Borrowed bytes; null is accepted only with a zero length. Identifier fields
/// contain UTF-8 names without NUL; ordinary data fields are unrestricted bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Bytes {
    /// Start of readable input storage; NULL is valid only when length is zero.
    pub pointer: *const u8,
    /// Number of readable bytes starting at pointer.
    pub length: usize,
}
impl Bytes {
    /// Empty descriptor with a null pointer and zero length.
    pub const EMPTY: Self = Self {
        pointer: core::ptr::null(),
        length: 0,
    };
    /// Borrow a slice as a descriptor; the caller preserves its storage through use.
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self {
            pointer: bytes.as_ptr(),
            length: bytes.len(),
        }
    }
}
/// Engine-owned allocation. Only release(owner), exactly once, may destroy it.
/// The view stays readable until release. None of these fields may be modified
/// to construct a different allocation; even a zero-length owned view is released.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OwnedBytes {
    /// Opaque allocation token returned by the engine; release once through that engine.
    pub owner: *mut c_void,
    /// Readable result view whose lifetime ends when owner is released.
    pub bytes: Bytes,
}
impl OwnedBytes {
    /// Empty descriptor with a null pointer or owner and zero length.
    pub const EMPTY: Self = Self {
        owner: core::ptr::null_mut(),
        bytes: Bytes::EMPTY,
    };
}
/// Versions reported by the selected component and its private crypto library.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Information {
    /// Component ABI version; compare with ABI_VERSION.
    pub abi_version: u32,
    /// Size in bytes of this Information representation.
    pub structure_size: u32,
    /// Component package version as major, minor and patch numbers.
    pub implementation_version: [u32; 3],
    /// Numeric version of the component's private OpenSSL library.
    pub openssl_version: u64,
}
/// Implementations required for a future verification, without a key. Names are
/// UTF-8 without NUL; digest names may be empty when not needed. Success reports
/// that each implementation can be fetched in the engine's private context. It
/// does not establish that their combination or a future key can be initialized;
/// explicit public-key verification uses the exact-key Probe to establish its
/// own operation requirements. No private possession-proof policy is provided.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VerificationAlgorithms {
    /// UTF-8 key-management algorithm name without NUL bytes.
    pub key_algorithm: Bytes,
    /// UTF-8 signature implementation name without NUL bytes.
    pub signature_algorithm: Bytes,
    /// UTF-8 digest name, or empty when the requested scheme uses none.
    pub digest: Bytes,
    /// UTF-8 MGF digest name, or empty when the requested scheme uses none.
    pub mgf_digest: Bytes,
}
/// Exact public verification parameters. Empty digest names mean no digest;
/// unused fields must be zero/empty. PQC encoding is 1 for engine framing and
/// 0 when Fe11 already supplied its exact FIPS frame. Context is not applied twice.
/// For scheme::EDDSA, message_encoding is an eddsa_instance code, digest/MGF
/// names and salt must be empty/zero, and input is the original message.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VerificationRequest {
    /// UTF-8 public-key algorithm name without NUL bytes.
    pub algorithm: Bytes,
    /// Public-key representation selected from key_format.
    pub key_format: u32,
    /// Complete public-key encoding in the selected format, borrowed through the call.
    pub key: Bytes,
    /// Signature operation selected from scheme.
    pub scheme: u32,
    /// Explicit message-digest name; empty for a scheme without a separate digest.
    pub digest: Bytes,
    /// RSA-PSS MGF1 digest name; empty for other schemes.
    pub mgf_digest: Bytes,
    /// Exact RSA-PSS salt length in bytes; zero for other schemes.
    pub salt_length: u64,
    /// EdDSA or PQC domain-separation context; empty when unused.
    pub context: Bytes,
    /// For EDDSA, an eddsa_instance code; for PQC, 1 for engine framing or 0 for an already framed message; zero otherwise.
    pub message_encoding: u32,
}
/// Parameters for a synchronous whole-message digest request.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DigestRequest {
    /// UTF-8 digest implementation name without NUL bytes.
    pub algorithm: Bytes,
    /// Requested digest length in bytes; exact method width for a fixed-size hash.
    pub output_length: usize,
    /// Zero selects a fixed-size hash; one selects extendable output.
    pub xof: u32,
    /// Complete input message borrowed through this synchronous request.
    pub message: Bytes,
}
/// Read component/engine versions into the caller's exact-sized output slot.
/// This may initialize the private engine; the image must already be pinned.
pub type ReadInformation =
    unsafe extern "C" fn(output: *mut Information, output_size: usize) -> u32;

/// Import the public key and prepare the exact parameters without verification.
/// OK establishes preparation availability, not validity of a future signature.
pub type Probe =
    unsafe extern "C" fn(request: *const VerificationRequest, request_size: usize) -> u32;

/// Check implementation availability without generating/importing a key or
/// performing a PKCS#11 operation. See VerificationAlgorithms for the limited
/// meaning of success; missing implementations return UNAVAILABLE.
pub type CheckVerificationAlgorithms =
    unsafe extern "C" fn(request: *const VerificationAlgorithms, request_size: usize) -> u32;

/// Verify one message/signature pair. OK with verified=0 is a signature mismatch;
/// engine/parameter failures have a non-OK status and never claim a mismatch.
pub type Verify = unsafe extern "C" fn(
    request: *const VerificationRequest,
    request_size: usize,
    message: Bytes,
    signature: Bytes,
    verified: *mut u32,
) -> u32;

/// Hash one whole message. On success the caller copies the result then releases
/// its owner; no output allocation belongs to the caller's allocator.
pub type Digest = unsafe extern "C" fn(
    request: *const DigestRequest,
    request_size: usize,
    output: *mut OwnedBytes,
) -> u32;

/// Consume an unmodified owner returned by this image, exactly once. Null is a
/// no-op. Every borrowed view of the allocation becomes invalid after this call.
pub type Release = unsafe extern "C" fn(owner: *mut c_void);

/// Function pointers use the C calling convention on every supported target.
/// Every request receives its structure size; mismatched sizes are refused before
/// dereferencing fields. Valid output slots are empty/zero on non-OK return;
/// invalid output size/alignment is rejected without accessing that storage. Probe
/// prepares the exact operation without signing or issuing any PKCS#11 call.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Interface {
    /// Size in bytes of this exact Interface representation.
    pub structure_size: u32,
    /// Version governing the layout and service contracts.
    pub abi_version: u32,
    /// Optional version-information service; Fe11 requires it when selecting an engine.
    pub information: Option<ReadInformation>,
    /// Optional exact-key verification preparation service.
    pub probe: Option<Probe>,
    /// Optional keyless implementation-availability service.
    pub verification_algorithms: Option<CheckVerificationAlgorithms>,
    /// Optional message/signature verification service; requires the preparation service.
    pub verify: Option<Verify>,
    /// Optional whole-message hashing service; returned allocations require release.
    pub digest: Option<Digest>,
    /// Optional originating-allocator release service for OwnedBytes results.
    pub release: Option<Release>,
}
/// GetInterface performs no OpenSSL initialization. A successful call copies the
/// exact requested ABI table into the caller's storage; it never returns a table
/// pointer with an inferred suffix length. Version/size mismatch writes nothing.
pub type GetInterface =
    unsafe extern "C" fn(requested_version: u32, output: *mut Interface, output_size: usize) -> u32;
