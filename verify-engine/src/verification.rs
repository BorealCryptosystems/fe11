// SPDX-License-Identifier: Apache-2.0
//! Public verification and a preparation probe with identical parameters.
use crate::{boundary, context::PROPERTIES, native, Context, Failure, Result};
use fe11_verify_engine_api::{key_format, scheme, VerificationRequest};
use std::{ffi::CString, marker::PhantomData, ptr};

struct Key<'a> {
    raw: *mut native::EVP_PKEY,
    context: &'a Context,
}

impl Drop for Key<'_> {
    fn drop(&mut self) {
        // SAFETY: unique imported key, with its context still borrowed.
        unsafe { native::EVP_PKEY_free(self.raw) };
    }
}

struct Digest<'a> {
    raw: *mut native::EVP_MD_CTX,
    _key: PhantomData<&'a native::EVP_PKEY>,
}

impl Drop for Digest<'_> {
    fn drop(&mut self) {
        // SAFETY: this owner alone frees the verification operation.
        unsafe { native::EVP_MD_CTX_free(self.raw) };
    }
}

/// Mutually exclusive parameter sets prevent accidental reuse of PSS or PQC
/// settings for another family. The API carries integers, this module does not.
enum Parameters {
    RsaPkcs1 {
        digest: CString,
    },
    RsaPss {
        digest: CString,
        mgf_digest: CString,
        salt: i32,
    },
    DigestSignature {
        digest: CString,
    },
    PureEdDsa,
    EdDsa {
        instance: &'static [u8],
        family: &'static [u8],
        context: boundary::Buffer,
    },
    Pqc {
        context: boundary::Buffer,
        encoding: i32,
    },
}

impl Parameters {
    unsafe fn read(request: &VerificationRequest) -> Result<Self> {
        // SAFETY: input descriptors are borrowed only during this ABI call.
        let context = unsafe { boundary::bytes(request.context) }?;
        let unused_context = context.is_empty() && request.message_encoding == 0;
        let unused_pss = request.mgf_digest.length == 0 && request.salt_length == 0;
        match request.scheme {
            scheme::RSA_PKCS1 if unused_context && unused_pss => Ok(Self::RsaPkcs1 {
                digest: unsafe { boundary::name(request.digest) }?,
            }),
            scheme::RSA_PSS if unused_context => Ok(Self::RsaPss {
                digest: unsafe { boundary::name(request.digest) }?,
                mgf_digest: unsafe { boundary::name(request.mgf_digest) }?,
                // Negative OpenSSL sentinel salts are never inferred from the
                // caller's exact nonnegative PKCS#11 salt length.
                salt: request
                    .salt_length
                    .try_into()
                    .map_err(|_| Failure::InvalidRequest)?,
            }),
            scheme::DIGEST_SIGNATURE if unused_context && unused_pss => Ok(Self::DigestSignature {
                digest: unsafe { boundary::name(request.digest) }?,
            }),
            scheme::PURE_EDDSA if unused_context && unused_pss && request.digest.length == 0 => {
                Ok(Self::PureEdDsa)
            }
            scheme::EDDSA if unused_pss && request.digest.length == 0 => {
                use fe11_verify_engine_api::eddsa_instance as I;
                if context.len() > 255 {
                    return Err(Failure::InvalidRequest);
                }
                let (instance, family): (&'static [u8], &'static [u8]) =
                    match request.message_encoding {
                        I::ED25519 if context.is_empty() => (b"Ed25519\0", b"ED25519\0"),
                        I::ED25519_CONTEXT => (b"Ed25519ctx\0", b"ED25519\0"),
                        I::ED25519_PREHASH => (b"Ed25519ph\0", b"ED25519\0"),
                        I::ED448 => (b"Ed448\0", b"ED448\0"),
                        I::ED448_PREHASH => (b"Ed448ph\0", b"ED448\0"),
                        _ => return Err(Failure::InvalidRequest),
                    };
                // OpenSSL 3.5.9 curve25519.c rejects csflag with an empty
                // context at verification time. Report that engine limitation
                // during the probe, not a false cryptographic mismatch later.
                // Core PKCS#11 Ed25519ctx still accepts the normative empty form.
                if request.message_encoding == I::ED25519_CONTEXT && context.is_empty() {
                    return Err(Failure::Unavailable);
                }
                Ok(Self::EdDsa {
                    instance,
                    family,
                    context: boundary::Buffer::copy_from(context)?,
                })
            }
            scheme::PQC if unused_pss && request.digest.length == 0 => {
                // FIPS 204/205 context length is encoded in one octet. A framed
                // message must not receive a second context at this boundary.
                if context.len() > 255
                    || request.message_encoding > 1
                    || (request.message_encoding == 0 && !context.is_empty())
                {
                    return Err(Failure::InvalidRequest);
                }
                Ok(Self::Pqc {
                    context: boundary::Buffer::copy_from(context)?,
                    encoding: request.message_encoding as i32,
                })
            }
            _ => Err(Failure::InvalidRequest),
        }
    }

    fn digest(&self) -> *const std::ffi::c_char {
        match self {
            Self::RsaPkcs1 { digest }
            | Self::RsaPss { digest, .. }
            | Self::DigestSignature { digest } => digest.as_ptr(),
            Self::PureEdDsa | Self::EdDsa { .. } | Self::Pqc { .. } => ptr::null(),
        }
    }
}

/// Import only public material. Core Fe11 additionally validates the exact
/// canonical SPKI and expected key identity before constructing the request.
unsafe fn import<'a>(context: &'a Context, request: &VerificationRequest) -> Result<Key<'a>> {
    let algorithm = unsafe { boundary::name(request.algorithm) }?;
    if request.scheme == scheme::PQC
        && !algorithm.as_bytes().starts_with(b"ML-DSA-")
        && !algorithm.as_bytes().starts_with(b"SLH-DSA-")
    {
        // Other key families may ignore PQC-only initialization parameters.
        // Refuse that mismatch instead of reporting a successful exact probe.
        return Err(Failure::InvalidRequest);
    }
    let input = unsafe { boundary::bytes(request.key) }?;
    if input.is_empty() {
        return Err(Failure::InvalidRequest);
    }
    let mut key = Key {
        raw: ptr::null_mut(),
        context,
    };
    match request.key_format {
        key_format::SPKI_DER => {
            let length = input
                .len()
                .try_into()
                .map_err(|_| Failure::InvalidRequest)?;
            let mut cursor = input.as_ptr();
            // SAFETY: a complete readable DER input, explicit context/properties
            // and no reuse pointer. d2i_PUBKEY_ex cannot import private key data.
            key.raw = unsafe {
                native::d2i_PUBKEY_ex(
                    ptr::null_mut(),
                    &mut cursor,
                    length,
                    context.raw(),
                    PROPERTIES.as_ptr().cast(),
                )
            };
            if key.raw.is_null() {
                return Err(Failure::Unavailable);
            }
            if cursor != input.as_ptr().wrapping_add(input.len()) {
                return Err(Failure::InvalidRequest);
            }
        }
        key_format::RAW_PUBLIC => {
            // SAFETY: typed public-only import with the supplied exact length.
            key.raw = unsafe {
                native::EVP_PKEY_new_raw_public_key_ex(
                    context.raw(),
                    algorithm.as_ptr(),
                    PROPERTIES.as_ptr().cast(),
                    input.as_ptr(),
                    input.len(),
                )
            };
            if key.raw.is_null() {
                return Err(Failure::Unavailable);
            }
        }
        _ => return Err(Failure::InvalidRequest),
    }
    // SAFETY: a live public key and a validated terminated algorithm name.
    if unsafe { native::EVP_PKEY_is_a(key.raw, algorithm.as_ptr()) } != 1 {
        return Err(Failure::InvalidRequest);
    }
    Ok(key)
}

fn prepare<'a>(key: &'a Key<'_>, parameters: &mut Parameters) -> Result<Digest<'a>> {
    // Reject a scheme/key mismatch before asking the engine to select defaults.
    let family = match parameters {
        Parameters::RsaPkcs1 { .. } | Parameters::RsaPss { .. } => Some(b"RSA\0".as_slice()),
        Parameters::DigestSignature { .. } => Some(b"EC\0".as_slice()),
        Parameters::PureEdDsa => {
            let edwards = unsafe {
                native::EVP_PKEY_is_a(key.raw, b"ED25519\0".as_ptr().cast()) == 1
                    || native::EVP_PKEY_is_a(key.raw, b"ED448\0".as_ptr().cast()) == 1
            };
            if !edwards {
                return Err(Failure::InvalidRequest);
            }
            None
        }
        Parameters::EdDsa { family, .. } => Some(*family),
        Parameters::Pqc { .. } => None,
    };
    if let Some(family) = family {
        if unsafe { native::EVP_PKEY_is_a(key.raw, family.as_ptr().cast()) } != 1 {
            return Err(Failure::InvalidRequest);
        }
    }
    let operation = Digest {
        raw: unsafe { native::EVP_MD_CTX_new() },
        _key: PhantomData,
    };
    if operation.raw.is_null() {
        return Err(Failure::Allocation);
    }
    let digest = parameters.digest();
    let mut native_parameters: [native::OSSL_PARAM; 3] =
        std::array::from_fn(|_| unsafe { native::OSSL_PARAM_construct_end() });
    if let Parameters::Pqc { context, encoding } = parameters {
        // SAFETY: parameter storage is stable for synchronous initialization.
        native_parameters = unsafe {
            [
                native::OSSL_PARAM_construct_octet_string(
                    b"context-string\0".as_ptr().cast(),
                    context.as_mut_slice().as_mut_ptr().cast(),
                    context.as_slice().len(),
                ),
                native::OSSL_PARAM_construct_int(b"message-encoding\0".as_ptr().cast(), encoding),
                native::OSSL_PARAM_construct_end(),
            ]
        };
    }
    // Maximum of the five fixed instance names, including its terminator.
    // OpenSSL copies both parameters into its own context during initialization.
    let mut instance_name = [0u8; b"Ed25519ctx\0".len()];
    if let Parameters::EdDsa {
        instance, context, ..
    } = parameters
    {
        instance_name[..instance.len()].copy_from_slice(instance);
        native_parameters = unsafe {
            [
                native::OSSL_PARAM_construct_utf8_string(
                    b"instance\0".as_ptr().cast(),
                    instance_name.as_mut_ptr().cast(),
                    instance.len() - 1,
                ),
                native::OSSL_PARAM_construct_octet_string(
                    b"context-string\0".as_ptr().cast(),
                    context.as_mut_slice().as_mut_ptr().cast(),
                    context.as_slice().len(),
                ),
                native::OSSL_PARAM_construct_end(),
            ]
        };
    }
    let mut key_context = ptr::null_mut();
    // SAFETY: all owners and names outlive this call, and the imported key
    // borrows the isolated context. No algorithm default is substituted.
    if unsafe {
        native::EVP_DigestVerifyInit_ex(
            operation.raw,
            &mut key_context,
            digest,
            key.context.raw(),
            PROPERTIES.as_ptr().cast(),
            key.raw,
            native_parameters.as_ptr(),
        )
    } != 1
        || key_context.is_null()
    {
        return Err(Failure::Unavailable);
    }
    let configured = match parameters {
        Parameters::RsaPkcs1 { .. } => unsafe {
            native::EVP_PKEY_CTX_set_rsa_padding(key_context, native::RSA_PKCS1_PADDING) == 1
        },
        Parameters::RsaPss {
            mgf_digest, salt, ..
        } => unsafe {
            native::EVP_PKEY_CTX_set_rsa_padding(key_context, native::RSA_PKCS1_PSS_PADDING) == 1
                && native::EVP_PKEY_CTX_set_rsa_mgf1_md_name(
                    key_context,
                    mgf_digest.as_ptr(),
                    PROPERTIES.as_ptr().cast(),
                ) == 1
                && native::EVP_PKEY_CTX_set_rsa_pss_saltlen(key_context, *salt) == 1
        },
        _ => true,
    };
    if !configured {
        return Err(Failure::Unavailable);
    }
    Ok(operation)
}

/// Probe and verification share preparation. No PKCS#11 calls or private-key
/// operations occur here; a probe never signs or changes the supplied message.
pub(crate) unsafe fn run(
    request: &VerificationRequest,
    input: Option<(&[u8], &[u8])>,
) -> Result<bool> {
    let mut parameters = unsafe { Parameters::read(request) }?;
    let context = Context::new()?;
    let key = unsafe { import(&context, request) }?;
    let operation = prepare(&key, &mut parameters)?;
    let Some((message, signature)) = input else {
        return Ok(false);
    };
    // SAFETY: borrowed message/signature stay readable through this synchronous
    // call, and operation/key/context are dropped in reverse dependency order.
    match unsafe {
        native::EVP_DigestVerify(
            operation.raw,
            signature.as_ptr(),
            signature.len(),
            message.as_ptr(),
            message.len(),
        )
    } {
        1 => Ok(true),
        0 => Ok(false),
        _ => Err(Failure::Engine),
    }
}
