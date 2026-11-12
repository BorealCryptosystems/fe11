// SPDX-License-Identifier: Apache-2.0
//! Owned generation parameters. Bind only after the enclosing frame is stable.
use crate::{
    bounds, native::derivation::InputBytes, symmetric::memory::Buffer, DsaDomainGeneration as Dsa,
    Error, NativeGenerationBytes, NativeGenerationOutput as Output, NativeKeyGeneration as Request,
    Result,
};

use fe11_sys::*;
use std::mem::size_of;

mod preparation;
pub(crate) use preparation::Storage;
fn ulong(value: u64) -> Result<CK_ULONG> {
    CK_ULONG::try_from(value).map_err(|_| {
        Error::Rejected(crate::RejectionReason::NativeExecution(
            crate::NativeExecutionRejection::GenerationScalarAbiWidth,
        ))
    })
}
fn add(total: usize, length: usize, copies: usize) -> Result<usize> {
    bounds::ck_length(length)?;
    length
        .checked_mul(copies)
        .and_then(|n| total.checked_add(n))
        .ok_or(Error::Rejected(crate::RejectionReason::NativeExecution(
            crate::NativeExecutionRejection::GenerationParameterAccounting,
        )))
}
fn optional_pointer(value: &mut Option<InputBytes>) -> CK_BYTE_PTR {
    value
        .as_mut()
        .map_or(std::ptr::null_mut(), InputBytes::pointer)
}
fn optional_expected(value: &Option<InputBytes>) -> CK_BYTE_PTR {
    value
        .as_ref()
        .map_or(std::ptr::null_mut(), InputBytes::expected_pointer)
}
fn optional_length(value: &Option<InputBytes>) -> CK_ULONG {
    value.as_ref().map_or(0, InputBytes::length)
}
pub(crate) enum PbkdfRaw {
    Current(CK_PKCS5_PBKD2_PARAMS2),
    Historical(CK_PKCS5_PBKD2_PARAMS),
}
pub(crate) enum Seed {
    Input(InputBytes),
    Output(Buffer),
}
impl Seed {
    fn pointer(&mut self) -> CK_BYTE_PTR {
        match self {
            Self::Input(v) => v.pointer(),
            Self::Output(v) => v.as_mut().as_mut_ptr(),
        }
    }
    fn expected(&self) -> CK_BYTE_PTR {
        match self {
            Self::Input(v) => v.expected_pointer(),
            Self::Output(v) => v.as_slice().as_ptr().cast_mut(),
        }
    }
    fn length(&self) -> CK_ULONG {
        match self {
            Self::Input(v) => v.length(),
            Self::Output(v) => v.as_slice().len() as CK_ULONG,
        }
    }
}
pub(crate) enum Parameters {
    Extension {
        contract: crate::MechanismExtension,
        graph: Option<crate::mechanism_extension::OwnedGraph>,
        pointer: CK_VOID_PTR,
        length: CK_ULONG,
    },
    None,
    Version {
        raw: CK_VERSION,
        expected: CK_VERSION,
    },
    Wtls {
        raw: CK_BYTE,
        expected: CK_BYTE,
    },
    Pbe {
        raw: CK_PBE_PARAMS,
        password: InputBytes,
        salt: InputBytes,
        iterations: CK_ULONG,
        iv: Option<Buffer>,
    },
    Pbkdf {
        raw: PbkdfRaw,
        password: InputBytes,
        salt: InputBytes,
        iterations: CK_ULONG,
        prf: CK_ULONG,
        data: Option<InputBytes>,
        length: CK_ULONG,
    },
    Dsa {
        raw: CK_DSA_PARAMETER_GEN_PARAM,
        hash: CK_MECHANISM_TYPE,
        index: CK_ULONG,
        seed: Seed,
    },
}
impl Parameters {
    pub(crate) fn extension(
        contract: crate::MechanismExtension,
        graph: crate::mechanism_extension::OwnedGraph,
    ) -> Self {
        Self::Extension {
            contract,
            graph: Some(graph),
            pointer: std::ptr::null_mut(),
            length: 0,
        }
    }
    pub(crate) fn check_extension(
        &self,
        inner: &std::sync::Arc<crate::module::Inner>,
        operation: crate::ExtensionOperation,
    ) -> Result<()> {
        if let Self::Extension { contract, .. } = self {
            contract.check(inner, operation)?;
        }
        Ok(())
    }

    pub(crate) fn payload_bytes(request: &Request<'_>) -> Result<usize> {
        match request {
            Request::Extension { request, .. } => {
                crate::mechanism_extension::OwnedGraph::allocation_bytes(&request.parameters)
            }
            Request::Simple(_)
            | Request::Ssl3PreMaster { .. }
            | Request::TlsPreMaster { .. }
            | Request::WtlsPreMaster { .. } => Ok(0),
            Request::Password {
                generator,
                password,
                salt,
                iterations,
            } => {
                ulong(*iterations)?;
                add(
                    add(if generator.has_iv() { 8 } else { 0 }, password.len(), 2)?,
                    salt.len(),
                    2,
                )
            }
            Request::Pbkdf2 {
                password,
                salt,
                iterations,
                prf,
                prf_data,
                ..
            } => {
                ulong(*iterations)?;
                ulong(*prf)?;
                add(
                    add(add(0, password.len(), 2)?, salt.len(), 2)?,
                    prf_data.map_or(0, |v| v.len()),
                    2,
                )
            }
            Request::Dsa(dsa) => {
                let (hash, index, length, copies) = match dsa {
                    Dsa::Probabilistic {
                        hash,
                        index,
                        seed_capacity,
                    }
                    | Dsa::ShaweTaylor {
                        hash,
                        index,
                        seed_capacity,
                    } => (*hash, *index, *seed_capacity, 1),
                    Dsa::Base { hash, index, seed } => (*hash, *index, seed.len(), 2),
                };
                ulong(hash)?;
                ulong(index)?;
                add(0, length, copies)
            }
        }
    }

    // Generation consumes its parameter owner and projects it once before C.
    // Extension construction installs Some(graph); take_output is reached only
    // after native completion and handle registration, never before projection.
    pub(crate) fn projection(&mut self) -> (CK_VOID_PTR, CK_ULONG) {
        match self {
            Self::Extension {
                graph,
                pointer,
                length,
                ..
            } => {
                (*pointer, *length) = graph
                    .as_mut()
                    .expect("undispatched extension graph")
                    .projection();
                (*pointer, *length)
            }
            Self::None => (std::ptr::null_mut(), 0),
            Self::Version { raw, .. } => (
                (raw as *mut CK_VERSION).cast(),
                size_of::<CK_VERSION>() as CK_ULONG,
            ),
            Self::Wtls { raw, .. } => (
                (raw as *mut CK_BYTE).cast(),
                size_of::<CK_BYTE>() as CK_ULONG,
            ),
            Self::Pbe {
                raw,
                password,
                salt,
                iterations,
                iv,
            } => {
                raw.pInitVector = iv
                    .as_mut()
                    .map_or(std::ptr::null_mut(), |v| v.as_mut().as_mut_ptr());
                raw.pPassword = password.pointer();
                raw.ulPasswordLen = password.length();
                raw.pSalt = salt.pointer();
                raw.ulSaltLen = salt.length();
                raw.ulIteration = *iterations;
                (
                    (raw as *mut CK_PBE_PARAMS).cast(),
                    size_of::<CK_PBE_PARAMS>() as CK_ULONG,
                )
            }
            Self::Pbkdf {
                raw,
                password,
                salt,
                iterations,
                prf,
                data,
                length,
            } => match raw {
                PbkdfRaw::Current(raw) => {
                    raw.saltSource = CKZ_SALT_SPECIFIED;
                    raw.pSaltSourceData = salt.pointer().cast();
                    raw.ulSaltSourceDataLen = salt.length();
                    raw.iterations = *iterations;
                    raw.prf = *prf;
                    raw.pPrfData = optional_pointer(data).cast();
                    raw.ulPrfDataLen = optional_length(data);
                    raw.pPassword = password.pointer();
                    raw.ulPasswordLen = password.length();
                    (
                        (raw as *mut CK_PKCS5_PBKD2_PARAMS2).cast(),
                        size_of::<CK_PKCS5_PBKD2_PARAMS2>() as CK_ULONG,
                    )
                }
                PbkdfRaw::Historical(raw) => {
                    raw.saltSource = CKZ_SALT_SPECIFIED;
                    raw.pSaltSourceData = salt.pointer().cast();
                    raw.ulSaltSourceDataLen = salt.length();
                    raw.iterations = *iterations;
                    raw.prf = *prf;
                    raw.pPrfData = optional_pointer(data).cast();
                    raw.ulPrfDataLen = optional_length(data);
                    raw.pPassword = password.pointer();
                    raw.ulPasswordLen = length as *mut CK_ULONG;
                    (
                        (raw as *mut CK_PKCS5_PBKD2_PARAMS).cast(),
                        size_of::<CK_PKCS5_PBKD2_PARAMS>() as CK_ULONG,
                    )
                }
            },
            Self::Dsa { raw, seed, .. } => {
                raw.pSeed = seed.pointer();
                (
                    (raw as *mut CK_DSA_PARAMETER_GEN_PARAM).cast(),
                    size_of::<CK_DSA_PARAMETER_GEN_PARAM>() as CK_ULONG,
                )
            }
        }
    }
    pub(crate) fn unchanged(&self, mechanism: &CK_MECHANISM) -> bool {
        let (pointer, length, fields) = match self {
            Self::Extension {
                graph,
                pointer,
                length,
                ..
            } => (
                *pointer,
                *length,
                graph.as_ref().is_some_and(|graph| graph.unchanged()),
            ),
            Self::None => (std::ptr::null_mut(), 0, true),
            Self::Version { raw, expected } => (
                (raw as *const CK_VERSION).cast_mut().cast(),
                size_of::<CK_VERSION>() as CK_ULONG,
                raw.major == expected.major && raw.minor == expected.minor,
            ),
            Self::Wtls { raw, expected } => (
                (raw as *const CK_BYTE).cast_mut().cast(),
                size_of::<CK_BYTE>() as CK_ULONG,
                raw == expected,
            ),
            Self::Pbe {
                raw,
                password,
                salt,
                iterations,
                iv,
            } => (
                (raw as *const CK_PBE_PARAMS).cast_mut().cast(),
                size_of::<CK_PBE_PARAMS>() as CK_ULONG,
                raw.pInitVector
                    == iv
                        .as_ref()
                        .map_or(std::ptr::null_mut(), |v| v.as_slice().as_ptr().cast_mut())
                    && raw.pPassword == password.expected_pointer()
                    && raw.ulPasswordLen == password.length()
                    && raw.pSalt == salt.expected_pointer()
                    && raw.ulSaltLen == salt.length()
                    && raw.ulIteration == *iterations
                    && (password.unchanged() & salt.unchanged()),
            ),
            Self::Pbkdf {
                raw,
                password,
                salt,
                iterations,
                prf,
                data,
                length,
            } => {
                let bytes = password.unchanged()
                    & salt.unchanged()
                    & data.as_ref().map_or(true, InputBytes::unchanged);
                match raw {
                    PbkdfRaw::Current(raw) => (
                        (raw as *const CK_PKCS5_PBKD2_PARAMS2).cast_mut().cast(),
                        size_of::<CK_PKCS5_PBKD2_PARAMS2>() as CK_ULONG,
                        raw.saltSource == CKZ_SALT_SPECIFIED
                            && raw.pSaltSourceData == salt.expected_pointer().cast()
                            && raw.ulSaltSourceDataLen == salt.length()
                            && raw.iterations == *iterations
                            && raw.prf == *prf
                            && raw.pPrfData == optional_expected(data).cast()
                            && raw.ulPrfDataLen == optional_length(data)
                            && raw.pPassword == password.expected_pointer()
                            && raw.ulPasswordLen == password.length()
                            && bytes,
                    ),
                    PbkdfRaw::Historical(raw) => (
                        (raw as *const CK_PKCS5_PBKD2_PARAMS).cast_mut().cast(),
                        size_of::<CK_PKCS5_PBKD2_PARAMS>() as CK_ULONG,
                        raw.saltSource == CKZ_SALT_SPECIFIED
                            && raw.pSaltSourceData == salt.expected_pointer().cast()
                            && raw.ulSaltSourceDataLen == salt.length()
                            && raw.iterations == *iterations
                            && raw.prf == *prf
                            && raw.pPrfData == optional_expected(data).cast()
                            && raw.ulPrfDataLen == optional_length(data)
                            && raw.pPassword == password.expected_pointer()
                            && raw.ulPasswordLen == (length as *const CK_ULONG).cast_mut()
                            && *length == password.length()
                            && bytes,
                    ),
                }
            }
            Self::Dsa {
                raw,
                hash,
                index,
                seed,
            } => (
                (raw as *const CK_DSA_PARAMETER_GEN_PARAM).cast_mut().cast(),
                size_of::<CK_DSA_PARAMETER_GEN_PARAM>() as CK_ULONG,
                raw.hash == *hash
                    && raw.ulIndex == *index
                    && raw.pSeed == seed.expected()
                    && match seed {
                        Seed::Input(v) => raw.ulSeedLen == v.length() && v.unchanged(),
                        Seed::Output(_) => true,
                    },
            ),
        };
        mechanism.pParameter == pointer && mechanism.ulParameterLen == length && fields
    }
    /// Called only after success and intact inputs, before registering handles.
    pub(crate) fn validate_output_bounds(&self) -> Result<()> {
        match self {
            Self::Extension {
                graph: Some(graph), ..
            } => graph.validate_output_bounds(),
            Self::Dsa {
                raw,
                seed: Seed::Output(seed),
                ..
            } if raw.ulSeedLen as u128 > seed.as_slice().len() as u128 => {
                Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                    crate::NativeExecutionRejection::DsaSeedReturnedLength,
                )))
            }
            _ => Ok(()),
        }
    }

    /// Called after native success and handle registration. A bad returned length
    /// remains a post-creation failure so the facade can clean up the known key.
    pub(crate) fn take_output(&mut self) -> Result<Output> {
        Ok(match self {
            Self::Extension {
                graph, contract, ..
            } => {
                graph
                    .as_mut()
                    .ok_or(Error::Rejected(crate::RejectionReason::NativeExecution(
                        crate::NativeExecutionRejection::GenerationExtensionOutputTaken,
                    )))?
                    .finish()?;
                // finish borrows the graph without taking its enclosing Option.
                // Only this transfer removes it; a repeated call is rejected by
                // the checked borrow above before this invariant is used.
                Output::Extension(crate::ExtensionParameterOutputs {
                    graph: graph.take().expect("validated extension graph"),
                    provenance: contract.provenance(),
                })
            }
            Self::Pbe { iv: Some(iv), .. } => {
                Output::InitializationVector(NativeGenerationBytes(iv.take()))
            }
            Self::Dsa {
                raw,
                seed: Seed::Output(seed),
                ..
            } => {
                let length = usize::try_from(raw.ulSeedLen).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::NativeExecution(
                        crate::NativeExecutionRejection::DsaSeedReturnedLength,
                    ))
                })?;
                seed.set_length(length)?;
                Output::DomainSeed(NativeGenerationBytes(seed.take()))
            }
            _ => Output::None,
        })
    }
}
