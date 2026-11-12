// SPDX-License-Identifier: Apache-2.0
//! Empty generation parameter storage, admitted with the enclosing template.
use super::{ulong, Dsa, Parameters, PbkdfRaw, Request, Seed};
use crate::{
    bounds,
    native::derivation::InputBytesStorage,
    symmetric::memory::{Credit, UnboundBuffer},
    Error, Pbkdf2Layout, Result,
};
use fe11_sys::{CK_DSA_PARAMETER_GEN_PARAM, CK_VERSION};

pub(crate) enum Storage<'a> {
    Extension(crate::mechanism_extension::GraphStorage<'a>),
    Scalars,
    Pbe {
        password: InputBytesStorage,
        salt: InputBytesStorage,
        iv: Option<UnboundBuffer>,
    },
    Pbkdf {
        password: InputBytesStorage,
        salt: InputBytesStorage,
        data: Option<InputBytesStorage>,
    },
    DsaInput(InputBytesStorage),
    DsaOutput(UnboundBuffer),
}

fn sum(values: impl IntoIterator<Item = usize>) -> Result<usize> {
    values.into_iter().try_fold(0usize, |total, value| {
        total
            .checked_add(value)
            .ok_or(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::GenerationParameterAccounting,
            )))
    })
}

impl<'a> Storage<'a> {
    pub(crate) fn allocate(request: &Request<'a>) -> Result<Self> {
        Parameters::payload_bytes(request)?;
        Ok(match request {
            Request::Extension { request, .. } => Self::Extension(
                crate::mechanism_extension::GraphStorage::allocate(&request.parameters)?,
            ),
            Request::Simple(_)
            | Request::Ssl3PreMaster { .. }
            | Request::TlsPreMaster { .. }
            | Request::WtlsPreMaster { .. } => Self::Scalars,
            Request::Password {
                generator,
                password,
                salt,
                ..
            } => Self::Pbe {
                password: InputBytesStorage::allocate(password.len())?,
                salt: InputBytesStorage::allocate(salt.len())?,
                iv: generator
                    .has_iv()
                    .then(|| UnboundBuffer::allocate(8))
                    .transpose()?,
            },
            Request::Pbkdf2 {
                password,
                salt,
                prf_data,
                ..
            } => Self::Pbkdf {
                password: InputBytesStorage::allocate(password.len())?,
                salt: InputBytesStorage::allocate(salt.len())?,
                data: prf_data
                    .map(|bytes| InputBytesStorage::allocate(bytes.len()))
                    .transpose()?,
            },
            Request::Dsa(Dsa::Base { seed, .. }) => {
                Self::DsaInput(InputBytesStorage::allocate(seed.len())?)
            }
            Request::Dsa(
                Dsa::Probabilistic { seed_capacity, .. } | Dsa::ShaweTaylor { seed_capacity, .. },
            ) => Self::DsaOutput(UnboundBuffer::allocate(*seed_capacity)?),
        })
    }

    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        match self {
            Self::Extension(graph) => graph.allocated_bytes(),
            Self::Scalars => Ok(0),
            Self::Pbe { password, salt, iv } => sum([
                password.allocated_bytes()?,
                salt.allocated_bytes()?,
                iv.as_ref().map_or(0, UnboundBuffer::allocated),
            ]),
            Self::Pbkdf {
                password,
                salt,
                data,
            } => sum([
                password.allocated_bytes()?,
                salt.allocated_bytes()?,
                data.as_ref()
                    .map(InputBytesStorage::allocated_bytes)
                    .transpose()?
                    .unwrap_or(0),
            ]),
            Self::DsaInput(seed) => seed.allocated_bytes(),
            Self::DsaOutput(seed) => Ok(seed.allocated()),
        }
    }

    pub(crate) fn bind(self, request: &Request<'_>, prepaid: &mut Credit) -> Result<Parameters> {
        Ok(match (self, request) {
            (Self::Extension(graph), Request::Extension { request, .. }) => {
                Parameters::extension(request.contract.clone(), graph.bind(prepaid)?)
            }
            (Self::Scalars, Request::Simple(_)) => Parameters::None,
            (
                Self::Scalars,
                Request::Ssl3PreMaster { major, minor } | Request::TlsPreMaster { major, minor },
            ) => Parameters::Version {
                raw: CK_VERSION {
                    major: *major,
                    minor: *minor,
                },
                expected: CK_VERSION {
                    major: *major,
                    minor: *minor,
                },
            },
            (Self::Scalars, Request::WtlsPreMaster { version }) => Parameters::Wtls {
                raw: *version,
                expected: *version,
            },
            (
                Self::Pbe { password, salt, iv },
                Request::Password {
                    generator,
                    password: input,
                    salt: salt_input,
                    iterations,
                },
            ) if iv.is_some() == generator.has_iv() => Parameters::Pbe {
                // SAFETY: nullable pointer/integer fields; projection binds
                // every field after the enclosing native frame is stable.
                raw: unsafe { std::mem::zeroed() },
                password: password.bind(input, prepaid)?,
                salt: salt.bind(salt_input, prepaid)?,
                iterations: ulong(*iterations)?,
                iv: iv.map(|buffer| buffer.bind(prepaid)).transpose()?,
            },
            (
                Self::Pbkdf {
                    password,
                    salt,
                    data,
                },
                Request::Pbkdf2 {
                    layout,
                    password: input,
                    salt: salt_input,
                    iterations,
                    prf,
                    prf_data,
                },
            ) if data.is_some() == prf_data.is_some() => Parameters::Pbkdf {
                // SAFETY: both explicit ABI layouts have nullable pointers
                // and integer fields; projection binds the selected layout.
                raw: unsafe {
                    match layout {
                        Pbkdf2Layout::Current => PbkdfRaw::Current(std::mem::zeroed()),
                        Pbkdf2Layout::Historical => PbkdfRaw::Historical(std::mem::zeroed()),
                    }
                },
                password: password.bind(input, prepaid)?,
                salt: salt.bind(salt_input, prepaid)?,
                iterations: ulong(*iterations)?,
                prf: ulong(*prf)?,
                data: data
                    .zip(*prf_data)
                    .map(|(storage, input)| storage.bind(input, prepaid))
                    .transpose()?,
                length: bounds::ck_length(input.len())?,
            },
            (
                Self::DsaInput(seed),
                Request::Dsa(Dsa::Base {
                    hash,
                    index,
                    seed: input,
                }),
            ) => dsa(*hash, *index, Seed::Input(seed.bind(input, prepaid)?))?,
            (
                Self::DsaOutput(seed),
                Request::Dsa(
                    Dsa::Probabilistic {
                        hash,
                        index,
                        seed_capacity,
                    }
                    | Dsa::ShaweTaylor {
                        hash,
                        index,
                        seed_capacity,
                    },
                ),
            ) => {
                let seed = seed.bind(prepaid)?;
                if seed.capacity() != *seed_capacity {
                    return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                        crate::NativeExecutionRejection::GenerationPreparationChanged,
                    )));
                }
                dsa(*hash, *index, Seed::Output(seed))?
            }
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                    crate::NativeExecutionRejection::GenerationPreparationChanged,
                )))
            }
        })
    }
}

fn dsa(hash: u64, index: u64, seed: Seed) -> Result<Parameters> {
    let hash = ulong(hash)?;
    let index = ulong(index)?;
    Ok(Parameters::Dsa {
        raw: CK_DSA_PARAMETER_GEN_PARAM {
            hash,
            pSeed: std::ptr::null_mut(),
            ulSeedLen: seed.length(),
            ulIndex: index,
        },
        hash,
        index,
        seed,
    })
}
