// SPDX-License-Identifier: Apache-2.0
//! Empty parameter graphs for every one-output derivation family.
use super::{
    agreement, encrypt_data, ike, messaging, tls, Derivation, InputBytes, InputBytesStorage,
    InputTemplate, NativeHkdfSalt, NativeKeyDerivation, Parameters,
};
use crate::{mechanism_extension::GraphStorage, symmetric::memory::Credit, Error, Result};
use fe11_sys::{CK_INVALID_HANDLE, CK_MECHANISM};
use std::mem::size_of;

struct Input<'a> {
    source: &'a [u8],
    storage: InputBytesStorage,
}
impl<'a> Input<'a> {
    fn allocate(source: &'a [u8]) -> Result<Self> {
        Ok(Self {
            source,
            storage: InputBytesStorage::allocate(source.len())?,
        })
    }
    fn bind(self, credit: &mut Credit) -> Result<InputBytes> {
        self.storage.bind(self.source, credit)
    }
}
enum Storage<'a> {
    Basic {
        first: Option<Input<'a>>,
        second: Option<Input<'a>>,
    },
    Extension(GraphStorage<'a>),
    Messaging(messaging::MessagingStorage<'a>),
    Master(tls::MasterStorage),
    Kdf(tls::KdfStorage),
    Ike(ike::IkeStorage<'a>),
    Agreement(agreement::AgreementStorage<'a>),
    EncryptData(InputBytesStorage),
}
pub(crate) struct DerivationStorage<'r, 'a> {
    request: &'r NativeKeyDerivation<'a>,
    storage: Storage<'a>,
    frame_bytes: usize,
}
impl<'r, 'a> DerivationStorage<'r, 'a> {
    pub(crate) fn allocate(request: &'r NativeKeyDerivation<'a>) -> Result<Self> {
        Derivation::allocation_bytes(request)?;
        let storage = match request {
            NativeKeyDerivation::Extension { request, .. } => {
                Storage::Extension(GraphStorage::allocate(&request.parameters)?)
            }
            NativeKeyDerivation::Messaging(input) => {
                Storage::Messaging(messaging::MessagingStorage::allocate(input)?)
            }
            NativeKeyDerivation::TlsMaster(input) => {
                Storage::Master(tls::MasterStorage::allocate(input)?)
            }
            NativeKeyDerivation::TlsKdf(input) => Storage::Kdf(tls::KdfStorage::allocate(input)?),
            NativeKeyDerivation::Ike(input) => Storage::Ike(ike::IkeStorage::allocate(input)?),
            NativeKeyDerivation::Ecmqv { agreement, layout } => {
                Storage::Agreement(agreement::AgreementStorage::mqv(agreement, layout, true)?)
            }
            NativeKeyDerivation::X942Mqv { agreement, layout } => {
                Storage::Agreement(agreement::AgreementStorage::mqv(agreement, layout, false)?)
            }
            NativeKeyDerivation::X942Hybrid(input) => Storage::Agreement(
                agreement::AgreementStorage::allocate(input, agreement::Layout::DhTwo, None)?,
            ),
            NativeKeyDerivation::EncryptData(input) => {
                Storage::EncryptData(InputBytesStorage::allocate(input.data().len())?)
            }
            _ => {
                let (first, second) = match request {
                    NativeKeyDerivation::GostR3410 {
                        peer_public, ukm, ..
                    } => (Some(*peer_public), *ukm),
                    NativeKeyDerivation::Hkdf { .. } | NativeKeyDerivation::HkdfParameters(_) => {
                        let parameters =
                            request.hkdf_parameters().expect("matched HKDF parameters");
                        (
                            match parameters.salt {
                                NativeHkdfSalt::Data(bytes) => Some(bytes),
                                _ => None,
                            },
                            parameters.info,
                        )
                    }
                    NativeKeyDerivation::DhPkcs { peer_public } => (Some(*peer_public), None),
                    NativeKeyDerivation::ConcatenateData { data, .. }
                    | NativeKeyDerivation::XorData { data } => (Some(*data), None),
                    NativeKeyDerivation::Ecdh {
                        peer_public,
                        shared_data,
                        ..
                    } => (Some(*peer_public), *shared_data),
                    NativeKeyDerivation::X942Dh {
                        peer_public,
                        other_info,
                        ..
                    } => (Some(*peer_public), *other_info),
                    NativeKeyDerivation::Null { .. }
                    | NativeKeyDerivation::Hash(_)
                    | NativeKeyDerivation::PublicFromPrivate
                    | NativeKeyDerivation::ConcatenateKey(_)
                    | NativeKeyDerivation::Extract { .. } => (None, None),
                    _ => {
                        return Err(Error::Rejected(crate::RejectionReason::NativeDerivation(
                            crate::NativeDerivationRejection::DerivationStorageVariantChanged,
                        )))
                    }
                };
                Storage::Basic {
                    first: first.map(Input::allocate).transpose()?,
                    second: second.map(Input::allocate).transpose()?,
                }
            }
        };
        let nested = if matches!(request, NativeKeyDerivation::Extension { .. }) {
            size_of::<crate::mechanism_extension::OwnedGraph>()
        } else {
            0
        };
        Ok(Self {
            request,
            storage,
            frame_bytes: Derivation::frame_bytes(nested),
        })
    }
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        let payload = match &self.storage {
            Storage::Basic { first, second } => {
                let first = first
                    .as_ref()
                    .map(|v| v.storage.allocated_bytes())
                    .transpose()?
                    .unwrap_or(0);
                let second = second
                    .as_ref()
                    .map(|v| v.storage.allocated_bytes())
                    .transpose()?
                    .unwrap_or(0);
                first.checked_add(second).ok_or(Error::Rejected(
                    crate::RejectionReason::NativeDerivation(
                        crate::NativeDerivationRejection::DerivationParameterStorageAccounting,
                    ),
                ))?
            }
            Storage::Extension(value) => value.allocated_bytes()?,
            Storage::Messaging(value) => value.allocated_bytes()?,
            Storage::Master(value) => value.allocated_bytes()?,
            Storage::Kdf(value) => value.allocated_bytes()?,
            Storage::Ike(value) => value.allocated_bytes()?,
            Storage::Agreement(value) => value.allocated_bytes()?,
            Storage::EncryptData(value) => value.allocated_bytes()?,
        };
        self.frame_bytes.checked_add(payload).ok_or(Error::Rejected(
            crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::DerivationFrameAccounting,
            ),
        ))
    }
    pub(crate) fn bind(self, template: InputTemplate, prepaid: &mut Credit) -> Result<Derivation> {
        let credit = prepaid.split(self.frame_bytes)?;
        let parameters = match (self.request, self.storage) {
            (request, Storage::Basic { first, second }) => Parameters::basic_from_storage(
                request,
                first.map(|v| v.bind(prepaid)).transpose()?,
                second.map(|v| v.bind(prepaid)).transpose()?,
            )?,
            (_, Storage::Extension(storage)) => {
                let graph = storage.bind(prepaid)?;
                Parameters::Extension(graph)
            }
            (_, Storage::Messaging(storage)) => Parameters::Messaging(storage.bind(prepaid)?),
            (NativeKeyDerivation::TlsMaster(input), Storage::Master(storage)) => {
                Parameters::TlsMaster(storage.bind(input, prepaid)?)
            }
            (NativeKeyDerivation::TlsKdf(input), Storage::Kdf(storage)) => {
                Parameters::TlsKdf(storage.bind(input, prepaid)?)
            }
            (_, Storage::Ike(storage)) => Parameters::Ike(storage.bind(prepaid)?),
            (_, Storage::Agreement(storage)) => Parameters::Agreement(storage.bind(prepaid)?),
            (NativeKeyDerivation::EncryptData(input), Storage::EncryptData(storage)) => {
                Parameters::EncryptData(encrypt_data::EncryptData::from_storage(
                    input, storage, prepaid,
                )?)
            }
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::NativeDerivation(
                    crate::NativeDerivationRejection::DerivationStorageVariantChanged,
                )))
            }
        };
        Ok(Derivation {
            mechanism: CK_MECHANISM {
                mechanism: self.request.native(),
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
            parameters,
            template,
            output: CK_INVALID_HANDLE,
            mutates_base: self.request.mutates_base(),
            _credit: credit,
        })
    }
}
