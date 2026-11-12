// SPDX-License-Identifier: Apache-2.0
//! Unpublished parameter storage for the caller-selected transport mechanism.
use super::super::{authenticated::GcmStorage, oaep::OaepStorage};
use super::*;
use crate::symmetric::memory::Credit;

pub(super) enum TransportStorage<'a> {
    Standard,
    Oaep(OaepStorage<'a>),
    AuthenticatedGcm(GcmStorage<'a>),
}
impl<'a> TransportStorage<'a> {
    pub(super) fn unwrap_allocation_bytes(selection: &UnwrapParameters<'_>) -> Result<usize> {
        match selection {
            UnwrapParameters::AesKw | UnwrapParameters::AesKwp => Ok(0),
            UnwrapParameters::RsaOaep { label, hash, mgf } => {
                bounds::ck_length(label.len())?;
                CK_MECHANISM_TYPE::try_from(*hash).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::KeyTransport(
                        crate::KeyTransportRejection::OaepHashIdentifierWidth,
                    ))
                })?;
                CK_RSA_PKCS_MGF_TYPE::try_from(*mgf).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::KeyTransport(
                        crate::KeyTransportRejection::OaepMgfIdentifierWidth,
                    ))
                })?;
                Ok(label.len())
            }
            UnwrapParameters::AuthenticatedGcm { nonce, tag, aad } => {
                GcmStorage::allocation_bytes(nonce, Some(tag), aad)
            }
        }
    }
    pub(super) fn for_unwrap(selection: &'a UnwrapParameters<'a>) -> Result<Self> {
        match selection {
            UnwrapParameters::AesKw | UnwrapParameters::AesKwp => Ok(Self::Standard),
            UnwrapParameters::RsaOaep { label, hash, mgf } => {
                Ok(Self::Oaep(OaepStorage::allocate(label, *hash, *mgf)?))
            }
            UnwrapParameters::AuthenticatedGcm { nonce, tag, aad } => Ok(Self::AuthenticatedGcm(
                GcmStorage::allocate(nonce, Some(tag), aad)?,
            )),
        }
    }

    pub(super) fn wrap_allocation_bytes(selection: &WrapParameters<'_>) -> Result<usize> {
        match selection {
            WrapParameters::AesKw | WrapParameters::AesKwp => Ok(0),
            WrapParameters::RsaOaep { label, hash, mgf } => {
                bounds::ck_length(label.len())?;
                CK_MECHANISM_TYPE::try_from(*hash).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::KeyTransport(
                        crate::KeyTransportRejection::OaepHashIdentifierWidth,
                    ))
                })?;
                CK_RSA_PKCS_MGF_TYPE::try_from(*mgf).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::KeyTransport(
                        crate::KeyTransportRejection::OaepMgfIdentifierWidth,
                    ))
                })?;
                Ok(label.len())
            }
            WrapParameters::AuthenticatedGcm { nonce, aad } => {
                GcmStorage::allocation_bytes(nonce, None, aad)
            }
        }
    }
    pub(super) fn for_wrap(selection: &'a WrapParameters<'a>) -> Result<Self> {
        match selection {
            WrapParameters::AesKw | WrapParameters::AesKwp => Ok(Self::Standard),
            WrapParameters::RsaOaep { label, hash, mgf } => {
                Ok(Self::Oaep(OaepStorage::allocate(label, *hash, *mgf)?))
            }
            WrapParameters::AuthenticatedGcm { nonce, aad } => Ok(Self::AuthenticatedGcm(
                GcmStorage::allocate(nonce, None, aad)?,
            )),
        }
    }
    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        match self {
            Self::Standard => Ok(0),
            Self::Oaep(storage) => Ok(storage.allocated_bytes()),
            Self::AuthenticatedGcm(storage) => storage.allocated_bytes(),
        }
    }
    pub(super) fn bind(self, prepaid: &mut Credit) -> Result<TransportInputs> {
        match self {
            Self::Standard => Ok(TransportInputs::Standard),
            Self::Oaep(storage) => {
                let mut buffers = storage.bind(prepaid)?;
                let parameters = buffers.parameters();
                Ok(TransportInputs::Oaep {
                    buffers,
                    parameters,
                })
            }
            Self::AuthenticatedGcm(storage) => {
                let mut buffers = storage.bind(prepaid)?;
                let (parameters, aad, aad_len) = buffers.parameters();
                Ok(TransportInputs::AuthenticatedGcm {
                    buffers,
                    parameters,
                    aad,
                    aad_len,
                })
            }
        }
    }
}
