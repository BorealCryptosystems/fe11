// SPDX-License-Identifier: Apache-2.0
//! OAEP parameter storage; logical label retained under the module budget.

use crate::{symmetric::memory::Buffer, Error, Result};
use fe11_sys::*;

pub(super) struct OaepStorage<'a> {
    source: &'a [u8],
    label: crate::symmetric::memory::UnboundBuffer,
    hash: CK_MECHANISM_TYPE,
    mgf: CK_RSA_PKCS_MGF_TYPE,
}
impl<'a> OaepStorage<'a> {
    pub(super) fn allocate(label: &'a [u8], hash: u64, mgf: u64) -> Result<Self> {
        crate::bounds::ck_length(label.len())?;
        Ok(Self {
            source: label,
            hash: hash.try_into().map_err(|_| {
                Error::Rejected(crate::RejectionReason::KeyTransport(
                    crate::KeyTransportRejection::OaepHashIdentifierWidth,
                ))
            })?,
            mgf: mgf.try_into().map_err(|_| {
                Error::Rejected(crate::RejectionReason::KeyTransport(
                    crate::KeyTransportRejection::OaepMgfIdentifierWidth,
                ))
            })?,
            label: crate::symmetric::memory::UnboundBuffer::allocate(label.len())?,
        })
    }
    pub(super) fn allocated_bytes(&self) -> usize {
        self.label.allocated()
    }
    pub(super) fn bind(self, prepaid: &mut crate::symmetric::memory::Credit) -> Result<OaepBuffer> {
        let mut label = self.label.bind(prepaid)?;
        label.as_mut().copy_from_slice(self.source);
        Ok(OaepBuffer {
            label,
            hash: self.hash,
            mgf: self.mgf,
        })
    }
}

pub(super) struct OaepBuffer {
    label: Buffer,
    hash: CK_MECHANISM_TYPE,
    mgf: CK_RSA_PKCS_MGF_TYPE,
}
impl OaepBuffer {
    pub(super) fn selection(&self) -> crate::OaepParams<'_> {
        crate::OaepParams {
            hash: self.hash as u64,
            mgf: self.mgf as u64,
            label: self.label.as_slice(),
        }
    }
    pub(super) fn label(&self) -> &[u8] {
        self.label.as_slice()
    }
    pub(super) fn parameters(&mut self) -> CK_RSA_PKCS_OAEP_PARAMS {
        CK_RSA_PKCS_OAEP_PARAMS {
            hashAlg: self.hash,
            mgf: self.mgf,
            source: CKZ_DATA_SPECIFIED,
            pSourceData: if self.label.capacity() == 0 {
                std::ptr::null_mut()
            } else {
                self.label.as_mut().as_mut_ptr().cast()
            },
            ulSourceDataLen: self.label.capacity() as CK_ULONG,
        }
    }
    pub(super) fn unchanged(
        &self,
        p: &CK_RSA_PKCS_OAEP_PARAMS,
        m: &CK_MECHANISM,
        pointer: CK_VOID_PTR,
        expected: &[u8],
    ) -> bool {
        let label = if self.label.capacity() == 0 {
            std::ptr::null_mut()
        } else {
            self.label.as_slice().as_ptr() as CK_VOID_PTR
        };
        m.mechanism == CKM_RSA_PKCS_OAEP
            && m.pParameter == pointer
            && m.ulParameterLen == std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>() as CK_ULONG
            && p.hashAlg == self.hash
            && p.mgf == self.mgf
            && p.source == CKZ_DATA_SPECIFIED
            && p.pSourceData == label
            && p.ulSourceDataLen as u128 == self.label.capacity() as u128
            && self.label.as_slice() == expected
    }
}
