// SPDX-License-Identifier: Apache-2.0
//! Owned storage for authenticated PKCS#11 3.2 transport parameters.

use crate::{symmetric::memory::Buffer, AeadNonce, Error, Result};
use fe11_sys::*;

pub(super) struct GcmStorage<'a> {
    origin: &'a AeadNonce,
    source_tag: Option<&'a [u8]>,
    source_aad: &'a [u8],
    iv: crate::symmetric::memory::UnboundBuffer,
    tag: crate::symmetric::memory::UnboundBuffer,
    aad: crate::symmetric::memory::UnboundBuffer,
    expected_tag: Option<crate::symmetric::memory::UnboundBuffer>,
}
impl<'a> GcmStorage<'a> {
    pub(super) fn allocation_bytes(
        origin: &AeadNonce,
        expected_tag: Option<&[u8]>,
        aad: &[u8],
    ) -> Result<usize> {
        origin.validate_gcm_message_encrypt(aad.len())?;
        let tag_bytes = origin.tag_bytes()?;
        if expected_tag.is_some_and(|tag| tag.len() != tag_bytes)
            || expected_tag.is_some() && origin.generated()
        {
            return Err(Error::Rejected(crate::RejectionReason::KeyTransport(
                crate::KeyTransportRejection::AuthenticatedUnwrapParameters,
            )));
        }
        [
            origin.retained_bytes(),
            origin.iv().len(),
            tag_bytes,
            aad.len(),
            expected_tag.map_or(0, <[u8]>::len),
        ]
        .into_iter()
        .try_fold(std::mem::size_of::<GcmBuffers>(), |size, bytes| {
            size.checked_add(bytes)
                .ok_or(Error::Rejected(crate::RejectionReason::KeyTransport(
                    crate::KeyTransportRejection::GcmSelectionSize,
                )))
        })
    }
    pub(super) fn allocate(
        origin: &'a AeadNonce,
        expected_tag: Option<&'a [u8]>,
        aad: &'a [u8],
    ) -> Result<Self> {
        use crate::symmetric::memory::UnboundBuffer;
        Self::allocation_bytes(origin, expected_tag, aad)?;
        Ok(Self {
            origin,
            source_tag: expected_tag,
            source_aad: aad,
            iv: UnboundBuffer::allocate(origin.iv().len())?,
            tag: UnboundBuffer::allocate(origin.tag_bytes()?)?,
            aad: UnboundBuffer::allocate(aad.len())?,
            expected_tag: expected_tag
                .map(|tag| UnboundBuffer::allocate(tag.len()))
                .transpose()?,
        })
    }
    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        [
            self.origin.retained_bytes(),
            self.iv.allocated(),
            self.tag.allocated(),
            self.aad.allocated(),
            self.expected_tag.as_ref().map_or(0, |tag| tag.allocated()),
        ]
        .into_iter()
        .try_fold(std::mem::size_of::<GcmBuffers>(), |size, bytes| {
            size.checked_add(bytes)
                .ok_or(Error::Rejected(crate::RejectionReason::KeyTransport(
                    crate::KeyTransportRejection::GcmSelectionSize,
                )))
        })
    }
    pub(super) fn bind(self, prepaid: &mut crate::symmetric::memory::Credit) -> Result<GcmBuffers> {
        let mut credit = prepaid.split(self.allocated_bytes()?)?;
        // All unbound siblings become locals after credit, so failure frees
        // them before returning their shared charge to concurrent waiters.
        let Self {
            origin,
            source_tag,
            source_aad,
            iv,
            tag,
            aad,
            expected_tag,
        } = self;
        let mut iv = iv.bind(&mut credit)?;
        let mut tag = tag.bind(&mut credit)?;
        let mut aad = aad.bind(&mut credit)?;
        let mut expected_tag = expected_tag
            .map(|value| value.bind(&mut credit))
            .transpose()?;
        iv.as_mut().copy_from_slice(origin.iv());
        aad.as_mut().copy_from_slice(source_aad);
        if let (Some(expected), Some(source)) = (&mut expected_tag, source_tag) {
            expected.as_mut().copy_from_slice(source);
            tag.as_mut().copy_from_slice(source);
        }
        // Validate the capacity the Buffer actually exposes, not the requested
        // allocation size or a cast made later while the native frame is armed.
        let iv_len = crate::bounds::ck_length(iv.capacity())?;
        let aad_len = crate::bounds::ck_length(aad.capacity())?;
        Ok(GcmBuffers {
            iv,
            tag,
            aad,
            origin: origin.clone(),
            expected_tag,
            iv_len,
            aad_len,
            _selection: credit,
        })
    }
}

pub(super) struct GcmBuffers {
    iv: Buffer,
    tag: Buffer,
    aad: Buffer,
    origin: AeadNonce,
    expected_tag: Option<Buffer>,
    iv_len: CK_ULONG,
    aad_len: CK_ULONG,
    _selection: crate::symmetric::memory::Credit,
}
impl GcmBuffers {
    pub(super) fn nonce(&self) -> &[u8] {
        self.iv.as_slice()
    }
    pub(super) fn tag(&self) -> &[u8] {
        self.tag.as_slice()
    }
    pub(super) fn aad(&self) -> &[u8] {
        self.aad.as_slice()
    }
    pub(super) fn origin(&self) -> AeadNonce {
        self.origin.clone()
    }
    fn generator(&self) -> CK_GENERATOR_FUNCTION {
        self.origin.generator().expect("validated GCM generator")
    }
    pub(super) fn parameters(&mut self) -> (CK_GCM_MESSAGE_PARAMS, CK_BYTE_PTR, CK_ULONG) {
        // Pointers remain valid when this owner moves: the Buffer allocations do
        // not move. The caller owns the descriptor and must keep its address
        // stable for the complete native use (including an uncertain return).
        let params = CK_GCM_MESSAGE_PARAMS {
            pIv: self.iv.as_mut().as_mut_ptr(),
            ulIvLen: self.iv_len,
            ulIvFixedBits: self.origin.fixed_bits() as CK_ULONG,
            ivGenerator: self.generator(),
            pTag: self.tag.as_mut().as_mut_ptr(),
            ulTagBits: self.origin.tag_bits() as CK_ULONG,
        };
        let aad = if self.aad.capacity() == 0 {
            std::ptr::null_mut()
        } else {
            self.aad.as_mut().as_mut_ptr()
        };
        (params, aad, self.aad_len)
    }
    pub(super) fn unchanged(
        &self,
        p: &CK_GCM_MESSAGE_PARAMS,
        m: &CK_MECHANISM,
        pointer: CK_VOID_PTR,
        aad: &[u8],
    ) -> bool {
        m.mechanism == CKM_AES_GCM
            && m.pParameter == pointer
            && m.ulParameterLen == std::mem::size_of::<CK_GCM_MESSAGE_PARAMS>() as CK_ULONG
            && p.pIv == self.iv.as_slice().as_ptr().cast_mut()
            && p.ulIvLen == self.iv_len
            && p.ulIvFixedBits == self.origin.fixed_bits() as CK_ULONG
            && p.ivGenerator == self.generator()
            && p.pTag == self.tag.as_slice().as_ptr().cast_mut()
            && p.ulTagBits == self.origin.tag_bits() as CK_ULONG
            && self.aad.as_slice() == aad
            && self.origin.fixed_bits_unchanged(self.iv.as_slice())
            && (self.origin.generated() || self.iv.as_slice() == self.origin.iv())
            && self
                .expected_tag
                .as_ref()
                .map_or(true, |tag| self.tag.as_slice() == tag.as_slice())
    }
}
