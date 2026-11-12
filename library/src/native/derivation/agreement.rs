// SPDX-License-Identifier: Apache-2.0
//! Exact two-pair agreement layouts; never infer a native private-key length.
use super::*;
use crate::{NativeMqvLayout, NativeTwoPairAgreement};

pub(super) enum Layout {
    EcTwo,
    EcMqv,
    DhTwo,
    DhMqv,
}
enum Raw {
    EcTwo(CK_ECDH2_DERIVE_PARAMS),
    EcMqv(CK_ECMQV_DERIVE_PARAMS),
    DhTwo(CK_X9_42_DH2_DERIVE_PARAMS),
    DhMqv(CK_X9_42_MQV_DERIVE_PARAMS),
}
pub(super) struct Agreement {
    raw: Raw,
    kdf: CK_ULONG,
    private: CK_OBJECT_HANDLE,
    private_bytes: CK_ULONG,
    public_key: CK_OBJECT_HANDLE,
    first: InputBytes,
    second: InputBytes,
    context: Option<InputBytes>,
}
pub(super) struct AgreementStorage<'a> {
    layout: Layout,
    kdf: CK_ULONG,
    private: CK_OBJECT_HANDLE,
    private_bytes: CK_ULONG,
    public_key: CK_OBJECT_HANDLE,
    first: (&'a [u8], InputBytesStorage),
    second: (&'a [u8], InputBytesStorage),
    context: Option<(&'a [u8], InputBytesStorage)>,
}
impl<'a> AgreementStorage<'a> {
    pub(super) fn allocate(
        input: &NativeTwoPairAgreement<'a>,
        layout: Layout,
        public_key: Option<&crate::NativeObjectRef>,
    ) -> Result<Self> {
        Agreement::payload_bytes(input)?;
        Ok(Self {
            layout,
            kdf: native_ulong(input.kdf)?,
            private: input.private_second.identity.handle,
            private_bytes: native_ulong(input.private_second_bytes)?,
            public_key: public_key.map_or(CK_INVALID_HANDLE, |key| key.identity.handle),
            first: (
                input.peer_public,
                InputBytesStorage::allocate(input.peer_public.len())?,
            ),
            second: (
                input.peer_public_second,
                InputBytesStorage::allocate(input.peer_public_second.len())?,
            ),
            context: input
                .context
                .map(|input| Ok::<_, Error>((input, InputBytesStorage::allocate(input.len())?)))
                .transpose()?,
        })
    }
    pub(super) fn mqv(
        input: &NativeTwoPairAgreement<'a>,
        layout: &NativeMqvLayout<'_>,
        ec: bool,
    ) -> Result<Self> {
        let (layout, public) = match (ec, layout) {
            (true, NativeMqvLayout::TwoPair) => (Layout::EcTwo, None),
            (true, NativeMqvLayout::WithPublicKey(key)) => (Layout::EcMqv, Some(*key)),
            (false, NativeMqvLayout::TwoPair) => (Layout::DhTwo, None),
            (false, NativeMqvLayout::WithPublicKey(key)) => (Layout::DhMqv, Some(*key)),
        };
        Self::allocate(input, layout, public)
    }
    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        let context = self
            .context
            .as_ref()
            .map(|(_, storage)| storage.allocated_bytes())
            .transpose()?
            .unwrap_or(0);
        self.first
            .1
            .allocated_bytes()?
            .checked_add(self.second.1.allocated_bytes()?)
            .and_then(|n| n.checked_add(context))
            .ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::TwoPairAgreementStorageAccounting,
            )))
    }
    pub(super) fn bind(self, credit: &mut Credit) -> Result<Agreement> {
        Agreement::from_owned_parts(
            self.layout,
            self.kdf,
            self.private,
            self.private_bytes,
            self.public_key,
            self.first.1.bind(self.first.0, credit)?,
            self.second.1.bind(self.second.0, credit)?,
            self.context
                .map(|(input, storage)| storage.bind(input, credit))
                .transpose()?,
        )
    }
}
impl Agreement {
    pub(super) fn payload_bytes(input: &NativeTwoPairAgreement<'_>) -> Result<usize> {
        native_ulong(input.kdf)?;
        native_ulong(input.private_second_bytes)?;
        [
            input.peer_public.len(),
            input.peer_public_second.len(),
            input.context.map_or(0, |v| v.len()),
        ]
        .into_iter()
        .try_fold(0usize, |n, len| {
            bounds::ck_length(len)?;
            len.checked_mul(2)
                .and_then(|v| n.checked_add(v))
                .ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
                    crate::NativeDerivationRejection::TwoPairAgreementStorageAccounting,
                )))
        })
    }

    fn from_owned_parts(
        layout: Layout,
        kdf: CK_ULONG,
        private: CK_OBJECT_HANDLE,
        private_bytes: CK_ULONG,
        public_key: CK_OBJECT_HANDLE,
        mut first: InputBytes,
        mut second: InputBytes,
        mut context: Option<InputBytes>,
    ) -> Result<Self> {
        let raw = match layout {
            Layout::EcTwo => Raw::EcTwo(CK_ECDH2_DERIVE_PARAMS {
                kdf,
                ulSharedDataLen: optional_length(&context),
                pSharedData: optional_pointer(&mut context),
                ulPublicDataLen: first.length(),
                pPublicData: first.pointer(),
                ulPrivateDataLen: private_bytes,
                hPrivateData: private,
                ulPublicDataLen2: second.length(),
                pPublicData2: second.pointer(),
            }),
            Layout::EcMqv => Raw::EcMqv(CK_ECMQV_DERIVE_PARAMS {
                kdf,
                ulSharedDataLen: optional_length(&context),
                pSharedData: optional_pointer(&mut context),
                ulPublicDataLen: first.length(),
                pPublicData: first.pointer(),
                ulPrivateDataLen: private_bytes,
                hPrivateData: private,
                ulPublicDataLen2: second.length(),
                pPublicData2: second.pointer(),
                publicKey: public_key,
            }),
            Layout::DhTwo => Raw::DhTwo(CK_X9_42_DH2_DERIVE_PARAMS {
                kdf,
                ulOtherInfoLen: optional_length(&context),
                pOtherInfo: optional_pointer(&mut context),
                ulPublicDataLen: first.length(),
                pPublicData: first.pointer(),
                ulPrivateDataLen: private_bytes,
                hPrivateData: private,
                ulPublicDataLen2: second.length(),
                pPublicData2: second.pointer(),
            }),
            Layout::DhMqv => Raw::DhMqv(CK_X9_42_MQV_DERIVE_PARAMS {
                kdf,
                ulOtherInfoLen: optional_length(&context),
                pOtherInfo: optional_pointer(&mut context),
                ulPublicDataLen: first.length(),
                pPublicData: first.pointer(),
                ulPrivateDataLen: private_bytes,
                hPrivateData: private,
                ulPublicDataLen2: second.length(),
                pPublicData2: second.pointer(),
                publicKey: public_key,
            }),
        };
        Ok(Self {
            raw,
            kdf,
            private,
            private_bytes,
            public_key,
            first,
            second,
            context,
        })
    }
    pub(super) fn projection(&mut self) -> (CK_VOID_PTR, CK_ULONG) {
        match &mut self.raw {
            Raw::EcTwo(raw) => (
                (raw as *mut CK_ECDH2_DERIVE_PARAMS).cast(),
                size_of::<CK_ECDH2_DERIVE_PARAMS>() as CK_ULONG,
            ),
            Raw::EcMqv(raw) => (
                (raw as *mut CK_ECMQV_DERIVE_PARAMS).cast(),
                size_of::<CK_ECMQV_DERIVE_PARAMS>() as CK_ULONG,
            ),
            Raw::DhTwo(raw) => (
                (raw as *mut CK_X9_42_DH2_DERIVE_PARAMS).cast(),
                size_of::<CK_X9_42_DH2_DERIVE_PARAMS>() as CK_ULONG,
            ),
            Raw::DhMqv(raw) => (
                (raw as *mut CK_X9_42_MQV_DERIVE_PARAMS).cast(),
                size_of::<CK_X9_42_MQV_DERIVE_PARAMS>() as CK_ULONG,
            ),
        }
    }

    pub(super) fn unchanged(&self) -> bool {
        let bytes =
            self.first.unchanged() & self.second.unchanged() & optional_unchanged(&self.context);
        bytes
            && match &self.raw {
                Raw::EcTwo(raw) => {
                    raw.kdf == self.kdf
                        && raw.ulSharedDataLen == optional_length(&self.context)
                        && raw.pSharedData == optional_expected_pointer(&self.context)
                        && raw.ulPublicDataLen == self.first.length()
                        && raw.pPublicData == self.first.expected_pointer()
                        && raw.ulPrivateDataLen == self.private_bytes
                        && raw.hPrivateData == self.private
                        && raw.ulPublicDataLen2 == self.second.length()
                        && raw.pPublicData2 == self.second.expected_pointer()
                }
                Raw::EcMqv(raw) => {
                    raw.kdf == self.kdf
                        && raw.ulSharedDataLen == optional_length(&self.context)
                        && raw.pSharedData == optional_expected_pointer(&self.context)
                        && raw.ulPublicDataLen == self.first.length()
                        && raw.pPublicData == self.first.expected_pointer()
                        && raw.ulPrivateDataLen == self.private_bytes
                        && raw.hPrivateData == self.private
                        && raw.ulPublicDataLen2 == self.second.length()
                        && raw.pPublicData2 == self.second.expected_pointer()
                        && raw.publicKey == self.public_key
                }
                Raw::DhTwo(raw) => {
                    raw.kdf == self.kdf
                        && raw.ulOtherInfoLen == optional_length(&self.context)
                        && raw.pOtherInfo == optional_expected_pointer(&self.context)
                        && raw.ulPublicDataLen == self.first.length()
                        && raw.pPublicData == self.first.expected_pointer()
                        && raw.ulPrivateDataLen == self.private_bytes
                        && raw.hPrivateData == self.private
                        && raw.ulPublicDataLen2 == self.second.length()
                        && raw.pPublicData2 == self.second.expected_pointer()
                }
                Raw::DhMqv(raw) => {
                    raw.kdf == self.kdf
                        && raw.ulOtherInfoLen == optional_length(&self.context)
                        && raw.pOtherInfo == optional_expected_pointer(&self.context)
                        && raw.ulPublicDataLen == self.first.length()
                        && raw.pPublicData == self.first.expected_pointer()
                        && raw.ulPrivateDataLen == self.private_bytes
                        && raw.hPrivateData == self.private
                        && raw.ulPublicDataLen2 == self.second.length()
                        && raw.pPublicData2 == self.second.expected_pointer()
                        && raw.publicKey == self.public_key
                }
            }
    }
}
