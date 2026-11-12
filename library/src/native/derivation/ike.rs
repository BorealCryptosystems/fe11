// SPDX-License-Identifier: Apache-2.0
//! Four explicit IKE layouts with retained keys and erased byte inputs.
use super::*;
use crate::NativeIkeDerivation;

#[derive(Clone, Copy)]
enum Layout {
    Plus,
    Prf,
    Ike1,
    Extended,
}

enum Raw {
    Plus(CK_IKE2_PRF_PLUS_DERIVE_PARAMS),
    Prf(CK_IKE_PRF_DERIVE_PARAMS),
    Ike1(CK_IKE1_PRF_DERIVE_PARAMS),
    Extended(CK_IKE1_EXTENDED_DERIVE_PARAMS),
}
pub(super) struct Ike {
    raw: Raw,
    prf: CK_MECHANISM_TYPE,
    first_flag: CK_BBOOL,
    second_flag: CK_BBOOL,
    first_key: CK_OBJECT_HANDLE,
    second_key: CK_OBJECT_HANDLE,
    number: u8,
    first: InputBytes,
    second: InputBytes,
}
pub(super) struct IkeStorage<'a> {
    kind: Layout,
    prf: CK_MECHANISM_TYPE,
    first_flag: CK_BBOOL,
    second_flag: CK_BBOOL,
    first_key: CK_OBJECT_HANDLE,
    second_key: CK_OBJECT_HANDLE,
    number: u8,
    first: (&'a [u8], InputBytesStorage),
    second: (&'a [u8], InputBytesStorage),
}
impl<'a> IkeStorage<'a> {
    pub(super) fn allocate(input: &NativeIkeDerivation<'a>) -> Result<Self> {
        Ike::payload_bytes(input)?;
        let (kind, prf, first_flag, second_flag, first_key, second_key, number, first, second) =
            match input {
                NativeIkeDerivation::PrfPlus {
                    prf,
                    seed_key,
                    seed,
                } => (
                    Layout::Plus,
                    *prf,
                    seed_key.is_some(),
                    false,
                    seed_key.map_or(CK_INVALID_HANDLE, |k| k.identity.handle),
                    CK_INVALID_HANDLE,
                    0,
                    *seed,
                    &[][..],
                ),
                NativeIkeDerivation::Prf {
                    prf,
                    data_as_key,
                    new_key,
                    initiator_nonce,
                    responder_nonce,
                } => (
                    Layout::Prf,
                    *prf,
                    *data_as_key,
                    new_key.is_some(),
                    new_key.map_or(CK_INVALID_HANDLE, |k| k.identity.handle),
                    CK_INVALID_HANDLE,
                    0,
                    *initiator_nonce,
                    *responder_nonce,
                ),
                NativeIkeDerivation::Ike1 {
                    prf,
                    shared_key,
                    previous_key,
                    initiator_cookie,
                    responder_cookie,
                    key_number,
                } => (
                    Layout::Ike1,
                    *prf,
                    previous_key.is_some(),
                    false,
                    shared_key.identity.handle,
                    previous_key.map_or(CK_INVALID_HANDLE, |k| k.identity.handle),
                    *key_number,
                    *initiator_cookie,
                    *responder_cookie,
                ),
                NativeIkeDerivation::Ike1Extended {
                    prf,
                    shared_key,
                    extra,
                } => (
                    Layout::Extended,
                    *prf,
                    shared_key.is_some(),
                    false,
                    shared_key.map_or(CK_INVALID_HANDLE, |k| k.identity.handle),
                    CK_INVALID_HANDLE,
                    0,
                    *extra,
                    &[][..],
                ),
            };
        Ok(Self {
            kind,
            prf: native_ulong(prf)?,
            first_flag: CK_BBOOL::from(first_flag),
            second_flag: CK_BBOOL::from(second_flag),
            first_key,
            second_key,
            number,
            first: (first, InputBytesStorage::allocate(first.len())?),
            second: (second, InputBytesStorage::allocate(second.len())?),
        })
    }
    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        self.first
            .1
            .allocated_bytes()?
            .checked_add(self.second.1.allocated_bytes()?)
            .ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::IkeParameterAccounting,
            )))
    }
    pub(super) fn bind(self, credit: &mut Credit) -> Result<Ike> {
        Ike::from_owned_parts(
            self.kind,
            self.prf,
            self.first_flag,
            self.second_flag,
            self.first_key,
            self.second_key,
            self.number,
            self.first.1.bind(self.first.0, credit)?,
            self.second.1.bind(self.second.0, credit)?,
        )
    }
}
impl Ike {
    pub(super) fn payload_bytes(input: &NativeIkeDerivation<'_>) -> Result<usize> {
        let (prf, a, b) = match input {
            NativeIkeDerivation::PrfPlus { prf, seed, .. } => (*prf, seed.len(), 0),
            NativeIkeDerivation::Prf {
                prf,
                initiator_nonce,
                responder_nonce,
                ..
            } => (*prf, initiator_nonce.len(), responder_nonce.len()),
            NativeIkeDerivation::Ike1 {
                prf,
                initiator_cookie,
                responder_cookie,
                ..
            } => (*prf, initiator_cookie.len(), responder_cookie.len()),
            NativeIkeDerivation::Ike1Extended { prf, extra, .. } => (*prf, extra.len(), 0),
        };
        native_ulong(prf)?;
        bounds::ck_length(a)?;
        bounds::ck_length(b)?;
        a.checked_add(b)
            .and_then(|n| n.checked_mul(2))
            .ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::IkeParameterAccounting,
            )))
    }

    fn from_owned_parts(
        kind: Layout,
        prf: CK_MECHANISM_TYPE,
        first_flag: CK_BBOOL,
        second_flag: CK_BBOOL,
        first_key: CK_OBJECT_HANDLE,
        second_key: CK_OBJECT_HANDLE,
        number: u8,
        mut first: InputBytes,
        mut second: InputBytes,
    ) -> Result<Self> {
        let raw = match kind {
            Layout::Plus => Raw::Plus(CK_IKE2_PRF_PLUS_DERIVE_PARAMS {
                prfMechanism: prf,
                bHasSeedKey: first_flag,
                hSeedKey: first_key,
                pSeedData: first.pointer(),
                ulSeedDataLen: first.length(),
            }),
            Layout::Prf => Raw::Prf(CK_IKE_PRF_DERIVE_PARAMS {
                prfMechanism: prf,
                bDataAsKey: first_flag,
                bRekey: second_flag,
                pNi: first.pointer(),
                ulNiLen: first.length(),
                pNr: second.pointer(),
                ulNrLen: second.length(),
                hNewKey: first_key,
            }),
            Layout::Ike1 => Raw::Ike1(CK_IKE1_PRF_DERIVE_PARAMS {
                prfMechanism: prf,
                bHasPrevKey: first_flag,
                hKeygxy: first_key,
                hPrevKey: second_key,
                pCKYi: first.pointer(),
                ulCKYiLen: first.length(),
                pCKYr: second.pointer(),
                ulCKYrLen: second.length(),
                keyNumber: number,
            }),
            Layout::Extended => Raw::Extended(CK_IKE1_EXTENDED_DERIVE_PARAMS {
                prfMechanism: prf,
                bHasKeygxy: first_flag,
                hKeygxy: first_key,
                pExtraData: first.pointer(),
                ulExtraDataLen: first.length(),
            }),
        };
        Ok(Self {
            raw,
            prf,
            first_flag,
            second_flag,
            first_key,
            second_key,
            number,
            first,
            second,
        })
    }
    pub(super) fn projection(&mut self) -> (CK_VOID_PTR, CK_ULONG) {
        match &mut self.raw {
            Raw::Plus(raw) => (
                (raw as *mut CK_IKE2_PRF_PLUS_DERIVE_PARAMS).cast(),
                size_of::<CK_IKE2_PRF_PLUS_DERIVE_PARAMS>() as CK_ULONG,
            ),
            Raw::Prf(raw) => (
                (raw as *mut CK_IKE_PRF_DERIVE_PARAMS).cast(),
                size_of::<CK_IKE_PRF_DERIVE_PARAMS>() as CK_ULONG,
            ),
            Raw::Ike1(raw) => (
                (raw as *mut CK_IKE1_PRF_DERIVE_PARAMS).cast(),
                size_of::<CK_IKE1_PRF_DERIVE_PARAMS>() as CK_ULONG,
            ),
            Raw::Extended(raw) => (
                (raw as *mut CK_IKE1_EXTENDED_DERIVE_PARAMS).cast(),
                size_of::<CK_IKE1_EXTENDED_DERIVE_PARAMS>() as CK_ULONG,
            ),
        }
    }
    pub(super) fn unchanged(&self) -> bool {
        let inputs = self.first.unchanged() & self.second.unchanged();
        inputs
            && match &self.raw {
                Raw::Plus(raw) => {
                    raw.prfMechanism == self.prf
                        && raw.bHasSeedKey == self.first_flag
                        && raw.hSeedKey == self.first_key
                        && raw.pSeedData == self.first.expected_pointer()
                        && raw.ulSeedDataLen == self.first.length()
                }
                Raw::Prf(raw) => {
                    raw.prfMechanism == self.prf
                        && raw.bDataAsKey == self.first_flag
                        && raw.bRekey == self.second_flag
                        && raw.pNi == self.first.expected_pointer()
                        && raw.ulNiLen == self.first.length()
                        && raw.pNr == self.second.expected_pointer()
                        && raw.ulNrLen == self.second.length()
                        && raw.hNewKey == self.first_key
                }
                Raw::Ike1(raw) => {
                    raw.prfMechanism == self.prf
                        && raw.bHasPrevKey == self.first_flag
                        && raw.hKeygxy == self.first_key
                        && raw.hPrevKey == self.second_key
                        && raw.pCKYi == self.first.expected_pointer()
                        && raw.ulCKYiLen == self.first.length()
                        && raw.pCKYr == self.second.expected_pointer()
                        && raw.ulCKYrLen == self.second.length()
                        && raw.keyNumber == self.number
                }
                Raw::Extended(raw) => {
                    raw.prfMechanism == self.prf
                        && raw.bHasKeygxy == self.first_flag
                        && raw.hKeygxy == self.first_key
                        && raw.pExtraData == self.first.expected_pointer()
                        && raw.ulExtraDataLen == self.first.length()
                }
            }
    }
}
