// SPDX-License-Identifier: Apache-2.0
//! Version-one wire codes, not PKCS#11 function ordinals. Never reorder.
use super::{Reader, Writer};
use crate::{Error, Result};

const NAMES: &[&str] = &[
    "C_DigestInit",
    "C_Digest",
    "C_DigestUpdate",
    "C_DigestFinal",
    "C_MessageEncryptInit",
    "C_EncryptMessage",
    "C_EncryptMessageBegin",
    "C_EncryptMessageNext",
    "C_MessageEncryptFinal",
    "C_MessageDecryptInit",
    "C_DecryptMessage",
    "C_DecryptMessageBegin",
    "C_DecryptMessageNext",
    "C_MessageDecryptFinal",
    "C_MessageSignInit",
    "C_SignMessage",
    "C_SignMessageBegin",
    "C_SignMessageNext",
    "C_MessageSignFinal",
    "C_MessageVerifyInit",
    "C_VerifyMessage",
    "C_VerifyMessageBegin",
    "C_VerifyMessageNext",
    "C_MessageVerifyFinal",
    "C_SignInit",
    "C_Sign",
    "C_SignFinal",
    "C_VerifyInit",
    "C_VerifyUpdate",
    "C_VerifyFinal",
    "C_EncryptInit",
    "C_EncryptFinal",
    "C_DecryptInit",
    "C_DecryptFinal",
    "C_DigestEncryptUpdate",
    "C_DecryptDigestUpdate",
    "C_SignEncryptUpdate",
    "C_DecryptVerifyUpdate",
    "C_FindObjectsInit",
    "C_FindObjects",
    "C_FindObjectsFinal",
    "C_GetAttributeValue",
    "C_GenerateRandom",
    "C_GenerateKey",
    "C_GenerateKeyPair",
    "C_DestroyObject",
    "C_GetSessionInfo",
    "C_GetOperationState",
    "C_SetOperationState",
    "C_GetSessionValidationFlags",
    "C_SignRecoverInit",
    "C_SignRecover",
    "C_VerifyRecoverInit",
    "C_VerifyRecover",
    "C_Encrypt",
    "C_EncryptUpdate",
    "C_Decrypt",
    "C_DecryptUpdate",
    "C_SignUpdate",
    "C_Verify",
    "C_VerifySignatureInit",
    "C_VerifySignature",
    "C_VerifySignatureUpdate",
    "C_VerifySignatureFinal",
];
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::advanced) struct Function(u16);
impl Function {
    pub(in crate::advanced) fn from_name(name: &str) -> Result<Self> {
        let index = NAMES
            .iter()
            .position(|n| *n == name)
            .ok_or(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::AsynchronousFunctionIdentity,
            )))?;
        Ok(Self(u16::try_from(index + 1).map_err(|_| {
            Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordFunctionCode,
            ))
        })?))
    }
    pub(in crate::advanced) fn write_phase(self, w: &mut Writer<'_>) -> Result<()> {
        w.u8(u8::try_from(self.0).map_err(|_| {
            Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordPhaseCode,
            ))
        })?)
    }
    pub(in crate::advanced) fn read_phase(r: &mut Reader<'_>) -> Result<Self> {
        let code = u16::from(r.u8()?);
        if code == 0 || usize::from(code) > NAMES.len() {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordPhaseCode,
            )));
        }
        Ok(Self(code))
    }
    pub(in crate::advanced) fn name(self) -> &'static str {
        NAMES[usize::from(self.0) - 1]
    }
    pub(in crate::advanced) fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        writer.u16(self.0)
    }
    pub(in crate::advanced) fn read(reader: &mut Reader<'_>) -> Result<Self> {
        let code = reader.u16()?;
        if code == 0 || usize::from(code) > NAMES.len() {
            return Err(Error::Rejected(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::RecordFunctionCode,
            )));
        }
        Ok(Self(code))
    }
}
