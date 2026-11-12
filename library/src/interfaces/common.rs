// SPDX-License-Identifier: Apache-2.0
//! Aligned Rust view of the common PKCS#11 functions, never passed across the ABI.
use fe11_sys::*;

/// Aligned value projection of the native version header; never passed to C.
#[derive(Clone, Copy)]
pub(crate) struct TableVersion {
    pub(crate) major: CK_BYTE,
    pub(crate) minor: CK_BYTE,
}

/// Field values are copied from the selected exact native layout. In particular,
/// Windows CK_FUNCTION_LIST is packed: borrowing its pointer fields would create
/// unaligned Rust references. This ordinary Rust struct owns aligned copies.
/// When needed, C_GetFunctionList is invoked through its export during loading;
/// its selected-table presence remains in FunctionCatalog.
/// The loaded image must still outlive every function pointer.
#[derive(Clone, Copy)]
// Native names keep the projection and dispatch sites directly comparable to PKCS#11.
#[allow(non_snake_case)]
pub(crate) struct CommonFunctions {
    pub(crate) version: TableVersion,
    pub(crate) C_Initialize: CK_C_Initialize,
    pub(crate) C_Finalize: CK_C_Finalize,
    pub(crate) C_GetInfo: CK_C_GetInfo,
    pub(crate) C_GetSlotList: CK_C_GetSlotList,
    pub(crate) C_GetSlotInfo: CK_C_GetSlotInfo,
    pub(crate) C_GetTokenInfo: CK_C_GetTokenInfo,
    pub(crate) C_GetMechanismList: CK_C_GetMechanismList,
    pub(crate) C_GetMechanismInfo: CK_C_GetMechanismInfo,
    pub(crate) C_InitToken: CK_C_InitToken,
    pub(crate) C_InitPIN: CK_C_InitPIN,
    pub(crate) C_SetPIN: CK_C_SetPIN,
    pub(crate) C_OpenSession: CK_C_OpenSession,
    pub(crate) C_CloseSession: CK_C_CloseSession,
    pub(crate) C_CloseAllSessions: CK_C_CloseAllSessions,
    pub(crate) C_GetSessionInfo: CK_C_GetSessionInfo,
    pub(crate) C_GetOperationState: CK_C_GetOperationState,
    pub(crate) C_SetOperationState: CK_C_SetOperationState,
    pub(crate) C_Login: CK_C_Login,
    pub(crate) C_Logout: CK_C_Logout,
    pub(crate) C_CreateObject: CK_C_CreateObject,
    pub(crate) C_CopyObject: CK_C_CopyObject,
    pub(crate) C_DestroyObject: CK_C_DestroyObject,
    pub(crate) C_GetObjectSize: CK_C_GetObjectSize,
    pub(crate) C_GetAttributeValue: CK_C_GetAttributeValue,
    pub(crate) C_SetAttributeValue: CK_C_SetAttributeValue,
    pub(crate) C_FindObjectsInit: CK_C_FindObjectsInit,
    pub(crate) C_FindObjects: CK_C_FindObjects,
    pub(crate) C_FindObjectsFinal: CK_C_FindObjectsFinal,
    pub(crate) C_EncryptInit: CK_C_EncryptInit,
    pub(crate) C_Encrypt: CK_C_Encrypt,
    pub(crate) C_EncryptUpdate: CK_C_EncryptUpdate,
    pub(crate) C_EncryptFinal: CK_C_EncryptFinal,
    pub(crate) C_DecryptInit: CK_C_DecryptInit,
    pub(crate) C_Decrypt: CK_C_Decrypt,
    pub(crate) C_DecryptUpdate: CK_C_DecryptUpdate,
    pub(crate) C_DecryptFinal: CK_C_DecryptFinal,
    pub(crate) C_DigestInit: CK_C_DigestInit,
    pub(crate) C_Digest: CK_C_Digest,
    pub(crate) C_DigestUpdate: CK_C_DigestUpdate,
    pub(crate) C_DigestKey: CK_C_DigestKey,
    pub(crate) C_DigestFinal: CK_C_DigestFinal,
    pub(crate) C_SignInit: CK_C_SignInit,
    pub(crate) C_Sign: CK_C_Sign,
    pub(crate) C_SignUpdate: CK_C_SignUpdate,
    pub(crate) C_SignFinal: CK_C_SignFinal,
    pub(crate) C_SignRecoverInit: CK_C_SignRecoverInit,
    pub(crate) C_SignRecover: CK_C_SignRecover,
    pub(crate) C_VerifyInit: CK_C_VerifyInit,
    pub(crate) C_Verify: CK_C_Verify,
    pub(crate) C_VerifyUpdate: CK_C_VerifyUpdate,
    pub(crate) C_VerifyFinal: CK_C_VerifyFinal,
    pub(crate) C_VerifyRecoverInit: CK_C_VerifyRecoverInit,
    pub(crate) C_VerifyRecover: CK_C_VerifyRecover,
    pub(crate) C_DigestEncryptUpdate: CK_C_DigestEncryptUpdate,
    pub(crate) C_DecryptDigestUpdate: CK_C_DecryptDigestUpdate,
    pub(crate) C_SignEncryptUpdate: CK_C_SignEncryptUpdate,
    pub(crate) C_DecryptVerifyUpdate: CK_C_DecryptVerifyUpdate,
    pub(crate) C_GenerateKey: CK_C_GenerateKey,
    pub(crate) C_GenerateKeyPair: CK_C_GenerateKeyPair,
    pub(crate) C_WrapKey: CK_C_WrapKey,
    pub(crate) C_UnwrapKey: CK_C_UnwrapKey,
    pub(crate) C_DeriveKey: CK_C_DeriveKey,
    pub(crate) C_SeedRandom: CK_C_SeedRandom,
    pub(crate) C_GenerateRandom: CK_C_GenerateRandom,
    pub(crate) C_GetFunctionStatus: CK_C_GetFunctionStatus,
    pub(crate) C_CancelFunction: CK_C_CancelFunction,
    pub(crate) C_WaitForSlotEvent: CK_C_WaitForSlotEvent,
}
