// SPDX-License-Identifier: Apache-2.0
//! Named PKCS#11 3.2 slots compared without calling them or reading padding.
use fe11_sys::CK_FUNCTION_LIST_3_2;

pub(super) fn compare(
    left: &CK_FUNCTION_LIST_3_2,
    right: &CK_FUNCTION_LIST_3_2,
    listed: &CK_FUNCTION_LIST_3_2,
) -> Vec<(&'static str, bool, bool)> {
    let mut result = Vec::with_capacity(104);
    macro_rules! entry {
        ($name:ident) => {{
            // Function addresses belong to the same loaded image. Null remains
            // distinct from any function; no cast changes the callable signature.
            let a = left.$name.map(|function| function as *const ());
            let b = right.$name.map(|function| function as *const ());
            let c = listed.$name.map(|function| function as *const ());
            result.push((stringify!($name), a == b && b == c, a.is_some()));
        }};
    }
    entry!(C_Initialize);
    entry!(C_Finalize);
    entry!(C_GetInfo);
    entry!(C_GetFunctionList);
    entry!(C_GetSlotList);
    entry!(C_GetSlotInfo);
    entry!(C_GetTokenInfo);
    entry!(C_GetMechanismList);
    entry!(C_GetMechanismInfo);
    entry!(C_InitToken);
    entry!(C_InitPIN);
    entry!(C_SetPIN);
    entry!(C_OpenSession);
    entry!(C_CloseSession);
    entry!(C_CloseAllSessions);
    entry!(C_GetSessionInfo);
    entry!(C_GetOperationState);
    entry!(C_SetOperationState);
    entry!(C_Login);
    entry!(C_Logout);
    entry!(C_CreateObject);
    entry!(C_CopyObject);
    entry!(C_DestroyObject);
    entry!(C_GetObjectSize);
    entry!(C_GetAttributeValue);
    entry!(C_SetAttributeValue);
    entry!(C_FindObjectsInit);
    entry!(C_FindObjects);
    entry!(C_FindObjectsFinal);
    entry!(C_EncryptInit);
    entry!(C_Encrypt);
    entry!(C_EncryptUpdate);
    entry!(C_EncryptFinal);
    entry!(C_DecryptInit);
    entry!(C_Decrypt);
    entry!(C_DecryptUpdate);
    entry!(C_DecryptFinal);
    entry!(C_DigestInit);
    entry!(C_Digest);
    entry!(C_DigestUpdate);
    entry!(C_DigestKey);
    entry!(C_DigestFinal);
    entry!(C_SignInit);
    entry!(C_Sign);
    entry!(C_SignUpdate);
    entry!(C_SignFinal);
    entry!(C_SignRecoverInit);
    entry!(C_SignRecover);
    entry!(C_VerifyInit);
    entry!(C_Verify);
    entry!(C_VerifyUpdate);
    entry!(C_VerifyFinal);
    entry!(C_VerifyRecoverInit);
    entry!(C_VerifyRecover);
    entry!(C_DigestEncryptUpdate);
    entry!(C_DecryptDigestUpdate);
    entry!(C_SignEncryptUpdate);
    entry!(C_DecryptVerifyUpdate);
    entry!(C_GenerateKey);
    entry!(C_GenerateKeyPair);
    entry!(C_WrapKey);
    entry!(C_UnwrapKey);
    entry!(C_DeriveKey);
    entry!(C_SeedRandom);
    entry!(C_GenerateRandom);
    entry!(C_GetFunctionStatus);
    entry!(C_CancelFunction);
    entry!(C_WaitForSlotEvent);
    entry!(C_GetInterfaceList);
    entry!(C_GetInterface);
    entry!(C_LoginUser);
    entry!(C_SessionCancel);
    entry!(C_MessageEncryptInit);
    entry!(C_EncryptMessage);
    entry!(C_EncryptMessageBegin);
    entry!(C_EncryptMessageNext);
    entry!(C_MessageEncryptFinal);
    entry!(C_MessageDecryptInit);
    entry!(C_DecryptMessage);
    entry!(C_DecryptMessageBegin);
    entry!(C_DecryptMessageNext);
    entry!(C_MessageDecryptFinal);
    entry!(C_MessageSignInit);
    entry!(C_SignMessage);
    entry!(C_SignMessageBegin);
    entry!(C_SignMessageNext);
    entry!(C_MessageSignFinal);
    entry!(C_MessageVerifyInit);
    entry!(C_VerifyMessage);
    entry!(C_VerifyMessageBegin);
    entry!(C_VerifyMessageNext);
    entry!(C_MessageVerifyFinal);
    entry!(C_EncapsulateKey);
    entry!(C_DecapsulateKey);
    entry!(C_VerifySignatureInit);
    entry!(C_VerifySignature);
    entry!(C_VerifySignatureUpdate);
    entry!(C_VerifySignatureFinal);
    entry!(C_GetSessionValidationFlags);
    entry!(C_AsyncComplete);
    entry!(C_AsyncGetID);
    entry!(C_AsyncJoin);
    entry!(C_WrapKeyAuthenticated);
    entry!(C_UnwrapKeyAuthenticated);
    result
}
