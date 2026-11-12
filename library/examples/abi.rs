// SPDX-License-Identifier: Apache-2.0
use fe11_sys::*;
fn main() {
    println!(
        "CK_ULONG {} {}",
        std::mem::size_of::<CK_ULONG>(),
        std::mem::align_of::<CK_ULONG>()
    );
    println!(
        "CK_BBOOL {} {}",
        std::mem::size_of::<CK_BBOOL>(),
        std::mem::align_of::<CK_BBOOL>()
    );
    println!(
        "CK_SLOT_ID {} {}",
        std::mem::size_of::<CK_SLOT_ID>(),
        std::mem::align_of::<CK_SLOT_ID>()
    );
    println!(
        "CK_SESSION_HANDLE {} {}",
        std::mem::size_of::<CK_SESSION_HANDLE>(),
        std::mem::align_of::<CK_SESSION_HANDLE>()
    );
    println!(
        "CK_OBJECT_HANDLE {} {}",
        std::mem::size_of::<CK_OBJECT_HANDLE>(),
        std::mem::align_of::<CK_OBJECT_HANDLE>()
    );
    println!(
        "CK_VERSION {} {}",
        std::mem::size_of::<CK_VERSION>(),
        std::mem::align_of::<CK_VERSION>()
    );
    println!(
        "CK_INFO {} {}",
        std::mem::size_of::<CK_INFO>(),
        std::mem::align_of::<CK_INFO>()
    );
    println!(
        "CK_SLOT_INFO {} {}",
        std::mem::size_of::<CK_SLOT_INFO>(),
        std::mem::align_of::<CK_SLOT_INFO>()
    );
    println!(
        "CK_TOKEN_INFO {} {}",
        std::mem::size_of::<CK_TOKEN_INFO>(),
        std::mem::align_of::<CK_TOKEN_INFO>()
    );
    println!(
        "CK_SESSION_INFO {} {}",
        std::mem::size_of::<CK_SESSION_INFO>(),
        std::mem::align_of::<CK_SESSION_INFO>()
    );
    println!(
        "CK_ATTRIBUTE {} {}",
        std::mem::size_of::<CK_ATTRIBUTE>(),
        std::mem::align_of::<CK_ATTRIBUTE>()
    );
    println!(
        "CK_MECHANISM {} {}",
        std::mem::size_of::<CK_MECHANISM>(),
        std::mem::align_of::<CK_MECHANISM>()
    );
    println!(
        "CK_RSA_PKCS_PSS_PARAMS {} {}",
        std::mem::size_of::<CK_RSA_PKCS_PSS_PARAMS>(),
        std::mem::align_of::<CK_RSA_PKCS_PSS_PARAMS>()
    );
    println!(
        "CK_MECHANISM_INFO {} {}",
        std::mem::size_of::<CK_MECHANISM_INFO>(),
        std::mem::align_of::<CK_MECHANISM_INFO>()
    );
    println!(
        "CK_C_INITIALIZE_ARGS {} {}",
        std::mem::size_of::<CK_C_INITIALIZE_ARGS>(),
        std::mem::align_of::<CK_C_INITIALIZE_ARGS>()
    );
    println!(
        "CK_FUNCTION_LIST {} {}",
        std::mem::size_of::<CK_FUNCTION_LIST>(),
        std::mem::align_of::<CK_FUNCTION_LIST>()
    );
    println!(
        "CK_VERSION.major {}",
        std::mem::offset_of!(CK_VERSION, major)
    );
    println!(
        "CK_VERSION.minor {}",
        std::mem::offset_of!(CK_VERSION, minor)
    );
    println!(
        "CK_INFO.cryptokiVersion {}",
        std::mem::offset_of!(CK_INFO, cryptokiVersion)
    );
    println!(
        "CK_INFO.manufacturerID {}",
        std::mem::offset_of!(CK_INFO, manufacturerID)
    );
    println!("CK_INFO.flags {}", std::mem::offset_of!(CK_INFO, flags));
    println!(
        "CK_INFO.libraryDescription {}",
        std::mem::offset_of!(CK_INFO, libraryDescription)
    );
    println!(
        "CK_INFO.libraryVersion {}",
        std::mem::offset_of!(CK_INFO, libraryVersion)
    );
    println!(
        "CK_SLOT_INFO.slotDescription {}",
        std::mem::offset_of!(CK_SLOT_INFO, slotDescription)
    );
    println!(
        "CK_SLOT_INFO.manufacturerID {}",
        std::mem::offset_of!(CK_SLOT_INFO, manufacturerID)
    );
    println!(
        "CK_SLOT_INFO.flags {}",
        std::mem::offset_of!(CK_SLOT_INFO, flags)
    );
    println!(
        "CK_SLOT_INFO.hardwareVersion {}",
        std::mem::offset_of!(CK_SLOT_INFO, hardwareVersion)
    );
    println!(
        "CK_SLOT_INFO.firmwareVersion {}",
        std::mem::offset_of!(CK_SLOT_INFO, firmwareVersion)
    );
    println!(
        "CK_TOKEN_INFO.label {}",
        std::mem::offset_of!(CK_TOKEN_INFO, label)
    );
    println!(
        "CK_TOKEN_INFO.manufacturerID {}",
        std::mem::offset_of!(CK_TOKEN_INFO, manufacturerID)
    );
    println!(
        "CK_TOKEN_INFO.model {}",
        std::mem::offset_of!(CK_TOKEN_INFO, model)
    );
    println!(
        "CK_TOKEN_INFO.serialNumber {}",
        std::mem::offset_of!(CK_TOKEN_INFO, serialNumber)
    );
    println!(
        "CK_TOKEN_INFO.flags {}",
        std::mem::offset_of!(CK_TOKEN_INFO, flags)
    );
    println!(
        "CK_TOKEN_INFO.ulMaxSessionCount {}",
        std::mem::offset_of!(CK_TOKEN_INFO, ulMaxSessionCount)
    );
    println!(
        "CK_TOKEN_INFO.ulSessionCount {}",
        std::mem::offset_of!(CK_TOKEN_INFO, ulSessionCount)
    );
    println!(
        "CK_TOKEN_INFO.ulMaxRwSessionCount {}",
        std::mem::offset_of!(CK_TOKEN_INFO, ulMaxRwSessionCount)
    );
    println!(
        "CK_TOKEN_INFO.ulRwSessionCount {}",
        std::mem::offset_of!(CK_TOKEN_INFO, ulRwSessionCount)
    );
    println!(
        "CK_TOKEN_INFO.ulMaxPinLen {}",
        std::mem::offset_of!(CK_TOKEN_INFO, ulMaxPinLen)
    );
    println!(
        "CK_TOKEN_INFO.ulMinPinLen {}",
        std::mem::offset_of!(CK_TOKEN_INFO, ulMinPinLen)
    );
    println!(
        "CK_TOKEN_INFO.ulTotalPublicMemory {}",
        std::mem::offset_of!(CK_TOKEN_INFO, ulTotalPublicMemory)
    );
    println!(
        "CK_TOKEN_INFO.ulFreePublicMemory {}",
        std::mem::offset_of!(CK_TOKEN_INFO, ulFreePublicMemory)
    );
    println!(
        "CK_TOKEN_INFO.ulTotalPrivateMemory {}",
        std::mem::offset_of!(CK_TOKEN_INFO, ulTotalPrivateMemory)
    );
    println!(
        "CK_TOKEN_INFO.ulFreePrivateMemory {}",
        std::mem::offset_of!(CK_TOKEN_INFO, ulFreePrivateMemory)
    );
    println!(
        "CK_TOKEN_INFO.hardwareVersion {}",
        std::mem::offset_of!(CK_TOKEN_INFO, hardwareVersion)
    );
    println!(
        "CK_TOKEN_INFO.firmwareVersion {}",
        std::mem::offset_of!(CK_TOKEN_INFO, firmwareVersion)
    );
    println!(
        "CK_TOKEN_INFO.utcTime {}",
        std::mem::offset_of!(CK_TOKEN_INFO, utcTime)
    );
    println!(
        "CK_SESSION_INFO.slotID {}",
        std::mem::offset_of!(CK_SESSION_INFO, slotID)
    );
    println!(
        "CK_SESSION_INFO.state {}",
        std::mem::offset_of!(CK_SESSION_INFO, state)
    );
    println!(
        "CK_SESSION_INFO.flags {}",
        std::mem::offset_of!(CK_SESSION_INFO, flags)
    );
    println!(
        "CK_SESSION_INFO.ulDeviceError {}",
        std::mem::offset_of!(CK_SESSION_INFO, ulDeviceError)
    );
    println!(
        "CK_ATTRIBUTE.type {}",
        std::mem::offset_of!(CK_ATTRIBUTE, r#type)
    );
    println!(
        "CK_ATTRIBUTE.pValue {}",
        std::mem::offset_of!(CK_ATTRIBUTE, pValue)
    );
    println!(
        "CK_ATTRIBUTE.ulValueLen {}",
        std::mem::offset_of!(CK_ATTRIBUTE, ulValueLen)
    );
    println!(
        "CK_MECHANISM.mechanism {}",
        std::mem::offset_of!(CK_MECHANISM, mechanism)
    );
    println!(
        "CK_MECHANISM.pParameter {}",
        std::mem::offset_of!(CK_MECHANISM, pParameter)
    );
    println!(
        "CK_MECHANISM.ulParameterLen {}",
        std::mem::offset_of!(CK_MECHANISM, ulParameterLen)
    );
    println!(
        "CK_RSA_PKCS_PSS_PARAMS.hashAlg {}",
        std::mem::offset_of!(CK_RSA_PKCS_PSS_PARAMS, hashAlg)
    );
    println!(
        "CK_RSA_PKCS_PSS_PARAMS.mgf {}",
        std::mem::offset_of!(CK_RSA_PKCS_PSS_PARAMS, mgf)
    );
    println!(
        "CK_RSA_PKCS_PSS_PARAMS.sLen {}",
        std::mem::offset_of!(CK_RSA_PKCS_PSS_PARAMS, sLen)
    );
    println!(
        "CK_MECHANISM_INFO.ulMinKeySize {}",
        std::mem::offset_of!(CK_MECHANISM_INFO, ulMinKeySize)
    );
    println!(
        "CK_MECHANISM_INFO.ulMaxKeySize {}",
        std::mem::offset_of!(CK_MECHANISM_INFO, ulMaxKeySize)
    );
    println!(
        "CK_MECHANISM_INFO.flags {}",
        std::mem::offset_of!(CK_MECHANISM_INFO, flags)
    );
    println!(
        "CK_C_INITIALIZE_ARGS.CreateMutex {}",
        std::mem::offset_of!(CK_C_INITIALIZE_ARGS, CreateMutex)
    );
    println!(
        "CK_C_INITIALIZE_ARGS.DestroyMutex {}",
        std::mem::offset_of!(CK_C_INITIALIZE_ARGS, DestroyMutex)
    );
    println!(
        "CK_C_INITIALIZE_ARGS.LockMutex {}",
        std::mem::offset_of!(CK_C_INITIALIZE_ARGS, LockMutex)
    );
    println!(
        "CK_C_INITIALIZE_ARGS.UnlockMutex {}",
        std::mem::offset_of!(CK_C_INITIALIZE_ARGS, UnlockMutex)
    );
    println!(
        "CK_C_INITIALIZE_ARGS.flags {}",
        std::mem::offset_of!(CK_C_INITIALIZE_ARGS, flags)
    );
    println!(
        "CK_C_INITIALIZE_ARGS.pReserved {}",
        std::mem::offset_of!(CK_C_INITIALIZE_ARGS, pReserved)
    );
    println!(
        "CK_FUNCTION_LIST.version {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, version)
    );
    println!(
        "CK_FUNCTION_LIST.C_Initialize {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_Initialize)
    );
    println!(
        "CK_FUNCTION_LIST.C_Finalize {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_Finalize)
    );
    println!(
        "CK_FUNCTION_LIST.C_GetInfo {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_GetInfo)
    );
    println!(
        "CK_FUNCTION_LIST.C_GetFunctionList {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_GetFunctionList)
    );
    println!(
        "CK_FUNCTION_LIST.C_GetSlotList {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_GetSlotList)
    );
    println!(
        "CK_FUNCTION_LIST.C_GetSlotInfo {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_GetSlotInfo)
    );
    println!(
        "CK_FUNCTION_LIST.C_GetTokenInfo {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_GetTokenInfo)
    );
    println!(
        "CK_FUNCTION_LIST.C_GetMechanismList {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_GetMechanismList)
    );
    println!(
        "CK_FUNCTION_LIST.C_GetMechanismInfo {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_GetMechanismInfo)
    );
    println!(
        "CK_FUNCTION_LIST.C_InitToken {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_InitToken)
    );
    println!(
        "CK_FUNCTION_LIST.C_InitPIN {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_InitPIN)
    );
    println!(
        "CK_FUNCTION_LIST.C_OpenSession {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_OpenSession)
    );
    println!(
        "CK_FUNCTION_LIST.C_CloseSession {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_CloseSession)
    );
    println!(
        "CK_FUNCTION_LIST.C_GetSessionInfo {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_GetSessionInfo)
    );
    println!(
        "CK_FUNCTION_LIST.C_Login {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_Login)
    );
    println!(
        "CK_FUNCTION_LIST.C_Logout {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_Logout)
    );
    println!(
        "CK_FUNCTION_LIST.C_CreateObject {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_CreateObject)
    );
    println!(
        "CK_FUNCTION_LIST.C_GetAttributeValue {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_GetAttributeValue)
    );
    println!(
        "CK_FUNCTION_LIST.C_SetAttributeValue {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_SetAttributeValue)
    );
    println!(
        "CK_FUNCTION_LIST.C_DestroyObject {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_DestroyObject)
    );
    println!(
        "CK_FUNCTION_LIST.C_GenerateKeyPair {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_GenerateKeyPair)
    );
    println!(
        "CK_FUNCTION_LIST.C_FindObjectsInit {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_FindObjectsInit)
    );
    println!(
        "CK_FUNCTION_LIST.C_FindObjects {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_FindObjects)
    );
    println!(
        "CK_FUNCTION_LIST.C_FindObjectsFinal {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_FindObjectsFinal)
    );
    println!(
        "CK_FUNCTION_LIST.C_SignInit {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_SignInit)
    );
    println!(
        "CK_FUNCTION_LIST.C_Sign {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_Sign)
    );
    println!(
        "CK_FUNCTION_LIST.C_VerifyInit {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_VerifyInit)
    );
    println!(
        "CK_FUNCTION_LIST.C_Verify {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_Verify)
    );
    println!(
        "CK_RSA_PKCS_OAEP_PARAMS {} {}",
        std::mem::size_of::<CK_RSA_PKCS_OAEP_PARAMS>(),
        std::mem::align_of::<CK_RSA_PKCS_OAEP_PARAMS>()
    );
    println!(
        "CK_RSA_PKCS_OAEP_PARAMS.hashAlg {}",
        std::mem::offset_of!(CK_RSA_PKCS_OAEP_PARAMS, hashAlg)
    );
    println!(
        "CK_RSA_PKCS_OAEP_PARAMS.mgf {}",
        std::mem::offset_of!(CK_RSA_PKCS_OAEP_PARAMS, mgf)
    );
    println!(
        "CK_RSA_PKCS_OAEP_PARAMS.source {}",
        std::mem::offset_of!(CK_RSA_PKCS_OAEP_PARAMS, source)
    );
    println!(
        "CK_RSA_PKCS_OAEP_PARAMS.pSourceData {}",
        std::mem::offset_of!(CK_RSA_PKCS_OAEP_PARAMS, pSourceData)
    );
    println!(
        "CK_RSA_PKCS_OAEP_PARAMS.ulSourceDataLen {}",
        std::mem::offset_of!(CK_RSA_PKCS_OAEP_PARAMS, ulSourceDataLen)
    );
    println!(
        "CK_FUNCTION_LIST.C_EncryptInit {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_EncryptInit)
    );
    println!(
        "CK_FUNCTION_LIST.C_Encrypt {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_Encrypt)
    );
    println!(
        "CK_FUNCTION_LIST.C_DecryptInit {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_DecryptInit)
    );
    println!(
        "CK_FUNCTION_LIST.C_Decrypt {}",
        std::mem::offset_of!(CK_FUNCTION_LIST, C_Decrypt)
    );
}
