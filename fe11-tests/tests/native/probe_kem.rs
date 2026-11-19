// SPDX-License-Identifier: Apache-2.0
//! ML-KEM availability witnesses for every standardized parameter set.
use super::{
    native_support::{required, status},
    outcome::Failure,
    probe_session::ProbeSession,
    probe_template::Template,
};
use fe11_sys::*;
use std::ptr;
use zeroize::Zeroizing;

pub(super) fn shared_template() -> Template {
    Template::new()
        .unsigned(CKA_CLASS, CKO_SECRET_KEY)
        .unsigned(CKA_KEY_TYPE, CKK_GENERIC_SECRET)
        .boolean(CKA_TOKEN, false)
        .boolean(CKA_PRIVATE, true)
        .boolean(CKA_SENSITIVE, false)
        .boolean(CKA_EXTRACTABLE, true)
        .bytes(CKA_LABEL, b"recipe-shared")
}

pub(super) fn read_shared(
    owner: &ProbeSession,
    key: CK_OBJECT_HANDLE,
) -> Result<Zeroizing<[u8; 32]>, Failure> {
    let mut value = Zeroizing::new([0u8; 32]);
    let mut attribute = CK_ATTRIBUTE {
        r#type: CKA_VALUE,
        pValue: value.as_mut_ptr().cast(),
        ulValueLen: 32,
    };
    let get = required(owner.functions()?.C_GetAttributeValue)?;
    // SAFETY: declared 32-byte value storage stays live through the call; the
    // descriptor is writable and no value is read on a native refusal.
    status("C_GetAttributeValue", unsafe {
        get(owner.handle()?, key, &mut attribute, 1)
    })?;
    if attribute.ulValueLen != 32 {
        return Err(Failure::Oracle("probe_kem_shared_length"));
    }
    Ok(value)
}

pub(super) fn run(owner: &mut ProbeSession, parameter_set: CK_ULONG) -> Result<(), Failure> {
    let ciphertext_size = match parameter_set {
        CKP_ML_KEM_512 => 768,
        CKP_ML_KEM_768 => 1088,
        CKP_ML_KEM_1024 => 1568,
        _ => return Err(Failure::Input("probe_kem_parameter_set")),
    };
    let mut public = Template::new()
        .unsigned(CKA_CLASS, CKO_PUBLIC_KEY)
        .unsigned(CKA_KEY_TYPE, CKK_ML_KEM)
        .unsigned(CKA_PARAMETER_SET, parameter_set)
        .boolean(CKA_TOKEN, false)
        .boolean(CKA_PRIVATE, false)
        .boolean(CKA_ENCAPSULATE, true)
        .bytes(CKA_LABEL, b"recipe-kem-public");
    let mut private = Template::new()
        .unsigned(CKA_CLASS, CKO_PRIVATE_KEY)
        .unsigned(CKA_KEY_TYPE, CKK_ML_KEM)
        .boolean(CKA_TOKEN, false)
        .boolean(CKA_PRIVATE, true)
        .boolean(CKA_DECAPSULATE, true)
        .boolean(CKA_SENSITIVE, true)
        .boolean(CKA_EXTRACTABLE, false)
        .bytes(CKA_LABEL, b"recipe-kem-private");
    let session = owner.handle()?;
    let generate = required(owner.functions()?.C_GenerateKeyPair)?;
    let mut generator = CK_MECHANISM {
        mechanism: CKM_ML_KEM_KEY_PAIR_GEN,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut public_key = CK_INVALID_HANDLE;
    let mut private_key = CK_INVALID_HANDLE;
    public.with_native(|public| {
        private.with_native(|private| {
            // SAFETY: input values and descriptors are owned across this synchronous
            // generation; both output handles have writable initialized storage.
            status("C_GenerateKeyPair", unsafe {
                generate(
                    session,
                    &mut generator,
                    public.as_mut_ptr(),
                    public.len() as CK_ULONG,
                    private.as_mut_ptr(),
                    private.len() as CK_ULONG,
                    &mut public_key,
                    &mut private_key,
                )
            })
        })
    })?;
    owner.retain(public_key)?;
    owner.retain(private_key)?;
    let encapsulate = required(owner.functions()?.C_EncapsulateKey)?;
    let decapsulate = required(owner.functions()?.C_DecapsulateKey)?;
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_ML_KEM,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut ciphertext = vec![0u8; ciphertext_size];
    let mut length = ciphertext.len() as CK_ULONG;
    let mut sender = CK_INVALID_HANDLE;
    let mut receiver = CK_INVALID_HANDLE;
    shared_template().with_native(|attributes| {
        // SAFETY: exact ML-KEM ciphertext capacity, valid public key, and owned
        // secret template; outputs are consumed only after successful completion.
        status("C_EncapsulateKey", unsafe {
            encapsulate(
                session,
                &mut mechanism,
                public_key,
                attributes.as_mut_ptr(),
                attributes.len() as CK_ULONG,
                ciphertext.as_mut_ptr(),
                &mut length,
                &mut sender,
            )
        })
    })?;
    owner.retain(sender)?;
    if length as usize != ciphertext_size {
        return Err(Failure::Oracle("probe_kem_ciphertext_length"));
    }
    shared_template().with_native(|attributes| {
        // SAFETY: exact ciphertext returned by the successful encapsulation;
        // owned template and writable secret-key handle retained through return.
        status("C_DecapsulateKey", unsafe {
            decapsulate(
                session,
                &mut mechanism,
                private_key,
                attributes.as_mut_ptr(),
                attributes.len() as CK_ULONG,
                ciphertext.as_mut_ptr(),
                length,
                &mut receiver,
            )
        })
    })?;
    owner.retain(receiver)?;
    let sender = read_shared(owner, sender)?;
    let receiver = read_shared(owner, receiver)?;
    if *sender != *receiver {
        return Err(Failure::Oracle("probe_kem_shared_value"));
    }
    Ok(())
}
