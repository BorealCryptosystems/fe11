// SPDX-License-Identifier: Apache-2.0
//! DH and ECDH recipe witnesses compare independently derived shared keys.
use super::{
    native_support::{required, status},
    outcome::Failure,
    probe_kem::{read_shared, shared_template},
    probe_parameters,
    probe_session::ProbeSession,
    probe_template::Template,
};
use fe11_sys::*;
use std::{mem::size_of, ptr};

fn pair(
    owner: &mut ProbeSession,
    elliptic: bool,
) -> Result<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE), Failure> {
    let key_type = if elliptic { CKK_EC } else { CKK_DH };
    let mut public = Template::new()
        .unsigned(CKA_CLASS, CKO_PUBLIC_KEY)
        .unsigned(CKA_KEY_TYPE, key_type)
        .boolean(CKA_TOKEN, false)
        .boolean(CKA_PRIVATE, false)
        .bytes(CKA_LABEL, b"recipe-agreement-public");
    let mut private = Template::new()
        .unsigned(CKA_CLASS, CKO_PRIVATE_KEY)
        .unsigned(CKA_KEY_TYPE, key_type)
        .boolean(CKA_TOKEN, false)
        .boolean(CKA_PRIVATE, true)
        .boolean(CKA_DERIVE, true)
        .boolean(CKA_SENSITIVE, true)
        .boolean(CKA_EXTRACTABLE, false)
        .bytes(CKA_LABEL, b"recipe-agreement-private");
    public = if elliptic {
        public.bytes(CKA_EC_PARAMS, &[6, 8, 42, 134, 72, 206, 61, 3, 1, 7])
    } else {
        let parameters = probe_parameters::domain(false)?;
        public
            .bytes(CKA_PRIME, &parameters.prime)
            .bytes(CKA_BASE, &parameters.base)
    };
    let generate = required(owner.functions()?.C_GenerateKeyPair)?;
    let session = owner.handle()?;
    let mut mechanism = CK_MECHANISM {
        mechanism: if elliptic {
            CKM_EC_KEY_PAIR_GEN
        } else {
            CKM_DH_PKCS_KEY_PAIR_GEN
        },
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };
    let (mut public_key, mut private_key) = (CK_INVALID_HANDLE, CK_INVALID_HANDLE);
    public.with_native(|public| {
        private.with_native(|private| {
            // SAFETY: owned input templates remain live through this synchronous
            // call; initialized writable outputs are consumed only after CKR_OK.
            status("C_GenerateKeyPair", unsafe {
                generate(
                    session,
                    &mut mechanism,
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
    Ok((public_key, private_key))
}

fn public_value(
    owner: &ProbeSession,
    key: CK_OBJECT_HANDLE,
    elliptic: bool,
) -> Result<Vec<u8>, Failure> {
    let mut bytes = vec![0u8; 512];
    let mut attribute = CK_ATTRIBUTE {
        r#type: if elliptic { CKA_EC_POINT } else { CKA_VALUE },
        pValue: bytes.as_mut_ptr().cast(),
        ulValueLen: bytes.len() as CK_ULONG,
    };
    let get = required(owner.functions()?.C_GetAttributeValue)?;
    // SAFETY: bounded storage for a public value, matching declared length.
    status("C_GetAttributeValue", unsafe {
        get(owner.handle()?, key, &mut attribute, 1)
    })?;
    let length = usize::try_from(attribute.ulValueLen)
        .map_err(|_| Failure::Oracle("probe_agreement_public_length"))?;
    if length == 0 || length > bytes.len() {
        return Err(Failure::Oracle("probe_agreement_public_length"));
    }
    bytes.truncate(length);
    if elliptic {
        // P-256 CKA_EC_POINT is a DER OCTET STRING containing a 65-byte SEC1 point.
        if bytes.len() != 67 || bytes[..3] != [4, 65, 4] {
            return Err(Failure::Oracle("probe_agreement_point_encoding"));
        }
        Ok(bytes[2..].to_vec())
    } else {
        Ok(bytes)
    }
}

fn derive(
    owner: &mut ProbeSession,
    base: CK_OBJECT_HANDLE,
    peer: &mut [u8],
    elliptic: bool,
) -> Result<CK_OBJECT_HANDLE, Failure> {
    let derive = required(owner.functions()?.C_DeriveKey)?;
    let session = owner.handle()?;
    let mut ecdh = CK_ECDH1_DERIVE_PARAMS {
        kdf: CKD_NULL,
        ulSharedDataLen: 0,
        pSharedData: ptr::null_mut(),
        ulPublicDataLen: peer.len() as CK_ULONG,
        pPublicData: peer.as_mut_ptr(),
    };
    let mut mechanism = if elliptic {
        CK_MECHANISM {
            mechanism: CKM_ECDH1_DERIVE,
            pParameter: (&mut ecdh as *mut CK_ECDH1_DERIVE_PARAMS).cast(),
            ulParameterLen: size_of::<CK_ECDH1_DERIVE_PARAMS>() as CK_ULONG,
        }
    } else {
        CK_MECHANISM {
            mechanism: CKM_DH_PKCS_DERIVE,
            pParameter: peer.as_mut_ptr().cast(),
            ulParameterLen: peer.len() as CK_ULONG,
        }
    };
    let mut handle = CK_INVALID_HANDLE;
    shared_template()
        .unsigned(CKA_VALUE_LEN, 32)
        .with_native(|attributes| {
            // SAFETY: peer bytes and any ECDH descriptor stay live; the template is
            // owned by this synchronous call, and its returned handle is writable.
            status("C_DeriveKey", unsafe {
                derive(
                    session,
                    &mut mechanism,
                    base,
                    attributes.as_mut_ptr(),
                    attributes.len() as CK_ULONG,
                    &mut handle,
                )
            })
        })?;
    owner.retain(handle)?;
    Ok(handle)
}

pub(super) fn run(owner: &mut ProbeSession, elliptic: bool) -> Result<(), Failure> {
    let (public_a, private_a) = pair(owner, elliptic)?;
    let (public_b, private_b) = pair(owner, elliptic)?;
    let mut a = public_value(owner, public_a, elliptic)?;
    let mut b = public_value(owner, public_b, elliptic)?;
    let shared_a = derive(owner, private_a, &mut b, elliptic)?;
    let shared_b = derive(owner, private_b, &mut a, elliptic)?;
    if *read_shared(owner, shared_a)? != *read_shared(owner, shared_b)? {
        return Err(Failure::Oracle("probe_agreement_shared_value"));
    }
    Ok(())
}
