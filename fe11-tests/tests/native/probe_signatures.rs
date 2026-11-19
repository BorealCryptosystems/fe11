// SPDX-License-Identifier: Apache-2.0
//! Real key generation and sign/verify witnesses for enabled signature families.
//! These preparation witnesses establish availability, not cryptographic KAT coverage.
use super::{
    native_support::{required, status},
    outcome::Failure,
    probe_session::ProbeSession,
    probe_template::Template,
};
use fe11_sys::*;
use std::{mem::size_of, ptr};

pub(super) enum SignatureFamily {
    Rsa,
    Dsa,
    Ecdsa,
    Edwards25519,
    Edwards448,
    MlDsa(CK_ULONG),
    SlhDsa(CK_ULONG),
}

impl SignatureFamily {
    fn selection(&self) -> (CK_MECHANISM_TYPE, CK_KEY_TYPE, CK_MECHANISM_TYPE, usize) {
        match self {
            Self::Dsa => (CKM_DSA_KEY_PAIR_GEN, CKK_DSA, CKM_DSA_SHA1, 40),
            Self::Rsa => (CKM_RSA_PKCS_KEY_PAIR_GEN, CKK_RSA, CKM_SHA256_RSA_PKCS, 256),
            Self::Ecdsa => (CKM_EC_KEY_PAIR_GEN, CKK_EC, CKM_ECDSA, 64),
            Self::Edwards25519 => (CKM_EC_EDWARDS_KEY_PAIR_GEN, CKK_EC_EDWARDS, CKM_EDDSA, 64),
            Self::Edwards448 => (CKM_EC_EDWARDS_KEY_PAIR_GEN, CKK_EC_EDWARDS, CKM_EDDSA, 114),
            Self::MlDsa(set) => (
                CKM_ML_DSA_KEY_PAIR_GEN,
                CKK_ML_DSA,
                CKM_ML_DSA,
                match set {
                    &CKP_ML_DSA_44 => 2420,
                    &CKP_ML_DSA_65 => 3309,
                    _ => 4627,
                },
            ),
            Self::SlhDsa(set) => (
                CKM_SLH_DSA_KEY_PAIR_GEN,
                CKK_SLH_DSA,
                CKM_SLH_DSA,
                match *set {
                    1 | 2 => 7856,
                    3 | 4 => 17088,
                    5 | 6 => 16224,
                    7 | 8 => 35664,
                    9 | 10 => 29792,
                    _ => 49856,
                },
            ),
        }
    }
}

fn pair(
    owner: &mut ProbeSession,
    family: &SignatureFamily,
) -> Result<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE), Failure> {
    let (generator, key_type, _, _) = family.selection();
    let mut public = Template::new()
        .unsigned(CKA_CLASS, CKO_PUBLIC_KEY)
        .unsigned(CKA_KEY_TYPE, key_type)
        .boolean(CKA_TOKEN, false)
        .boolean(CKA_PRIVATE, false)
        .boolean(CKA_VERIFY, true)
        .bytes(CKA_LABEL, b"recipe-public");
    let mut private = Template::new()
        .unsigned(CKA_CLASS, CKO_PRIVATE_KEY)
        .unsigned(CKA_KEY_TYPE, key_type)
        .boolean(CKA_TOKEN, false)
        .boolean(CKA_PRIVATE, true)
        .boolean(CKA_SIGN, true)
        .boolean(CKA_SENSITIVE, true)
        .boolean(CKA_EXTRACTABLE, false)
        .bytes(CKA_LABEL, b"recipe-private");
    public = match family {
        SignatureFamily::Dsa => {
            let parameters = super::probe_parameters::domain(true)?;
            public
                .bytes(CKA_PRIME, &parameters.prime)
                .bytes(CKA_SUBPRIME, &parameters.subprime)
                .bytes(CKA_BASE, &parameters.base)
        }
        SignatureFamily::Rsa => public
            .unsigned(CKA_MODULUS_BITS, 2048)
            .bytes(CKA_PUBLIC_EXPONENT, &[1, 0, 1]),
        SignatureFamily::Ecdsa => {
            public.bytes(CKA_EC_PARAMS, &[6, 8, 42, 134, 72, 206, 61, 3, 1, 7])
        }
        SignatureFamily::Edwards25519 => public.bytes(CKA_EC_PARAMS, &[6, 3, 43, 101, 112]),
        SignatureFamily::Edwards448 => public.bytes(CKA_EC_PARAMS, &[6, 3, 43, 101, 113]),
        SignatureFamily::MlDsa(set) | SignatureFamily::SlhDsa(set) => {
            public.unsigned(CKA_PARAMETER_SET, *set)
        }
    };
    let generate = required(owner.functions()?.C_GenerateKeyPair)?;
    let session = owner.handle()?;
    let mut mechanism = CK_MECHANISM {
        mechanism: generator,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };
    let mut public_handle = CK_INVALID_HANDLE;
    let mut private_handle = CK_INVALID_HANDLE;
    public.with_native(|public| {
        private.with_native(|private| {
            // SAFETY: templates own every correctly typed input until return; both
            // output handles are writable and read only after successful generation.
            status("C_GenerateKeyPair", unsafe {
                generate(
                    session,
                    &mut mechanism,
                    public.as_mut_ptr(),
                    public.len() as CK_ULONG,
                    private.as_mut_ptr(),
                    private.len() as CK_ULONG,
                    &mut public_handle,
                    &mut private_handle,
                )
            })
        })
    })?;
    owner.retain(public_handle)?;
    owner.retain(private_handle)?;
    Ok((public_handle, private_handle))
}

pub(super) fn run(owner: &mut ProbeSession, family: SignatureFamily) -> Result<(), Failure> {
    if matches!(&family, SignatureFamily::MlDsa(set) if !(1..=3).contains(set))
        || matches!(&family, SignatureFamily::SlhDsa(set) if !(1..=12).contains(set))
    {
        return Err(Failure::Input("probe_signature_parameter_set"));
    }
    let (public, private) = pair(owner, &family)?;
    let (_, _, number, signature_length) = family.selection();
    let session = owner.handle()?;
    let functions = owner.functions()?;
    let sign_init = required(functions.C_SignInit)?;
    let sign = required(functions.C_Sign)?;
    let verify_init = required(functions.C_VerifyInit)?;
    let verify = required(functions.C_Verify)?;
    let mut context = CK_SIGN_ADDITIONAL_CONTEXT {
        hedgeVariant: CKH_HEDGE_PREFERRED,
        pContext: ptr::null_mut(),
        ulContextLen: 0,
    };
    let mut edwards = CK_EDDSA_PARAMS {
        phFlag: CK_FALSE,
        ulContextDataLen: 0,
        pContextData: ptr::null_mut(),
    };
    let (pointer, length) = match family {
        SignatureFamily::MlDsa(_) | SignatureFamily::SlhDsa(_) => (
            (&mut context as *mut CK_SIGN_ADDITIONAL_CONTEXT).cast(),
            size_of::<CK_SIGN_ADDITIONAL_CONTEXT>() as CK_ULONG,
        ),
        SignatureFamily::Edwards448 => (
            (&mut edwards as *mut CK_EDDSA_PARAMS).cast(),
            size_of::<CK_EDDSA_PARAMS>() as CK_ULONG,
        ),
        _ => (ptr::null_mut(), 0),
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: number,
        pParameter: pointer,
        ulParameterLen: length,
    };
    let mut message = [0x42; 32];
    let mut signature = vec![0u8; signature_length];
    let mut length = signature.len() as CK_ULONG;
    // SAFETY: live session and owned keys; parameter and message storage remains
    // alive through the synchronous sign/verify sequence. No async flag is used.
    status("C_SignInit", unsafe {
        sign_init(session, &mut mechanism, private)
    })?;
    status("C_Sign", unsafe {
        sign(
            session,
            message.as_mut_ptr(),
            message.len() as CK_ULONG,
            signature.as_mut_ptr(),
            &mut length,
        )
    })?;
    if length as usize != signature_length {
        return Err(Failure::Oracle("probe_signature_length"));
    }
    status("C_VerifyInit", unsafe {
        verify_init(session, &mut mechanism, public)
    })?;
    status("C_Verify", unsafe {
        verify(
            session,
            message.as_mut_ptr(),
            message.len() as CK_ULONG,
            signature.as_mut_ptr(),
            length,
        )
    })?;
    Ok(())
}
