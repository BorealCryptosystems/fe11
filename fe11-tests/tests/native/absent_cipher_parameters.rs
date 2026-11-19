// SPDX-License-Identifier: Apache-2.0
//! Valid cipher parameter layouts for checking unavailable native initializers.
use super::{AesCipherParameters, CipherParameters, Failure};
use fe11_sys::*;

pub(super) fn parameters(
    number: CK_MECHANISM_TYPE,
) -> std::result::Result<CipherParameters<'static>, Failure> {
    let aes_iv = [0x21; 16];
    let des_iv = [0x21; 8];
    let value = match number {
        CKM_AES_CFB1 => CipherParameters::AesCfb1 { iv: aes_iv },
        CKM_AES_CFB8 => AesCipherParameters::Cfb8 { iv: aes_iv }.into(),
        CKM_AES_CFB64 => AesCipherParameters::Cfb64 { iv: aes_iv }.into(),
        CKM_AES_CFB128 => AesCipherParameters::Cfb128 { iv: aes_iv }.into(),
        CKM_AES_OFB => AesCipherParameters::Ofb { iv: aes_iv }.into(),
        CKM_AES_CTS => CipherParameters::AesCts { iv: aes_iv },
        CKM_AES_KEY_WRAP_PKCS7 => CipherParameters::AesKeyWrapPkcs7 { iv: None },
        CKM_DES_CFB8 => CipherParameters::DesCfb8 { iv: des_iv },
        CKM_DES_CFB64 => CipherParameters::DesCfb64 { iv: des_iv },
        CKM_DES_OFB8 => CipherParameters::DesOfb8 { iv: des_iv },
        CKM_DES_OFB64 => CipherParameters::DesOfb64 { iv: des_iv },
        _ => return Err(Failure::Input("unknown_cipher_selector")),
    };
    Ok(value)
}
