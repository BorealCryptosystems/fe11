// SPDX-License-Identifier: Apache-2.0
//! Mechanism identities are independent of borrowed input contents and presence.
use fe11::*;
use fe11_sys::*;

#[test]
fn encrypt_data_variants_preserve_the_selected_cipher_and_mode() {
    for data in [&[][..], &[0][..], &[0, 0xff, 0x80, 1][..]] {
        let values = [
            (NativeEncryptData::DesEcb(data), CKM_DES_ECB_ENCRYPT_DATA),
            (NativeEncryptData::Des3Ecb(data), CKM_DES3_ECB_ENCRYPT_DATA),
            (NativeEncryptData::AesEcb(data), CKM_AES_ECB_ENCRYPT_DATA),
            (
                NativeEncryptData::CamelliaEcb(data),
                CKM_CAMELLIA_ECB_ENCRYPT_DATA,
            ),
            (NativeEncryptData::AriaEcb(data), CKM_ARIA_ECB_ENCRYPT_DATA),
            (NativeEncryptData::SeedEcb(data), CKM_SEED_ECB_ENCRYPT_DATA),
            (
                NativeEncryptData::DesCbc {
                    iv: [0xa5; 8],
                    data,
                },
                CKM_DES_CBC_ENCRYPT_DATA,
            ),
            (
                NativeEncryptData::Des3Cbc {
                    iv: [0xa5; 8],
                    data,
                },
                CKM_DES3_CBC_ENCRYPT_DATA,
            ),
            (
                NativeEncryptData::AesCbc {
                    iv: [0xa5; 16],
                    data,
                },
                CKM_AES_CBC_ENCRYPT_DATA,
            ),
            (
                NativeEncryptData::CamelliaCbc {
                    iv: [0xa5; 16],
                    data,
                },
                CKM_CAMELLIA_CBC_ENCRYPT_DATA,
            ),
            (
                NativeEncryptData::AriaCbc {
                    iv: [0xa5; 16],
                    data,
                },
                CKM_ARIA_CBC_ENCRYPT_DATA,
            ),
            (
                NativeEncryptData::SeedCbc {
                    iv: [0xa5; 16],
                    data,
                },
                CKM_SEED_CBC_ENCRYPT_DATA,
            ),
        ];
        for (value, expected) in values {
            assert_eq!(value.mechanism_number(), expected as u64);
            assert_eq!(
                NativeKeyDerivation::EncryptData(value).mechanism_number(),
                expected as u64
            );
        }
    }
}

#[test]
fn master_secret_derivation_distinguishes_all_protocol_and_dh_variants() {
    let randoms = TlsRandoms {
        client: &[0, 1, 0xff],
        server: &[0x80, 2],
    };
    // Selecting an identifier does not validate protocol-sized randoms or hashes.
    // Those inputs are still borrowed exactly, including an empty transcript.
    for hash in [0, CKM_SHA256 as u64, u64::MAX] {
        let values = [
            (
                TlsMasterDerivation::Ssl3 { randoms, dh: false },
                CKM_SSL3_MASTER_KEY_DERIVE,
            ),
            (
                TlsMasterDerivation::Ssl3 { randoms, dh: true },
                CKM_SSL3_MASTER_KEY_DERIVE_DH,
            ),
            (
                TlsMasterDerivation::Tls { randoms, dh: false },
                CKM_TLS_MASTER_KEY_DERIVE,
            ),
            (
                TlsMasterDerivation::Tls { randoms, dh: true },
                CKM_TLS_MASTER_KEY_DERIVE_DH,
            ),
            (
                TlsMasterDerivation::Tls12 {
                    randoms,
                    hash,
                    dh: false,
                },
                CKM_TLS12_MASTER_KEY_DERIVE,
            ),
            (
                TlsMasterDerivation::Tls12 {
                    randoms,
                    hash,
                    dh: true,
                },
                CKM_TLS12_MASTER_KEY_DERIVE_DH,
            ),
            (
                TlsMasterDerivation::Tls12Extended {
                    session_hash: &[],
                    hash,
                    dh: false,
                },
                CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE,
            ),
            (
                TlsMasterDerivation::Tls12Extended {
                    session_hash: &[0, 0xff],
                    hash,
                    dh: true,
                },
                CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH,
            ),
            (
                TlsMasterDerivation::Wtls {
                    randoms,
                    digest: hash,
                    dh_ecc: false,
                },
                CKM_WTLS_MASTER_KEY_DERIVE,
            ),
            (
                TlsMasterDerivation::Wtls {
                    randoms,
                    digest: hash,
                    dh_ecc: true,
                },
                CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC,
            ),
        ];
        for (value, expected) in values {
            assert_eq!(value.mechanism_number(), expected as u64);
            assert_eq!(
                NativeKeyDerivation::TlsMaster(value).mechanism_number(),
                expected as u64
            );
        }
    }
}

#[test]
fn ike_optional_key_absence_does_not_change_the_mechanism_identity() {
    // IKE1's required shared-key form needs a real-object case and separate
    // evidence; no native reference is fabricated in this module-free test.
    for prf in [0, CKM_SHA256_HMAC as u64, u64::MAX] {
        for data in [&[][..], &[0, 0xff, 1][..]] {
            for data_as_key in [false, true] {
                let values = [
                    (
                        NativeIkeDerivation::PrfPlus {
                            prf,
                            seed_key: None,
                            seed: data,
                        },
                        CKM_IKE2_PRF_PLUS_DERIVE,
                    ),
                    (
                        NativeIkeDerivation::Prf {
                            prf,
                            data_as_key,
                            new_key: None,
                            initiator_nonce: data,
                            responder_nonce: &[],
                        },
                        CKM_IKE_PRF_DERIVE,
                    ),
                    (
                        NativeIkeDerivation::Ike1Extended {
                            prf,
                            shared_key: None,
                            extra: data,
                        },
                        CKM_IKE1_EXTENDED_DERIVE,
                    ),
                ];
                for (value, expected) in values {
                    assert_eq!(value.mechanism_number(), expected as u64);
                    assert_eq!(
                        NativeKeyDerivation::Ike(value).mechanism_number(),
                        expected as u64
                    );
                }
            }
        }
    }
}
