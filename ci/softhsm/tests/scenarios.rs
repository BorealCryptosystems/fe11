// SPDX-License-Identifier: Apache-2.0
//! Small independent public contracts. Native errors are checked by function and code.
use crate::{
    fixture::{self, Fixture},
    report::{require, Cause, Failure, Outcome},
};
use fe11::*;

pub fn run(id: &str, fixture: &mut Fixture) -> Outcome {
    match id {
        "discovery" => Ok(()), // open() checked exact token identity and required mechanisms.
        "authentication" => {
            fixture.login()?;
            fixture.logout()
        }
        "invalid_pin" => {
            expect_native(
                fixture
                    .session()
                    .login_as(LoginRole::User, SecretPin::new(b"not-the-pin".to_vec())),
                "C_Login",
                fe11_sys::CKR_PIN_INCORRECT as u64,
            )?;
            fixture.login()
        }
        "digest_single" => digest(fixture, false),
        "digest_multipart" => digest(fixture, true),
        "rsa_sign_verify" => rsa(fixture, false),
        "invalid_signature" => rsa(fixture, true),
        "aes_gcm" => gcm(fixture, false),
        "invalid_gcm_tag" => gcm(fixture, true),
        "object_search" => search(fixture),
        _ => Err(Failure::new(Cause::Assertion)),
    }
}

fn expect_native<T>(result: fe11::Result<T>, function: &str, code: u64) -> Outcome {
    match result {
        Err(Error::Native {
            function: actual,
            code: actual_code,
            ..
        }) if actual == function && actual_code == code => Ok(()),
        Err(error) => Err(Failure::from(error)),
        Ok(_) => Err(Failure::new(Cause::Assertion)),
    }
}

fn digest(fixture: &Fixture, multipart: bool) -> Outcome {
    // SHA-256("abc"), the published FIPS 180-4 example; not derived using Fe11.
    const EXPECTED: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    let result = if multipart {
        fixture.session().digest_multipart(
            HashAlgorithm::Sha256,
            &[b"a", b"b", b"c"],
            fixture::limits(),
        )?
    } else {
        fixture
            .session()
            .digest(HashAlgorithm::Sha256, b"abc", fixture::limits())?
    };
    require(result.as_bytes() == EXPECTED)
}

fn attribute<'a>(name: StandardAttribute, value: AttributeInputValue<'a>) -> AttributeInput<'a> {
    AttributeInput {
        attribute: AttributeType::Standard(name),
        value,
    }
}

fn rsa(fixture: &mut Fixture, invalid: bool) -> Outcome {
    use AttributeInputValue::{Boolean, Bytes, Unsigned};
    fixture.login()?;
    let public = [
        attribute(StandardAttribute::TOKEN, Boolean(false)),
        attribute(StandardAttribute::PRIVATE, Boolean(false)),
        attribute(StandardAttribute::MODULUS_BITS, Unsigned(2048)),
        attribute(StandardAttribute::PUBLIC_EXPONENT, Bytes(&[1, 0, 1])),
        attribute(StandardAttribute::VERIFY, Boolean(true)),
    ];
    let private = [
        attribute(StandardAttribute::TOKEN, Boolean(false)),
        attribute(StandardAttribute::PRIVATE, Boolean(true)),
        attribute(StandardAttribute::SENSITIVE, Boolean(true)),
        attribute(StandardAttribute::EXTRACTABLE, Boolean(false)),
        attribute(StandardAttribute::SIGN, Boolean(true)),
    ];
    let created = fixture.session().generate_native_key_pair(
        KeyPairGenerator::RSA_PKCS_KEY_PAIR_GEN,
        fixture::generation(&public),
        fixture::generation(&private),
    )?;
    let pair = fixture.retain(created)?;
    let parameters =
        || NativeSignatureParameters::Parameterless(NativeSignatureAlgorithm::SHA256_RSA_PKCS);
    let message = b"public Fe11 signature example";
    let signature = fixture.session().sign_native(
        pair.private.native(),
        parameters(),
        MessageRoute::Single,
        &[message],
        fixture::limits(),
        256,
        None,
    )?;
    require(signature.as_bytes().len() == 256)?;
    fixture.session().verify_native(
        pair.public.native(),
        parameters(),
        MessageRoute::Single,
        &[message],
        signature.as_bytes(),
        fixture::limits(),
        None,
    )?;
    if invalid {
        expect_native(
            fixture.session().verify_native(
                pair.public.native(),
                parameters(),
                MessageRoute::Single,
                &[b"changed message"],
                signature.as_bytes(),
                fixture::limits(),
                None,
            ),
            "C_Verify",
            fe11_sys::CKR_SIGNATURE_INVALID as u64,
        )?;
        // A refused verification must permit a subsequent valid verification.
        fixture.session().verify_native(
            pair.public.native(),
            parameters(),
            MessageRoute::Single,
            &[message],
            signature.as_bytes(),
            fixture::limits(),
            None,
        )?;
    }
    Ok(())
}

fn gcm(fixture: &mut Fixture, invalid: bool) -> Outcome {
    fixture.login()?;
    let created = fixture.session().generate_aes_key(fixture::aes_spec())?;
    let key = fixture.retain(created)?;
    let random = fixture.session().generate_random(12)?;
    let nonce: [u8; 12] = random
        .as_slice()
        .try_into()
        .map_err(|_| Failure::new(Cause::Assertion))?;
    // The classic facade preserves CK_RV; the convenience decrypt_aead facade
    // intentionally maps native validity failures to InvalidCiphertext.
    let key = key.managed().native_object();
    let parameters = || ClassicAeadParameters::Gcm {
        iv: &nonce,
        aad: b"public associated data",
        tag_bits: 128,
    };
    let plaintext = b"public authenticated plaintext";
    let encrypted = fixture.session().encrypt_classic_aead(
        &key,
        parameters(),
        MessageRoute::Single,
        &[plaintext],
        fixture::limits(),
    )?;
    require(encrypted.as_bytes().len() == plaintext.len() + 16)?;
    let clear = fixture.session().decrypt_classic_aead(
        &key,
        parameters(),
        MessageRoute::Single,
        &[encrypted.as_bytes()],
        fixture::limits(),
    )?;
    require(clear.as_bytes() == plaintext)?;
    if invalid {
        let mut damaged = encrypted.as_bytes().to_vec();
        *damaged.last_mut().ok_or(Failure::new(Cause::Assertion))? ^= 1;
        // Only the final tag byte differs. The intact envelope succeeded above.
        expect_native(
            fixture.session().decrypt_classic_aead(
                &key,
                parameters(),
                MessageRoute::Single,
                &[&damaged],
                fixture::limits(),
            ),
            "C_Decrypt",
            fe11_sys::CKR_ENCRYPTED_DATA_INVALID as u64,
        )?;
        let clear = fixture.session().decrypt_classic_aead(
            &key,
            parameters(),
            MessageRoute::Single,
            &[encrypted.as_bytes()],
            fixture::limits(),
        )?;
        require(clear.as_bytes() == plaintext)?;
    }
    Ok(())
}

fn search(fixture: &mut Fixture) -> Outcome {
    use AttributeInputValue::{Boolean, Bytes, Unsigned};
    fixture.login()?;
    // Each child has a fresh token and an independently random token label.
    let id = fixture
        .environment
        .as_ref()
        .ok_or(Failure::new(Cause::Setup))?
        .label
        .as_bytes()
        .to_vec();
    let attributes = [
        attribute(StandardAttribute::TOKEN, Boolean(false)),
        attribute(StandardAttribute::PRIVATE, Boolean(true)),
        attribute(StandardAttribute::VALUE_LEN, Unsigned(16)),
        attribute(StandardAttribute::ID, Bytes(&id)),
    ];
    let created = fixture
        .session()
        .generate_native_key(KeyGenerator::AES_KEY_GEN, fixture::generation(&attributes))?;
    let object = fixture.retain(created)?;
    let query = [attribute(StandardAttribute::ID, Bytes(&id))];
    let found = fixture.session().find_native_objects(
        &query,
        fixture::template_limits(),
        fixture::search_plan(),
    )?;
    require(found.as_slice().len() == 1)?;
    drop(found);
    fixture.destroy(object.native())?;
    let absent = fixture.session().find_native_objects(
        &query,
        fixture::template_limits(),
        fixture::search_plan(),
    )?;
    require(absent.as_slice().is_empty())
}
