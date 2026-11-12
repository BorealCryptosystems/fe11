// SPDX-License-Identifier: Apache-2.0
use fe11::*;

/// A native SHA-256 digest of an already available message.
pub fn sha256(session: &Session, message: &[u8], limits: InputLimits) -> Result<PreparedDigest> {
    session.digest(HashAlgorithm::Sha256, message, limits)
}

/// Native Init/Update/Final preserving the supplied fragment boundaries.
pub fn sha256_parts(
    session: &Session, parts: &[&[u8]], limits: InputLimits,
) -> Result<PreparedDigest> {
    session.digest_multipart(HashAlgorithm::Sha256, parts, limits)
}

/// Request random bytes from the selected native module.
pub fn random_bytes(session: &Session, length: usize) -> Result<SecretBytes> {
    session.generate_random(length)
}

/// SHA-256 hashing and RSA PKCS#1 v1.5 signing performed by the native mechanism.
pub fn sign_message(
    session: &Session, key: &NativeObjectRef, message: &[u8],
    limits: InputLimits, signature_capacity: usize,
) -> Result<NativeSignature> {
    session.sign_native(
        key,
        NativeSignatureParameters::Parameterless(NativeSignatureAlgorithm::SHA256_RSA_PKCS),
        MessageRoute::Single,
        &[message],
        limits,
        signature_capacity,
        None,
    )
}

/// Verify the original message with the matching native public key.
pub fn verify_message(
    session: &Session, key: &NativeObjectRef, message: &[u8],
    signature: &[u8], limits: InputLimits,
) -> Result<()> {
    session.verify_native(
        key,
        NativeSignatureParameters::Parameterless(NativeSignatureAlgorithm::SHA256_RSA_PKCS),
        MessageRoute::Single,
        &[message],
        signature,
        limits,
        None,
    )
}

/// Encrypt with an application-managed unique 96-bit nonce and 128-bit GCM tag.
pub fn encrypt_record(
    session: &Session, key: &SymmetricKey, nonce: [u8; 12],
    aad: &[u8], plaintext: &[u8], limits: InputLimits,
) -> Result<AeadCiphertext> {
    session.encrypt_aead(
        key, AeadParameters { nonce: AeadNonce::Provided(nonce), aad },
        plaintext, limits,
    )
}

/// Authenticate and decrypt the ciphertext-and-tag record.
pub fn decrypt_record(
    session: &Session, key: &SymmetricKey, nonce: [u8; 12],
    aad: &[u8], ciphertext_and_tag: &[u8], limits: InputLimits,
) -> Result<AeadPlaintext> {
    session.decrypt_aead(
        key, AeadParameters { nonce: AeadNonce::Provided(nonce), aad },
        ciphertext_and_tag, limits,
    )
}
