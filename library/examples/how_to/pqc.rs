// SPDX-License-Identifier: Apache-2.0
use fe11::*;

/// Select a signature family while preserving the application's object choices.
pub fn generate_signature_pair(
    session: &Session, mut spec: PqcKeySpec, algorithm: PqcAlgorithm,
    public_policy: MechanismAttributes<'_>, private_policy: MechanismAttributes<'_>,
    protection: CurrentKeyProtection, public_visibility: ObjectVisibility,
) -> Result<CreatedObjects<PqcKeyPair>> {
    spec.algorithm = algorithm;
    spec.public_usages.verify = Some(true);
    spec.private_usages.sign = Some(true);
    session.generate_pqc_key_pair(
        spec, public_policy, private_policy, protection, public_visibility,
    )
}

/// Explicit pure ML-DSA and SLH-DSA parameter-set selections.
pub fn signature_algorithms() -> [PqcAlgorithm; 2] {
    [PqcAlgorithm::MlDsa(MlDsaParameterSet::MlDsa65),
     PqcAlgorithm::SlhDsa(SlhDsaParameterSet::Sha2_128s)]
}

/// Sign an original message, including its application-defined binary context.
pub fn sign_pure(
    session: &Session, key: &PqcSigningKey, message: &[u8], context: &[u8],
    hedging: PqcHedging, limits: InputLimits,
) -> Result<PqcSignature> {
    let parameters = PqcSignatureParameters::pure(context, hedging)?;
    session.sign_pqc(key, &parameters, message, limits)
}

/// Verify with the exact same pure-message context at the native module.
pub fn verify_pure(
    session: &Session, key: &PqcVerificationKey, message: &[u8], context: &[u8],
    hedging: PqcHedging, signature: &PqcSignature, limits: InputLimits,
) -> Result<Verification> {
    let parameters = PqcSignatureParameters::pure(context, hedging)?;
    session.verify_pqc(key, &parameters, message, signature, limits)
}

/// Select the standardized external SHA-512 prehash mode explicitly.
pub fn sign_sha512_prehash(
    session: &Session, key: &PqcSigningKey, digest: &[u8; 64], context: &[u8],
    hedging: PqcHedging, limits: InputLimits,
) -> Result<PqcSignature> {
    let parameters = PqcSignatureParameters::new(
        PqcSignatureMode::Prehashed(PqcHash::Sha512), context, hedging,
    )?;
    session.sign_pqc(key, &parameters, digest, limits)
}

/// Supply original bytes to a combined native hash/signature mechanism.
pub fn sign_hashed_message(
    session: &Session, key: &PqcSigningKey, message: &[u8], context: &[u8],
    hedging: PqcHedging, limits: InputLimits,
) -> Result<PqcSignature> {
    let parameters = PqcSignatureParameters::new(
        PqcSignatureMode::HashMessage(PqcHash::Sha512), context, hedging,
    )?;
    session.sign_pqc(key, &parameters, message, limits)
}

/// Verify a pure signature in the explicitly selected software component.
pub fn verify_in_software(
    engine: &VerifyEngine, public_key: &PqcPublicKey,
    message: &[u8], context: &[u8], hedging: PqcHedging,
    signature: &PqcSignature, limits: InputLimits,
) -> Result<Verification> {
    let parameters = PqcSignatureParameters::pure(context, hedging)?;
    public_key.verify(engine, message, signature, &parameters, limits)
}

/// Generate a caller-configured ML-KEM pair, preserving the creation outcome.
pub fn generate_kem_pair(
    session: &Session, mut spec: KemKeySpec, parameter_set: MlKemParameterSet,
    public_policy: MechanismAttributes<'_>, private_policy: MechanismAttributes<'_>,
    protection: CurrentKeyProtection, public_visibility: ObjectVisibility,
) -> Result<CreatedObjects<KemKeyPair>> {
    spec.parameter_set = parameter_set;
    spec.public_usages.encapsulate = Some(true);
    spec.private_usages.decapsulate = Some(true);
    session.generate_kem_key_pair(
        spec, public_policy, private_policy, protection, public_visibility,
    )
}

/// Return the public ciphertext and the locally retained native shared key.
pub fn encapsulate(
    session: &Session, recipient: &KemEncapsulationKey, output: KemSharedKeySpec,
) -> Result<CreatedObjects<KemEncapsulation>> {
    session.encapsulate_kem(recipient, output)
}

/// Decode the received ciphertext and create the recipient's native shared key.
pub fn decapsulate(
    session: &Session, recipient: &KemDecapsulationKey,
    ciphertext: &[u8], output: KemSharedKeySpec,
) -> Result<CreatedObjects<KemSharedKey>> {
    let ciphertext = KemCiphertext::from_bytes(recipient.parameter_set(), ciphertext)?;
    session.decapsulate_kem(recipient, &ciphertext, output)
}
