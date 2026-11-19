// SPDX-License-Identifier: Apache-2.0
//! Public key encodings and lengths immediately outside the allocation domain.
use fe11::*;

// FIPS 204, Table 2. FIPS 205 public keys concatenate PK.seed and PK.root,
// each n bytes. The parameter set selects n independently of the hash family.
#[test]
fn signature_public_key_lengths_match_the_standard_encodings() {
    use MlDsaParameterSet::*;
    use PqcAlgorithm::*;
    use SlhDsaParameterSet::*;

    for parameter in PqcAlgorithm::ALL {
        let expected = match parameter {
            MlDsa(MlDsa44) => 1312,
            MlDsa(MlDsa65) => 1952,
            MlDsa(MlDsa87) => 2592,
            SlhDsa(Sha2_128s | Sha2_128f | Shake128s | Shake128f) => 32,
            SlhDsa(Sha2_192s | Sha2_192f | Shake192s | Shake192f) => 48,
            SlhDsa(Sha2_256s | Sha2_256f | Shake256s | Shake256f) => 64,
        };
        assert_eq!(parameter.public_key_length(), expected, "{parameter:?}");
    }
}

#[test]
fn secret_bytes_reject_the_first_unrepresentable_allocation() {
    // This is one byte past the largest valid Rust allocation. Vec rejects
    // the capacity before asking the allocator for memory.
    let length = isize::MAX as usize + 1;
    assert!(matches!(
        SecretBytes::new(length),
        Err(Error::Rejected(RejectionReason::RandomGeneration(
            RandomGenerationRejection::SecretBufferAllocation
        )))
    ));
}

#[test]
fn plaintext_rejects_the_first_unrepresentable_length() {
    // Windows uses a 32-bit CK_ULONG even on x86-64. Linux reaches the Rust
    // allocation boundary first. Both invalid requests fail before allocation.
    let max_native = fe11_sys::CK_ULONG::MAX as u128;
    let max_allocation = isize::MAX as u128;
    let length = usize::try_from(max_native.min(max_allocation) + 1).unwrap();
    let expected = if max_native < max_allocation {
        RejectionReason::InputBounds(InputBoundsRejection::LengthConversion)
    } else {
        RejectionReason::KeyTransport(KeyTransportRejection::OaepPlaintextAllocation)
    };
    assert!(
        matches!(SecretPlaintext::new(length), Err(Error::Rejected(actual)) if actual == expected)
    );
}
