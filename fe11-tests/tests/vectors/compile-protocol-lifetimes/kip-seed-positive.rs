// SPDX-License-Identifier: Apache-2.0
//! Compiler-only ownership contract; no module or cryptographic operation is invoked.
pub fn check() {
    let bytes = [0u8; 1];
    let value = fe11::NativeKipParameters {
        mechanism: fe11::NativeNestedMechanism::Digest(fe11::NativeDigestAlgorithm::Sha256),
        key: None,
        seed: Some(&bytes),
    };
    std::hint::black_box(value);
}
