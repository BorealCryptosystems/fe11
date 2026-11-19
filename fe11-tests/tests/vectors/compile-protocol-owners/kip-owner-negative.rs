// SPDX-License-Identifier: Apache-2.0
//! Compiler-only ownership contract; no native or cryptographic call.
pub fn check(key: fe11::NativeObjectRef) {
    let value;
    {
        let short = key;
        value = fe11::NativeKipParameters {
            mechanism: fe11::NativeNestedMechanism::Digest(fe11::NativeDigestAlgorithm::Sha256),
            key: Some(&short),
            seed: None,
        };
    }
    std::hint::black_box(value);
}
