// SPDX-License-Identifier: Apache-2.0
//! Compiler-only ownership contract; no native or cryptographic call.
pub fn check() {
    let short = [0u8; 1];
    let value = fe11::NativeCmsParameters {
        signing: fe11::NativeNestedMechanism::Digest(fe11::NativeDigestAlgorithm::Sha256),
        digest: None,
        certificate: None,
        content_type: None,
        requested_attributes: None,
        required_attributes: Some(&short),
    };
    std::hint::black_box(value);
}
