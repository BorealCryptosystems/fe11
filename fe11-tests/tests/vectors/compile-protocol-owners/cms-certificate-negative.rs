// SPDX-License-Identifier: Apache-2.0
//! Compiler-only ownership contract; no native or cryptographic call.
pub fn check(key: fe11::NativeObjectRef) {
    let value;
    {
        let short = key;
        value = fe11::NativeCmsParameters {
            signing: fe11::NativeNestedMechanism::Digest(fe11::NativeDigestAlgorithm::Sha256),
            digest: None,
            certificate: Some(&short),
            content_type: None,
            requested_attributes: None,
            required_attributes: None,
        };
    }
    std::hint::black_box(value);
}
