// SPDX-License-Identifier: Apache-2.0
//! Compiler-only ownership contract; no native or cryptographic call.
pub fn check() {
    let value;
    {
        let short = std::ffi::CString::new("application/octet-stream").expect("literal without NUL");
        value = fe11::NativeCmsParameters {
            signing: fe11::NativeNestedMechanism::Digest(fe11::NativeDigestAlgorithm::Sha256),
            digest: None,
            certificate: None,
            content_type: Some(&short),
            requested_attributes: None,
            required_attributes: None,
        };
    }
    std::hint::black_box(value);
}
