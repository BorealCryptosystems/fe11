// SPDX-License-Identifier: Apache-2.0
//! Compiler-only ownership contract; no module or cryptographic operation is invoked.
pub fn check() {
    let value;
    {
        let bytes = [0u8; 1];
        value = fe11::NativeKipParameters {
            mechanism: fe11::NativeNestedMechanism::GostDigest { oid: Some(&bytes) },
            key: None,
            seed: None,
        };
    }
    std::hint::black_box(value);
}
