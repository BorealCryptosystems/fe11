// SPDX-License-Identifier: Apache-2.0
//! Compiler-only ownership contract; no module or cryptographic operation is invoked.
pub fn check() {
    let bytes = [0u8; 1];
    let value = fe11::KeaRequest {
        mechanism: fe11::KeaMechanism::KeyDerive,
        sender: true,
        random_a: &[],
        random_b: &[],
        peer_public: &bytes,
    };
    std::hint::black_box(value);
}
