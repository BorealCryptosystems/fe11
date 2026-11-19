// SPDX-License-Identifier: Apache-2.0
//! Compiler-only ownership contract; no module or cryptographic operation is invoked.
pub fn check() {
    let value;
    {
        let bytes = [0u8; 1];
        value = fe11::KeaRequest {
            mechanism: fe11::KeaMechanism::KeyDerive,
            sender: true,
            random_a: &bytes,
            random_b: &[],
            peer_public: &[],
        };
    }
    std::hint::black_box(value);
}
