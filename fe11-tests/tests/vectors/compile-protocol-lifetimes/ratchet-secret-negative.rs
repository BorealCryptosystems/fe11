// SPDX-License-Identifier: Apache-2.0
//! Compiler-only ownership contract; no module or cryptographic operation is invoked.
pub fn check() {
    let value;
    {
        let bytes = [0u8; 1];
        value = fe11::RatchetParameters {
            shared_secret: &bytes,
            encrypted_header: false,
            curve: 0,
            aead: 0,
            kdf: 1,
        };
    }
    std::hint::black_box(value);
}
