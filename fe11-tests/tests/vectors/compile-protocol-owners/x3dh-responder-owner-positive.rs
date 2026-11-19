// SPDX-License-Identifier: Apache-2.0
//! Compiler-only ownership contract; no native or cryptographic call.
pub fn check(key: fe11::NativeObjectRef) {
    let short = key;
    let value = fe11::X3dhResponder {
        kdf: 1,
        identity_id: &[],
        prekey_id: &[],
        onetime_id: None,
        initiator_ephemeral: &[],
        initiator_identity: &short,
    };
    std::hint::black_box(value);
}
