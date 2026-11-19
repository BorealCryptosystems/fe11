// SPDX-License-Identifier: Apache-2.0
//! Compiler-only ownership contract; no native or cryptographic call.
pub fn check(key: fe11::NativeObjectRef, other: &fe11::NativeObjectRef) {
    let value;
    {
        let short = key;
        value = fe11::X3dhInitiator {
            kdf: 1,
            prekey_signature: &[],
            onetime_key: None,
            peer_identity: other,
            peer_prekey: other,
            own_identity: other,
            own_ephemeral: &short,
        };
    }
    std::hint::black_box(value);
}
