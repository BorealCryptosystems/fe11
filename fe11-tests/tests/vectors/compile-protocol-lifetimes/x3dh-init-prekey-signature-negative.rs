// SPDX-License-Identifier: Apache-2.0
//! Compiler-only ownership contract; no module or cryptographic operation is invoked.
pub fn check(key: &fe11::NativeObjectRef) {
    let value;
    {
        let bytes = [0u8; 1];
        value = fe11::X3dhInitiator {
            kdf: 1,
            peer_identity: key,
            peer_prekey: key,
            prekey_signature: &bytes,
            onetime_key: None,
            own_identity: key,
            own_ephemeral: key,
        };
    }
    std::hint::black_box(value);
}
