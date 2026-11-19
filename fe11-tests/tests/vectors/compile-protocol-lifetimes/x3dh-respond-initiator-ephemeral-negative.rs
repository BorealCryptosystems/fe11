// SPDX-License-Identifier: Apache-2.0
//! Compiler-only ownership contract; no module or cryptographic operation is invoked.
pub fn check(key: &fe11::NativeObjectRef) {
    let value;
    {
        let bytes = [0u8; 1];
        value = fe11::X3dhResponder {
            kdf: 1,
            identity_id: &[],
            prekey_id: &[],
            onetime_id: None,
            initiator_ephemeral: &bytes,
            initiator_identity: key,
        };
    }
    std::hint::black_box(value);
}
