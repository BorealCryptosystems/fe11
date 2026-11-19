// SPDX-License-Identifier: Apache-2.0
//! AES-CBC-ENCRYPT-DATA with a valid offset input span at the owned block end.
use super::Owner;
use fe11::*;
use fe11_sys::{CK_AES_CBC_ENCRYPT_DATA_PARAMS, CK_ULONG};
use std::mem::{align_of, offset_of, size_of};

pub(super) fn derive(
    owner: &Owner,
    base: &NativeObjectRef,
    contract: &MechanismExtension,
    template: GenerationTemplate<'_>,
) -> Result<CreatedObjects<NativeObjectView>> {
    // NIST SP800-38A F.2.1, first block; the prefix is deliberately excluded.
    let mut data = vec![0xa5; 16];
    data.extend_from_slice(&[
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a,
    ]);
    let mut root = [0u8; size_of::<CK_AES_CBC_ENCRYPT_DATA_PARAMS>()];
    let iv = offset_of!(CK_AES_CBC_ENCRYPT_DATA_PARAMS, iv);
    root[iv..iv + 16].copy_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    let length = offset_of!(CK_AES_CBC_ENCRYPT_DATA_PARAMS, length);
    root[length..length + size_of::<CK_ULONG>()].copy_from_slice(&(16 as CK_ULONG).to_ne_bytes());
    let blocks = [
        ExtensionBlock {
            initial: &root,
            alignment: align_of::<CK_AES_CBC_ENCRYPT_DATA_PARAMS>(),
            direction: ExtensionDirection::Input,
        },
        ExtensionBlock {
            initial: &data,
            alignment: 1,
            direction: ExtensionDirection::Input,
        },
    ];
    let pointers = [ExtensionPointer {
        block: 0,
        offset: offset_of!(CK_AES_CBC_ENCRYPT_DATA_PARAMS, pData),
        target: ExtensionPointerTarget::Block {
            block: 1,
            offset: 16,
        },
    }];
    // SAFETY: initialized exact standard ABI; pData addresses exactly16 live
    // input bytes at the end of block1. Root and payload are immutable; there
    // are no output regions, hidden handles or pointer retention after return.
    let request = unsafe {
        ExtensionRequest::new(
            contract,
            ExtensionParameters {
                blocks: &blocks,
                pointers: &pointers,
                root: Some(0),
                outputs: &[],
            },
        )
    };
    let parameters = NativeKeyDerivation::Extension {
        request,
        class: ManagedClass::SecretKey,
    };
    match owner {
        Owner::Session(s) => s.derive_native_key(base, parameters, template),
        Owner::Advanced(s) => s.derive_native_key(base, parameters, template),
    }
}
