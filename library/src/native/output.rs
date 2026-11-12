// SPDX-License-Identifier: Apache-2.0
//! Initialized native output slots and unbound descriptors.
//!
//! These constructors provide valid Rust storage, not successful native results.
//! Callers must check the return code and returned lengths before reading outputs.
//! Pointer-bearing placeholders must be bound to their stable owners before use.
use fe11_sys::*;
use std::ptr::null_mut;

fn version() -> CK_VERSION {
    CK_VERSION { major: 0, minor: 0 }
}

pub(crate) fn info() -> CK_INFO {
    CK_INFO {
        cryptokiVersion: version(),
        manufacturerID: [0; 32],
        flags: 0,
        libraryDescription: [0; 32],
        libraryVersion: version(),
    }
}

pub(crate) fn slot_info() -> CK_SLOT_INFO {
    CK_SLOT_INFO {
        slotDescription: [0; 64],
        manufacturerID: [0; 32],
        flags: 0,
        hardwareVersion: version(),
        firmwareVersion: version(),
    }
}

pub(crate) fn token_info() -> CK_TOKEN_INFO {
    CK_TOKEN_INFO {
        label: [0; 32],
        manufacturerID: [0; 32],
        model: [0; 16],
        serialNumber: [0; 16],
        flags: 0,
        ulMaxSessionCount: 0,
        ulSessionCount: 0,
        ulMaxRwSessionCount: 0,
        ulRwSessionCount: 0,
        ulMaxPinLen: 0,
        ulMinPinLen: 0,
        ulTotalPublicMemory: 0,
        ulFreePublicMemory: 0,
        ulTotalPrivateMemory: 0,
        ulFreePrivateMemory: 0,
        hardwareVersion: version(),
        firmwareVersion: version(),
        utcTime: [0; 16],
    }
}

pub(crate) fn session_info() -> CK_SESSION_INFO {
    CK_SESSION_INFO {
        slotID: 0,
        state: 0,
        flags: 0,
        ulDeviceError: 0,
    }
}

pub(crate) fn mechanism_info() -> CK_MECHANISM_INFO {
    CK_MECHANISM_INFO {
        ulMinKeySize: 0,
        ulMaxKeySize: 0,
        flags: 0,
    }
}

pub(crate) fn interface() -> CK_INTERFACE {
    CK_INTERFACE {
        pInterfaceName: null_mut(),
        pFunctionList: null_mut(),
        flags: 0,
    }
}

pub(crate) fn async_data() -> CK_ASYNC_DATA {
    CK_ASYNC_DATA {
        ulVersion: 0,
        pValue: null_mut(),
        ulValue: 0,
        hObject: CK_INVALID_HANDLE,
        hAdditionalObject: CK_INVALID_HANDLE,
    }
}

pub(crate) fn mechanism() -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: 0,
        pParameter: null_mut(),
        ulParameterLen: 0,
    }
}

pub(crate) fn attribute() -> CK_ATTRIBUTE {
    CK_ATTRIBUTE {
        r#type: 0,
        pValue: null_mut(),
        ulValueLen: 0,
    }
}
