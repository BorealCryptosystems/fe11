// SPDX-License-Identifier: Apache-2.0
//! Borrowed operands for one AEAD message call, independent of input scheduling.
//!
//! This view never owns or releases native storage. The installed operation
//! retains every descriptor, nonce/tag, input, output and length cell for the
//! full native loan, even when invocation returns pending or uncertain.
use super::NativeParameters;
pub(super) mod types;
use fe11_sys::{CK_FLAGS, CK_MECHANISM, CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_ULONG};

pub(super) struct Data<'a> {
    pub parameters: &'a mut NativeParameters,
    pub input: &'a mut [u8],
    pub input_length: CK_ULONG,
    pub output: &'a mut [u8],
    pub length: &'a mut CK_ULONG,
}

pub(super) enum Call<'a> {
    Init {
        native: types::Init,
        mechanism: &'a mut CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
    },
    Begin {
        native: types::Begin,
        parameters: &'a mut NativeParameters,
        aad: &'a mut [u8],
        aad_length: CK_ULONG,
    },
    Single {
        native: types::Single,
        data: Data<'a>,
        aad: &'a mut [u8],
        aad_length: CK_ULONG,
    },
    Next {
        native: types::Next,
        data: Data<'a>,
        flags: CK_FLAGS,
    },
    Final {
        native: types::Final,
    },
}

impl Call<'_> {
    /// Dispatch exactly once; no probe, retry, cleanup or transition is implied.
    ///
    /// # Safety
    /// The caller holds session/operation possession and has checked the selected
    /// function tuple, parameter representation and buffer dimensions. Pointers
    /// inside parameters and mechanism must address stable owned allocations.
    /// All referents, including the output-length cell, must remain owned after
    /// this temporary borrow ends until native memory return is established.
    pub(super) unsafe fn invoke(self, session: CK_SESSION_HANDLE) -> CK_RV {
        // SAFETY: the enclosing owner establishes the contract above. The
        // branches preserve the exact C typedef and each distinct argument list;
        // no cast between function pointers or shared scratch allocation is used.
        unsafe {
            match self {
                Self::Init {
                    native,
                    mechanism,
                    key,
                } => native(session, mechanism, key),
                Self::Begin {
                    native,
                    parameters,
                    aad,
                    aad_length,
                } => {
                    let call = native;
                    let pointer = parameters.pointer_mut();
                    call(
                        session,
                        pointer,
                        parameters.size(),
                        aad.as_mut_ptr(),
                        aad_length,
                    )
                }
                Self::Single {
                    native,
                    data,
                    aad,
                    aad_length,
                } => {
                    let call = native;
                    let pointer = data.parameters.pointer_mut();
                    call(
                        session,
                        pointer,
                        data.parameters.size(),
                        aad.as_mut_ptr(),
                        aad_length,
                        data.input.as_mut_ptr(),
                        data.input_length,
                        data.output.as_mut_ptr(),
                        data.length,
                    )
                }
                Self::Next {
                    native,
                    data,
                    flags,
                } => {
                    let call = native;
                    let pointer = data.parameters.pointer_mut();
                    call(
                        session,
                        pointer,
                        data.parameters.size(),
                        data.input.as_mut_ptr(),
                        data.input_length,
                        data.output.as_mut_ptr(),
                        data.length,
                        flags,
                    )
                }
                Self::Final { native } => native(session),
            }
        }
    }
}
