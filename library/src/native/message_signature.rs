// SPDX-License-Identifier: Apache-2.0
//! Shared typed/generic message signature calls, independent of operation ownership.
//!
//! These borrowed views grant no lifetime beyond invocation. The installed
//! owner must retain every referent until native memory return is established.
use crate::mechanism_extension::OwnedGraph;
pub(crate) mod types;
use fe11_sys::{CK_MECHANISM, CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_ULONG};

pub(crate) enum Signature<'a> {
    // None is the specified intermediate Next form (NULL output and length).
    Produce {
        native: types::Sign,
        output: Option<(&'a mut [u8], &'a mut CK_ULONG)>,
    },
    // None is the specified intermediate Next form (NULL signature, zero length).
    Verify {
        native: types::Verify,
        signature: Option<(&'a mut [u8], CK_ULONG)>,
    },
}

pub(crate) enum Call<'a> {
    Init {
        native: types::Init,
        mechanism: &'a mut CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
    },
    Begin {
        native: types::Begin,
        parameters: Option<&'a mut OwnedGraph>,
    },
    Data {
        parameters: Option<&'a mut OwnedGraph>,
        // None is the explicit NULL/0 input required by OTP mechanisms. A
        // present empty slice keeps its non-NULL pointer, including Update.
        input: Option<&'a mut [u8]>,
        // Converted before dispatch accounting and native-effect publication.
        input_length: CK_ULONG,
        signature: Signature<'a>,
    },
    Final {
        native: types::Final,
    },
}
impl Call<'_> {
    /// Invoke the exact selected function without a probe, retry or fallback.
    ///
    /// # Safety
    /// The function tuple and session must have been checked under possession.
    /// All referents must be stable, owned and retained after this borrow ends
    /// if the module has not established memory return. Input/output lengths
    /// must have been checked against the corresponding owned allocation.
    /// A missing input requires length zero; parameter graphs must have been
    /// checked against the selected module, mechanism and message route.
    pub(crate) unsafe fn invoke(self, session: CK_SESSION_HANDLE) -> CK_RV {
        // SAFETY: the caller establishes function availability, ABI dimensions,
        // ownership and serialization above. Each branch preserves its exact C
        // typedef; no function-pointer cast or shared scratch pointer is used.
        unsafe {
            match self {
                Self::Init {
                    native,
                    mechanism,
                    key,
                } => native(session, mechanism, key),
                Self::Begin { native, parameters } => {
                    let (parameters, parameter_length) = projection(parameters);
                    native(session, parameters, parameter_length)
                }
                Self::Data {
                    parameters,
                    input,
                    input_length,
                    signature,
                } => {
                    let (parameters, parameter_length) = projection(parameters);
                    let input = input.map_or(std::ptr::null_mut(), |bytes| bytes.as_mut_ptr());
                    match signature {
                        Signature::Produce { native, output } => {
                            let (pointer, length) = output.map_or(
                                (std::ptr::null_mut(), std::ptr::null_mut()),
                                |(bytes, length)| (bytes.as_mut_ptr(), length as *mut CK_ULONG),
                            );
                            let call = native;
                            call(
                                session,
                                parameters,
                                parameter_length,
                                input,
                                input_length,
                                pointer,
                                length,
                            )
                        }
                        Signature::Verify { native, signature } => {
                            let (pointer, length) = signature
                                .map_or((std::ptr::null_mut(), 0), |(bytes, length)| {
                                    (bytes.as_mut_ptr(), length)
                                });
                            let call = native;
                            call(
                                session,
                                parameters,
                                parameter_length,
                                input,
                                input_length,
                                pointer,
                                length,
                            )
                        }
                    }
                }
                Self::Final { native } => native(session),
            }
        }
    }
}

// Projection borrows the installed graph without copying its pointed-to data.
// The caller still owns and retains that graph after this call view expires.
fn projection(parameters: Option<&mut OwnedGraph>) -> (fe11_sys::CK_VOID_PTR, CK_ULONG) {
    parameters.map_or((std::ptr::null_mut(), 0), OwnedGraph::projection)
}
