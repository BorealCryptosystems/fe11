// SPDX-License-Identifier: Apache-2.0
//! Owned PQC call storage; byte credits travel with their native allocations.
use super::{parameters::NativeParameters, PqcAlgorithm, PqcSignature, PqcSignatureParameters};
use crate::{
    bounds, native::frame::NativeFrame, session::Sequence, symmetric::memory::Buffer, Error,
    Result, Session, Verification,
};
use fe11_sys::*;

mod preparation;
pub(super) use preparation::PreparedPqcCall;

type InputFunction = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV;
type SignFunction = unsafe extern "C" fn(
    CK_SESSION_HANDLE,
    CK_BYTE_PTR,
    CK_ULONG,
    CK_BYTE_PTR,
    CK_ULONG_PTR,
) -> CK_RV;
type SignFinalFunction =
    unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV;
type VerifyFunction =
    unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG) -> CK_RV;
#[derive(Clone, Copy)]
enum SignDispatch {
    Single(SignFunction),
    Multipart {
        update: InputFunction,
        finish: SignFinalFunction,
    },
}
#[derive(Clone, Copy)]
enum VerifyDispatch {
    Single(VerifyFunction),
    Multipart {
        update: InputFunction,
        finish: InputFunction,
    },
}

pub(super) struct PqcCall {
    native: NativeParameters,
    pub(super) mechanism: CK_MECHANISM,
    pub(super) input: Buffer,
    pub(super) signature: Buffer,
}
// SAFETY: native parameter boxes, context, input and signature are all owned;
// the enclosing data allocation stays fixed while native use may survive.
unsafe impl Send for PqcCall {}
impl PqcCall {
    /// Bind storage already paid for by an aggregate owner. This transition
    /// performs neither allocation nor resource admission.
    pub(super) fn from_prepared(
        algorithm: PqcAlgorithm,
        mut native: NativeParameters,
        input: Buffer,
        signature: Buffer,
    ) -> Result<Self> {
        // The parameter boxes and context allocation already have stable
        // addresses; the enclosing CK_MECHANISM is pinned by NativeFrame.
        let mechanism = native.mechanism(algorithm)?;
        Ok(Self {
            native,
            mechanism,
            input,
            signature,
        })
    }
    pub(super) fn prepare_input(&mut self, message: &[u8]) {
        zeroize::Zeroize::zeroize(self.input.as_mut());
        self.input.as_mut()[..message.len()].copy_from_slice(message);
    }
    pub(super) fn unchanged(
        &self,
        algorithm: PqcAlgorithm,
        parameters: &PqcSignatureParameters,
        message: &[u8],
    ) -> bool {
        self.native
            .unchanged(&self.mechanism, algorithm, parameters)
            && &self.input.as_slice()[..message.len()] == message
            && self.input.as_slice()[message.len()..]
                .iter()
                .all(|byte| *byte == 0)
    }
}
pub(super) struct SigningCall {
    buffers: PqcCall,
    length: CK_ULONG,
    _credit: crate::symmetric::memory::Credit,
}

/// Invocation diagnostics never enter the native frame. Their credits remain at
/// the public signing boundary even when authentication or publication fails.
#[derive(Default)]
pub(super) struct SigningDiagnostics {
    pub(super) sequence: Option<crate::error::PreparedCompletionCell>,
    pub(super) authentication: Option<crate::session::ContextDiagnostics>,
}

impl Session {
    pub(super) fn pqc_sign_parts_guarded(
        &self,
        state: &crate::session::SessionAccess<'_>,
        key: CK_OBJECT_HANDLE,
        algorithm: PqcAlgorithm,
        parameters: &PqcSignatureParameters,
        parts: &[&[u8]],
        multipart: bool,
        authentication: Option<&mut crate::session::PreparedContextLogin<'_>>,
        prepared: SigningCall,
        diagnostic: &crate::error::CompletionCell,
    ) -> Result<PqcSignature> {
        if !multipart && parts.len() != 1 {
            return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::SinglePartPqcSignatureRequiresOneInput,
            )));
        }
        let handle = self.entry(state)?.handle;
        let init = state.native.table.C_SignInit.ok_or(Error::Rejected(
            crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::CSignInitUnavailable,
            ),
        ))?;
        let dispatch = if multipart {
            SignDispatch::Multipart {
                update: state.native.table.C_SignUpdate.ok_or(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::CSignUpdateUnavailable,
                    ),
                ))?,
                finish: state.native.table.C_SignFinal.ok_or(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::CSignFinalUnavailable,
                    ),
                ))?,
            }
        } else {
            SignDispatch::Single(state.native.table.C_Sign.ok_or(Error::Rejected(
                crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::CSignUnavailable,
                ),
            ))?)
        };
        let parts = super::multipart::nonempty_parts(parts);
        let single_input_length = bounds::ck_length(parts[0].len())?;
        let mut frame = NativeFrame::session(state.clone(), prepared)?;
        {
            let (returned, body) = frame.session_parts();
            let state = &body.access;
            let call = &mut *body.data;
            state.native.record("C_SignInit")?;
            let sequence = Sequence::for_frame_prepared(state, self, returned, diagnostic);
            // SAFETY: complete frame owns context, native descriptors and all
            // inherited guards; no pointer is borrowed from the caller.
            let rv = returned.observe(
                unsafe { init(handle, &mut call.buffers.mechanism, key) },
                &state.native,
            );
            sequence
                .inspect_return(
                    rv,
                    "C_SignInit",
                    crate::native_return::protocol::SequencePhase::Initialize,
                    || {
                        if !call.buffers.unchanged(algorithm, parameters, &[]) {
                            Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                                crate::PostQuantumKeysRejection::PqcSignatureParametersChanged,
                            )))
                        } else {
                            Ok(())
                        }
                    },
                )?
                .check(false)?;
            if let Some(authentication) = authentication {
                if let Err(error) = authentication.perform(self) {
                    returned.recoverable();
                    return Err(error);
                }
                if !call.buffers.unchanged(algorithm, parameters, &[]) {
                    returned.quarantine(&state.native);
                    return Err(sequence.invalid_output(
                        crate::RejectionReason::PostQuantumKeys(crate::PostQuantumKeysRejection::PqcSignatureParametersChangedDuringContextAuthentication),
                    ));
                }
            }

            if let SignDispatch::Multipart { update, .. } = dispatch {
                for part in parts {
                    call.buffers.prepare_input(part);
                    let length = bounds::ck_length(part.len())?;
                    sequence.record_next("C_SignUpdate")?;
                    // SAFETY: preallocated scratch and credit retained until
                    // known completion; only a successful Update permits reuse.
                    let rv = returned.observe(
                        unsafe { update(handle, call.buffers.input.as_mut().as_mut_ptr(), length) },
                        &state.native,
                    );
                    sequence
                        .inspect_return(
                            rv,
                            "C_SignUpdate",
                            crate::native_return::protocol::SequencePhase::Continue(
                                crate::native_return::sequence::OutputRequest::Unspecified,
                            ),
                            || {
                                if !call.buffers.unchanged(algorithm, parameters, part) {
                                    Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                                        crate::PostQuantumKeysRejection::PqcSignatureInputChanged,
                                    )))
                                } else {
                                    Ok(())
                                }
                            },
                        )?
                        .check(false)?;
                }
            } else {
                call.buffers.prepare_input(parts[0]);
            }
            let function = match dispatch {
                SignDispatch::Single(_) => "C_Sign",
                SignDispatch::Multipart { .. } => "C_SignFinal",
            };
            sequence.record_next(function)?;
            // SAFETY: stable exact-width output, aligned owned length and
            // protected input. No size query, fallback or private-effect retry.
            let rv = returned.observe(
                unsafe {
                    match dispatch {
                        SignDispatch::Multipart { finish, .. } => finish(
                            handle,
                            call.buffers.signature.as_mut().as_mut_ptr(),
                            &mut call.length,
                        ),
                        SignDispatch::Single(sign) => sign(
                            handle,
                            call.buffers.input.as_mut().as_mut_ptr(),
                            single_input_length,
                            call.buffers.signature.as_mut().as_mut_ptr(),
                            &mut call.length,
                        ),
                    }
                },
                &state.native,
            );
            let last = parts.last().expect("at least one PQC signature part");
            let result = sequence
                .inspect_output_return(
                    rv,
                    function,
                    call.buffers.signature.capacity(),
                    || call.length,
                    || {
                        if !call.buffers.unchanged(algorithm, parameters, last) {
                            Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                                crate::PostQuantumKeysRejection::PqcSignatureInputChanged,
                            )))
                        } else {
                            if rv == CKR_OK {
                                bounds::final_length(
                                    call.length,
                                    call.buffers.signature.capacity(),
                                )
                                .map_err(|_| {
                                    Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                                        crate::PostQuantumKeysRejection::PqcNativeSignatureLength,
                                    ))
                                })?;
                            }
                            Ok(())
                        }
                    },
                )?
                .check(false);
            if !sequence.termination_known() {
                result?;
                return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                    crate::PostQuantumKeysRejection::PqcSignatureCompletionUnproven,
                )));
            }

            result?;
            if bounds::final_length(call.length, call.buffers.signature.capacity()).map_err(
                |_| {
                    sequence.invalid_output(crate::RejectionReason::PostQuantumKeys(
                        crate::PostQuantumKeysRejection::PqcNativeSignatureLength,
                    ))
                },
            )? != call.buffers.signature.capacity()
            {
                return Err(
                    sequence.invalid_value(crate::RejectionReason::PostQuantumKeys(
                        crate::PostQuantumKeysRejection::PqcNativeSignatureWidth,
                    )),
                );
            }
        }
        PqcSignature::from_native(
            algorithm,
            frame.into_inner()?.data.into_inner().buffers.signature,
        )
    }

    pub(super) fn pqc_verify_parts_guarded(
        &self,
        state: &crate::session::SessionAccess<'_>,
        key: CK_OBJECT_HANDLE,
        algorithm: PqcAlgorithm,
        parameters: &PqcSignatureParameters,
        parts: &[&[u8]],
        multipart: bool,
        signature: &[u8],
        prepared: PreparedPqcCall,
        diagnostic: &crate::error::CompletionCell,
    ) -> Result<Verification> {
        if !multipart && parts.len() != 1 {
            return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::SinglePartPqcVerificationRequiresOneInput,
            )));
        }
        let handle = self.entry(state)?.handle;
        let init = state.native.table.C_VerifyInit.ok_or(Error::Rejected(
            crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::CVerifyInitUnavailable,
            ),
        ))?;
        let dispatch = if multipart {
            VerifyDispatch::Multipart {
                update: state.native.table.C_VerifyUpdate.ok_or(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::CVerifyUpdateUnavailable,
                    ),
                ))?,
                finish: state.native.table.C_VerifyFinal.ok_or(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::CVerifyFinalUnavailable,
                    ),
                ))?,
            }
        } else {
            VerifyDispatch::Single(state.native.table.C_Verify.ok_or(Error::Rejected(
                crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::CVerifyUnavailable,
                ),
            ))?)
        };
        let parts = super::multipart::nonempty_parts(parts);
        let single_input_length = bounds::ck_length(parts[0].len())?;
        let signature_length = bounds::ck_length(signature.len())?;
        let mut frame = NativeFrame::session(state.clone(), prepared)?;
        let (returned, body) = frame.session_parts();
        let state = &body.access;
        let call = body.data.call_mut();
        state.native.record("C_VerifyInit")?;
        let sequence = Sequence::for_frame_prepared(state, self, returned, diagnostic);
        // SAFETY: all addressed storage and its credits live in the complete
        // frame; the access owner retains the original object read permit.
        let rv = returned.observe(
            unsafe { init(handle, &mut call.mechanism, key) },
            &state.native,
        );
        sequence
            .inspect_return(
                rv,
                "C_VerifyInit",
                crate::native_return::protocol::SequencePhase::Initialize,
                || {
                    if !call.unchanged(algorithm, parameters, &[]) {
                        Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                            crate::PostQuantumKeysRejection::PqcVerificationParametersChanged,
                        )))
                    } else {
                        Ok(())
                    }
                },
            )?
            .check(false)?;
        if let VerifyDispatch::Multipart { update, .. } = dispatch {
            for part in parts {
                call.prepare_input(part);
                let length = bounds::ck_length(part.len())?;
                sequence.record_next("C_VerifyUpdate")?;
                // SAFETY: each bounded piece is copied into the stable scratch.
                let rv = returned.observe(
                    unsafe { update(handle, call.input.as_mut().as_mut_ptr(), length) },
                    &state.native,
                );
                sequence
                    .inspect_return(
                        rv,
                        "C_VerifyUpdate",
                        crate::native_return::protocol::SequencePhase::Continue(
                            crate::native_return::sequence::OutputRequest::Unspecified,
                        ),
                        || {
                            if !call.unchanged(algorithm, parameters, part) {
                                Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                                    crate::PostQuantumKeysRejection::PqcVerificationInputChanged,
                                )))
                            } else {
                                Ok(())
                            }
                        },
                    )?
                    .check(false)?;
            }
        } else {
            call.prepare_input(parts[0]);
        }
        let function = match dispatch {
            VerifyDispatch::Single(_) => "C_Verify",
            VerifyDispatch::Multipart { .. } => "C_VerifyFinal",
        };
        sequence.record_next(function)?;
        // SAFETY: exact signature copy and bounded input owned by this frame.
        let rv = returned.observe(
            unsafe {
                match dispatch {
                    VerifyDispatch::Multipart { finish, .. } => finish(
                        handle,
                        call.signature.as_mut().as_mut_ptr(),
                        signature_length,
                    ),
                    VerifyDispatch::Single(verify) => verify(
                        handle,
                        call.input.as_mut().as_mut_ptr(),
                        single_input_length,
                        call.signature.as_mut().as_mut_ptr(),
                        signature_length,
                    ),
                }
            },
            &state.native,
        );
        let last = parts.last().expect("at least one PQC verification part");
        let result = sequence
            .inspect_return(
                rv,
                function,
                crate::native_return::protocol::SequencePhase::Continue(
                    crate::native_return::sequence::OutputRequest::Unspecified,
                ),
                || {
                    if !call.unchanged(algorithm, parameters, last)
                        || call.signature.as_slice() != signature
                    {
                        Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                            crate::PostQuantumKeysRejection::PqcVerificationInputChanged,
                        )))
                    } else {
                        Ok(())
                    }
                },
            )?
            .check(false);
        if !sequence.termination_known() {
            result?;
            return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcVerificationCompletionUnproven,
            )));
        }

        match rv {
            CKR_OK => Ok(Verification::Valid),
            CKR_SIGNATURE_INVALID | CKR_SIGNATURE_LEN_RANGE => Ok(Verification::Invalid),
            _ => result.map(|_| unreachable!()),
        }
    }
}
