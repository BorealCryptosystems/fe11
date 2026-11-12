// SPDX-License-Identifier: Apache-2.0
//! Explicit PKCS#11 3.2 verification with the signature supplied at Init.

use super::{
    frame::PreparedPqcCall, PqcSignature, PqcSignatureMode, PqcSignatureParameters,
    PqcVerificationKey,
};
use crate::{
    bounds, interfaces::VerifySignatureFunctions, session::Sequence, Error, InputLimits, Result,
    Session, Verification,
};
use fe11_sys::*;

type DataFunction = unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV;
type FinalFunction = unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV;

enum Input<'a> {
    Single(&'a [u8]),
    Multipart(&'a [&'a [u8]]),
}

// Each variant owns the complete dispatch contract for one valid sequence.
// An Update path cannot accidentally terminate with the single-part function.
enum Prepared<'a> {
    Single {
        message: &'a [u8],
        verify: DataFunction,
    },
    Multipart {
        parts: &'a [&'a [u8]],
        update: DataFunction,
        finish: FinalFunction,
    },
}

impl<'a> Input<'a> {
    fn validate(
        &self,
        parameters: &PqcSignatureParameters,
        limits: InputLimits,
        module: crate::CryptoLimits,
    ) -> Result<()> {
        match self {
            Self::Single(message) => {
                super::parameters::validate_message(limits, module, message.len())?;
                parameters.validate_input(message.len())
            }
            Self::Multipart(parts) => {
                if matches!(parameters.mode(), PqcSignatureMode::Prehashed(_)) {
                    return Err(Error::Unsupported(
                        crate::UnsupportedReason::PostQuantumKeys(crate::PostQuantumKeysUnsupported::Pkcs11PqcExternalPrehashIsSinglePartOnly),
                    ));
                }
                limits.validate(module, parts)
            }
        }
    }

    fn buffer_length(&self) -> usize {
        match self {
            Self::Single(message) => message.len(),
            Self::Multipart(parts) => parts.iter().map(|part| part.len()).max().unwrap_or(0),
        }
    }

    fn prepare(self, functions: VerifySignatureFunctions) -> Result<Prepared<'a>> {
        match self {
            Self::Single(message) => Ok(Prepared::Single {
                message,
                verify: functions.single.ok_or(Error::Rejected(
                    crate::RejectionReason::PostQuantumKeys(
                        crate::PostQuantumKeysRejection::CVerifySignatureUnavailable,
                    ),
                ))?,
            }),
            Self::Multipart(parts) => Ok(Prepared::Multipart {
                parts,
                update: functions.update.ok_or(Error::Rejected(
                    crate::RejectionReason::PostQuantumKeys(
                        crate::PostQuantumKeysRejection::CVerifySignatureUpdateUnavailable,
                    ),
                ))?,
                finish: functions.finish.ok_or(Error::Rejected(
                    crate::RejectionReason::PostQuantumKeys(
                        crate::PostQuantumKeysRejection::CVerifySignatureFinalUnavailable,
                    ),
                ))?,
            }),
        }
    }
}

impl Session {
    /// Explicitly use C_VerifySignatureInit/C_VerifySignature (PKCS#11 3.2).
    /// The signature and context remain owned until verification terminates.
    /// An absent function or native refusal never selects another family.
    pub fn verify_pqc_signature(
        &self,
        key: &PqcVerificationKey,
        parameters: &PqcSignatureParameters,
        message: &[u8],
        signature: &PqcSignature,
        limits: InputLimits,
    ) -> Result<Verification> {
        let mut diagnostic = None;
        self.verify_pqc_signature_input(
            key,
            parameters,
            Input::Single(message),
            signature,
            limits,
            &mut diagnostic,
        )
    }

    /// Explicitly use C_VerifySignatureUpdate/Final after signature-bearing Init.
    /// Pure and token-hashed modes accept bounded fragments, including empty ones.
    /// A list without fragments represents one empty fragment and one Update.
    /// External prehash input remains single-part only.
    pub fn verify_pqc_signature_multipart(
        &self,
        key: &PqcVerificationKey,
        parameters: &PqcSignatureParameters,
        parts: &[&[u8]],
        signature: &PqcSignature,
        limits: InputLimits,
    ) -> Result<Verification> {
        let mut diagnostic = None;
        self.verify_pqc_signature_input(
            key,
            parameters,
            Input::Multipart(super::multipart::nonempty_parts(parts)),
            signature,
            limits,
            &mut diagnostic,
        )
    }

    fn verify_pqc_signature_input(
        &self,
        key: &PqcVerificationKey,
        parameters: &PqcSignatureParameters,
        input: Input<'_>,
        signature: &PqcSignature,
        limits: InputLimits,
        diagnostic_root: &mut Option<crate::error::PreparedCompletionCell>,
    ) -> Result<Verification> {
        input.validate(parameters, limits, self.inner.crypto_options.limits)?;
        if signature.algorithm() != key.algorithm {
            return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcSignatureAlgorithmMismatch,
            )));
        }
        parameters.mechanism_type(key.algorithm)?;

        let epoch = self.snapshot.authentication_stamp();
        let progress = crate::session::AdmissionProgress::default()
            .retaining(signature.retained_bytes(&self.inner.symmetric_budget)?)?;
        let ((buffers, prepared_diagnostic), state) = self.prepare_with_roles_prepaid_at_epoch(
            [(
                Some(&key.managed),
                crate::session::activity::AccessMode::Read,
            )],
            false,
            epoch,
            &progress,
            |overhead| {
                PreparedPqcCall::verification(
                    self,
                    key.algorithm,
                    parameters,
                    input.buffer_length(),
                    signature.as_bytes(),
                    &progress,
                    epoch,
                    overhead,
                )
            },
        )?;
        let diagnostic = diagnostic_root.insert(prepared_diagnostic).cell();
        let handle = self.managed_handle(&state, &key.managed)?;
        let session_handle = self.entry(&state)?.handle;
        let functions = state.native.verify_signature.ok_or(Error::Unsupported(
            crate::UnsupportedReason::PostQuantumKeys(
                crate::PostQuantumKeysUnsupported::VerifysignatureRequiresThePkcs1132Interface,
            ),
        ))?;
        let init =
            functions
                .init
                .ok_or(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                    crate::PostQuantumKeysRejection::CVerifySignatureInitUnavailable,
                )))?;
        let prepared = input.prepare(functions)?;
        let signature_length = bounds::ck_length(signature.as_bytes().len())?;
        let mut frame = crate::native::frame::NativeFrame::session(state.clone(), buffers)?;
        let verdict = {
            let (returned, body) = frame.session_parts();
            let state = &body.access;
            let call = body.data.call_mut();
            state.native.record("C_VerifySignatureInit")?;
            let sequence = Sequence::for_frame_prepared(state, self, returned, diagnostic);
            // SAFETY: signature-bearing Init receives only owned stable frame
            // storage; its parameters, signature, credits and guards survive all
            // subsequent calls, or remain retained on unproven completion.
            let rv = returned.observe(
                unsafe {
                    init(
                        session_handle,
                        &mut call.mechanism,
                        handle,
                        call.signature.as_mut().as_mut_ptr(),
                        signature_length,
                    )
                },
                &state.native,
            );
            sequence
                .inspect_return(
                    rv,
                    "C_VerifySignatureInit",
                    crate::native_return::protocol::SequencePhase::Initialize,
                    || {
                        if !call.unchanged(key.algorithm, parameters, &[])
                            || call.signature.as_slice() != signature.as_bytes()
                        {
                            Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                                crate::PostQuantumKeysRejection::PqcVerifysignatureInputChanged,
                            )))
                        } else {
                            Ok(())
                        }
                    },
                )?
                .check(false)?;

            let (rv, function, last) =
                match prepared {
                    Prepared::Single { message, verify } => {
                        call.prepare_input(message);
                        let length = bounds::ck_length(message.len())?;
                        sequence.record_next("C_VerifySignature")?;
                        // SAFETY: exact prevalidated input in the complete frame.
                        let rv = returned.observe(
                            unsafe {
                                verify(session_handle, call.input.as_mut().as_mut_ptr(), length)
                            },
                            &state.native,
                        );
                        (rv, "C_VerifySignature", message)
                    }
                    Prepared::Multipart {
                        parts,
                        update,
                        finish,
                    } => {
                        for part in parts {
                            call.prepare_input(part);
                            let length = bounds::ck_length(part.len())?;
                            sequence.record_next("C_VerifySignatureUpdate")?;
                            // SAFETY: scratch reuse follows only synchronous Update
                            // success; all native addresses remain in the frame.
                            let rv = returned.observe(
                                unsafe {
                                    update(session_handle, call.input.as_mut().as_mut_ptr(), length)
                                },
                                &state.native,
                            );
                            sequence.inspect_return(
            rv, "C_VerifySignatureUpdate",
            crate::native_return::protocol::SequencePhase::Continue(
                crate::native_return::sequence::OutputRequest::Unspecified
            ),
            || {
                if !call.unchanged(key.algorithm, parameters, part)
                            || call.signature.as_slice() != signature.as_bytes() {
                    Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                                    crate::PostQuantumKeysRejection::PqcVerifysignatureInputChanged,
                                )))
                } else {
                    Ok(())
                }
            },
        )?.check(false)?;
                        }
                        sequence.record_next("C_VerifySignatureFinal")?;
                        // SAFETY: same owned session and signature-bearing Init;
                        // every parameter/buffer and byte credit is still retained.
                        let rv = returned.observe(unsafe { finish(session_handle) }, &state.native);
                        (
                            rv,
                            "C_VerifySignatureFinal",
                            *parts.last().expect("nonempty prepared parts"),
                        )
                    }
                };
            let result = sequence
                .inspect_return(
                    rv,
                    function,
                    crate::native_return::protocol::SequencePhase::Continue(
                        crate::native_return::sequence::OutputRequest::Unspecified,
                    ),
                    || {
                        if !call.unchanged(key.algorithm, parameters, last)
                            || call.signature.as_slice() != signature.as_bytes()
                        {
                            Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                                crate::PostQuantumKeysRejection::PqcVerifysignatureInputChanged,
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
                    crate::PostQuantumKeysRejection::PqcVerifysignatureCompletionUnproven,
                )));
            }

            match rv {
                CKR_OK => Verification::Valid,
                CKR_SIGNATURE_INVALID | CKR_SIGNATURE_LEN_RANGE => Verification::Invalid,
                _ => {
                    result?;
                    unreachable!()
                }
            }
        };
        self.managed_result(&state, &key.managed, Ok(verdict))
    }
}
