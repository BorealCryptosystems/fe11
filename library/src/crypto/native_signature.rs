// SPDX-License-Identifier: Apache-2.0
//! Owned traditional signature mechanisms and synchronous signing sequences.
use super::{signature_encoding, EcCurve};
use crate::{bounds, session::Sequence, Error, Result, SecretBytes, Session};
use fe11_sys::*;

mod parameters;
pub(super) mod prehash;
pub(super) mod storage;
pub(crate) use parameters::{SignatureMechanism, SignatureParameters};

/// Output width and encoding fixed by the selected public key/profile.
pub(super) enum SignatureOutput {
    ExactLength(usize),
    Ecdsa(EcCurve),
}
impl SignatureOutput {
    fn capacity(&self) -> usize {
        match self {
            Self::ExactLength(length) => *length,
            Self::Ecdsa(curve) => 2 * curve.domain().width,
        }
    }
    fn valid(&self, signature: &[u8]) -> bool {
        signature.len() == self.capacity()
            && match self {
                Self::ExactLength(_) => true,
                Self::Ecdsa(curve) => signature_encoding::valid_ecdsa_output(*curve, signature),
            }
    }
}
impl Session {
    pub(super) fn sign_native_frame(
        &self,
        s: &crate::session::SessionAccess<'_>,
        object: CK_OBJECT_HANDLE,
        kind: CK_MECHANISM_TYPE,
        parameters: SignatureParameters<'_>,
        encoding: SignatureOutput,
        parts: &[&[u8]],
        multipart: bool,
        authentication: Option<&mut crate::session::PreparedContextLogin<'_>>,
        prepared: storage::Storage,
        diagnostics: &mut crate::crypto::ClassicalDiagnostics,
    ) -> Result<SecretBytes> {
        if !multipart && parts.len() != 1 {
            return Err(Error::Rejected(crate::RejectionReason::NativeSignature(
                crate::NativeSignatureRejection::SinglePartSignatureRequiresOneInput,
            )));
        }
        let handle = self.entry(s)?.handle;
        let init = s.native.table.C_SignInit.ok_or(Error::Rejected(
            crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::CSignInitUnavailable,
            ),
        ))?;
        // Retain one complete route before Init. A native return cannot change
        // the selected tuple or turn a later Update/Final into an absent entry.
        let route = if multipart {
            crate::crypto::native_route::Route::Multipart {
                update: s.native.table.C_SignUpdate.ok_or(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::CSignUpdateUnavailable,
                    ),
                ))?,
                finish: s.native.table.C_SignFinal.ok_or(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::CSignFinalUnavailable,
                    ),
                ))?,
            }
        } else {
            crate::crypto::native_route::Route::Single(s.native.table.C_Sign.ok_or(
                Error::Rejected(crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::CSignUnavailable,
                )),
            )?)
        };
        let empty: &[&[u8]] = &[&[]];
        let pieces = if parts.is_empty() { empty } else { parts };
        let mut capacity = 0;
        for piece in pieces {
            bounds::ck_length(piece.len())?;
            capacity = capacity.max(piece.len());
        }
        let width = encoding.capacity();
        let input_length = bounds::ck_length(capacity)?;
        let (prepared, diagnostic) = prepared.bind(kind, parameters, capacity, width)?;
        let diagnostic = diagnostics.primitive.insert(diagnostic).cell();
        let mut frame = crate::native::frame::NativeFrame::session(s.clone(), prepared)?;
        frame.data.mechanism.bind_parameters()?;
        {
            let (returned, body) = frame.session_parts();
            let s = &body.access;
            let call = &mut *body.data;
            s.native.record("C_SignInit")?;
            let sequence = Sequence::for_frame_prepared(s, self, returned, diagnostic);
            // SAFETY: the complete frame owns parameters and all inherited
            // session/key/selection/creation guards through final disposition.
            let rv = returned.observe(
                unsafe { init(handle, &mut call.mechanism.native, object) },
                &s.native,
            );
            sequence
                .inspect_return(
                    rv,
                    "C_SignInit",
                    crate::native_return::protocol::SequencePhase::Initialize,
                    || {
                        if !call.mechanism.unchanged(kind, parameters) {
                            Err(Error::Rejected(
                                crate::RejectionReason::ClassicalSignatures(
                                    crate::ClassicalSignaturesRejection::SignatureParametersChanged,
                                ),
                            ))
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
                if !call.mechanism.unchanged(kind, parameters) {
                    returned.quarantine(&s.native);
                    return Err(sequence.invalid_output(
                        crate::RejectionReason::ClassicalSignatures(crate::ClassicalSignaturesRejection::SignatureParametersChangedDuringContextAuthentication),
                    ));
                }
            }
            if let crate::crypto::native_route::Route::Multipart { update, .. } = route {
                for expected in pieces {
                    zeroize::Zeroize::zeroize(call.input.as_mut_slice());
                    call.input.as_mut_slice()[..expected.len()].copy_from_slice(expected);
                    let length = bounds::ck_length(expected.len())?;
                    sequence.record_next("C_SignUpdate")?;
                    // SAFETY: one stable protected scratch, reused only after
                    // synchronous Update success; no caller memory passed to C.
                    let rv = returned.observe(
                        unsafe { update(handle, call.input.as_mut_slice().as_mut_ptr(), length) },
                        &s.native,
                    );
                    sequence
                        .inspect_return(
                            rv,
                            "C_SignUpdate",
                            crate::native_return::protocol::SequencePhase::Continue(
                                crate::native_return::sequence::OutputRequest::Unspecified,
                            ),
                            || {
                                if !call.mechanism.unchanged(kind, parameters)
                                    || !call.input_unchanged(expected)
                                {
                                    Err(Error::Rejected(crate::RejectionReason::ClassicalSignatures(
                                crate::ClassicalSignaturesRejection::SignatureInputChanged,
                            )))
                                } else {
                                    Ok(())
                                }
                            },
                        )?
                        .check(false)?;
                }
            } else {
                call.input.as_mut_slice()[..pieces[0].len()].copy_from_slice(pieces[0]);
            }
            let function = if multipart { "C_SignFinal" } else { "C_Sign" };
            sequence.record_next(function)?;
            let rv = match route {
                crate::crypto::native_route::Route::Multipart { finish, .. } => {
                    // SAFETY: output and aligned length remain in the stable frame.
                    returned.observe(
                        unsafe {
                            finish(
                                handle,
                                call.signature.as_mut_slice().as_mut_ptr(),
                                &mut call.length,
                            )
                        },
                        &s.native,
                    )
                }
                crate::crypto::native_route::Route::Single(sign) => {
                    // SAFETY: bounded owned input/output, no size query or retry.
                    returned.observe(
                        unsafe {
                            sign(
                                handle,
                                call.input.as_mut_slice().as_mut_ptr(),
                                input_length,
                                call.signature.as_mut_slice().as_mut_ptr(),
                                &mut call.length,
                            )
                        },
                        &s.native,
                    )
                }
            };
            let last = pieces.last().expect("at least one signature piece");
            let result = sequence
                .inspect_output_return(
 rv, function, call.signature.len(), || call.length,
                    || {
                        if !call.mechanism.unchanged(kind, parameters)
                            || !call.input_unchanged(last)
                        {
                            Err(Error::Rejected(
                                crate::RejectionReason::ClassicalSignatures(
                                    crate::ClassicalSignaturesRejection::SignatureInputChanged,
                                ),
                            ))
                        } else {
                            if rv == CKR_OK {
                                bounds::final_length(call.length, call.signature.len()).map_err(|_| {
                                    Error::Rejected(crate::RejectionReason::ClassicalSignatures(
                                        crate::ClassicalSignaturesRejection::NativeSignatureOutputLength,
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
                return Err(Error::Rejected(
                    crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::SignatureCompletionUnproven,
                    ),
                ));
            }

            result?;
            let length = bounds::final_length(call.length, call.signature.len()).map_err(|_| {
                sequence.invalid_output(crate::RejectionReason::ClassicalSignatures(
                    crate::ClassicalSignaturesRejection::NativeSignatureOutputLength,
                ))
            })?;
            if length != call.signature.len() || !encoding.valid(call.signature.as_slice()) {
                return Err(
                    sequence.invalid_value(crate::RejectionReason::ClassicalSignatures(
                        crate::ClassicalSignaturesRejection::NativeSignatureEncoding,
                    )),
                );
            }
        }
        Ok(frame.into_inner()?.data.into_inner().signature)
    }
}
