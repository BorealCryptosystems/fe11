// SPDX-License-Identifier: Apache-2.0
//! Byte-output C_DeriveKey contracts: no object template, handle or cleanup.
use super::*;
use crate::native::frame::SessionFrame;
use crate::{InputLimits, NativeObjectRef, NativePrfOutput, TlsPrfMechanism, TlsPrfRequest};
use std::sync::atomic::Ordering;

enum Parameters {
    Tls(CK_TLS_PRF_PARAMS),
    Wtls(CK_WTLS_PRF_PARAMS),
}
struct Prf {
    mechanism: CK_MECHANISM,
    selected: TlsPrfMechanism,
    parameters: Parameters,
    seed: InputBytes,
    label: InputBytes,
    output: Buffer,
    length: CK_ULONG,
    expected: CK_ULONG,
    _credit: Credit,
}
// Keep the read authority with the native buffers, including an uncertain
// return. It does not need a separate heap-allocated permission collection.
struct ProtectedPrf {
    prf: Prf,
    _source: crate::registry::ReadPermit,
    _credit: Credit,
}
// SAFETY: the stabilized frame owns every referent, including the native output
// length. Its enclosing session frame retains the source activity and image on
// pending/uncertain completion, so no pointer outlives its allocation.
unsafe impl Send for Prf {}
impl Prf {
    fn allocation_bytes(request: &TlsPrfRequest<'_>) -> Result<usize> {
        bounds::ck_length(request.seed.len())?;
        bounds::ck_length(request.label.len())?;
        bounds::ck_length(request.output_bytes)?;
        if let TlsPrfMechanism::Wtls { digest } = request.mechanism {
            native_ulong(digest)?;
        }
        request
            .seed
            .len()
            .checked_add(request.label.len())
            .and_then(|n| n.checked_mul(2))
            .and_then(|n| n.checked_add(request.output_bytes))
            .and_then(|n| n.checked_add(size_of::<Self>()))
            .ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
                crate::NativeDerivationRejection::TlsPrfStorageAccounting,
            )))
    }
    fn new(request: TlsPrfRequest<'_>, prepaid: &mut Credit) -> Result<Self> {
        let credit = prepaid.split(size_of::<Self>())?;
        let mut seed = InputBytes::new(request.seed, prepaid)?;
        let mut label = InputBytes::new(request.label, prepaid)?;
        let mut output = Buffer::new_prepaid(prepaid, request.output_bytes)?;
        let length = bounds::ck_length(request.output_bytes)?;
        let (kind, parameters) = match request.mechanism {
            TlsPrfMechanism::Tls => (
                CKM_TLS_PRF,
                Parameters::Tls(CK_TLS_PRF_PARAMS {
                    pSeed: seed.pointer(),
                    ulSeedLen: seed.length(),
                    pLabel: label.pointer(),
                    ulLabelLen: label.length(),
                    pOutput: output.as_mut().as_mut_ptr(),
                    pulOutputLen: std::ptr::null_mut(),
                }),
            ),
            TlsPrfMechanism::Wtls { digest } => (
                CKM_WTLS_PRF,
                Parameters::Wtls(CK_WTLS_PRF_PARAMS {
                    DigestMechanism: native_ulong(digest)?,
                    pSeed: seed.pointer(),
                    ulSeedLen: seed.length(),
                    pLabel: label.pointer(),
                    ulLabelLen: label.length(),
                    pOutput: output.as_mut().as_mut_ptr(),
                    pulOutputLen: std::ptr::null_mut(),
                }),
            ),
        };
        Ok(Self {
            mechanism: CK_MECHANISM {
                mechanism: kind,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
            selected: request.mechanism,
            parameters,
            seed,
            label,
            output,
            length,
            expected: length,
            _credit: credit,
        })
    }
    fn bind(&mut self) {
        let (pointer, length) = match &mut self.parameters {
            Parameters::Tls(raw) => {
                raw.pulOutputLen = &mut self.length;
                (
                    (raw as *mut CK_TLS_PRF_PARAMS).cast(),
                    size_of::<CK_TLS_PRF_PARAMS>() as CK_ULONG,
                )
            }
            Parameters::Wtls(raw) => {
                raw.pulOutputLen = &mut self.length;
                (
                    (raw as *mut CK_WTLS_PRF_PARAMS).cast(),
                    size_of::<CK_WTLS_PRF_PARAMS>() as CK_ULONG,
                )
            }
        };
        self.mechanism.pParameter = pointer;
        self.mechanism.ulParameterLen = length;
    }
    fn unchanged(&self) -> bool {
        let length_slot = (&self.length as *const CK_ULONG).cast_mut();
        let output = self.output.as_slice().as_ptr().cast_mut();
        let (pointer, length, kind, descriptor) = match &self.parameters {
            Parameters::Tls(raw) => (
                (raw as *const CK_TLS_PRF_PARAMS).cast_mut().cast(),
                size_of::<CK_TLS_PRF_PARAMS>() as CK_ULONG,
                CKM_TLS_PRF,
                raw.pSeed == self.seed.expected_pointer()
                    && raw.ulSeedLen == self.seed.length()
                    && raw.pLabel == self.label.expected_pointer()
                    && raw.ulLabelLen == self.label.length()
                    && raw.pOutput == output
                    && raw.pulOutputLen == length_slot,
            ),
            Parameters::Wtls(raw) => (
                (raw as *const CK_WTLS_PRF_PARAMS).cast_mut().cast(),
                size_of::<CK_WTLS_PRF_PARAMS>() as CK_ULONG,
                CKM_WTLS_PRF,
                matches!(self.selected, TlsPrfMechanism::Wtls { digest } if raw.DigestMechanism as u64 == digest)
                    && raw.pSeed == self.seed.expected_pointer()
                    && raw.ulSeedLen == self.seed.length()
                    && raw.pLabel == self.label.expected_pointer()
                    && raw.ulLabelLen == self.label.length()
                    && raw.pOutput == output
                    && raw.pulOutputLen == length_slot,
            ),
        };
        let bytes = self.seed.unchanged() & self.label.unchanged();
        self.mechanism.mechanism == kind
            && self.mechanism.pParameter == pointer
            && self.mechanism.ulParameterLen == length
            && descriptor
            && bytes
    }
}

fn prepare<'a>(
    session: &'a Session,
    base: &NativeObjectRef,
    request: &TlsPrfRequest<'_>,
) -> Result<(
    crate::error::PreparedCompletion,
    ProtectedPrf,
    crate::session::SessionAccess<'a>,
)> {
    let enclosing = size_of::<ProtectedPrf>()
        .checked_sub(size_of::<Prf>())
        .and_then(|bytes| bytes.checked_add(SessionFrame::<'_, ProtectedPrf>::allocation_bytes()))
        .ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
            crate::NativeDerivationRejection::TlsPrfFrameAccounting,
        )))?;
    let bytes = Prf::allocation_bytes(request)?
        .checked_add(enclosing)
        .and_then(|bytes| bytes.checked_add(crate::error::PreparedCompletion::allocation_bytes()))
        .ok_or(Error::Rejected(crate::RejectionReason::NativeDerivation(
            crate::NativeDerivationRejection::TlsPrfStorageAccounting,
        )))?;
    let progress = crate::session::AdmissionProgress::default();
    let admission = crate::admission_wait::current();
    let session_admission = session.admission();
    {
        let access = session.access_progress(&progress)?;
        session.native_object_handle(&access, base)?;
    }
    // UID attribution is shared Activity storage, not a private permission
    // vector. Prepare it before reserving any of this call's private buffers.
    let readers =
        crate::session::activity::Readers::prepare(session, [Some(base.identity.activity()?)])?;
    loop {
        // One reservation covers all private storage. A budget wait therefore
        // retains neither a partial permission credit nor a partial PRF frame.
        let mut prepaid =
            crate::advanced::reserve_preparation_with_progress(session, bytes, &progress)?;
        let prf = Prf::new(
            TlsPrfRequest {
                mechanism: request.mechanism,
                seed: request.seed,
                label: request.label,
                output_bytes: request.output_bytes,
            },
            &mut prepaid,
        )?;
        let diagnostic = crate::error::PreparedCompletion::prepare("C_DeriveKey", &mut prepaid)?;
        let attempt = readers.try_acquire(session, || {
            session.try_operation_access_progress(false, &progress)
        });
        match attempt {
            Ok((access, [Some(source)])) => {
                session.native_object_handle(&access, base)?;
                return Ok((
                    diagnostic,
                    ProtectedPrf {
                        prf,
                        _source: source,
                        _credit: prepaid,
                    },
                    access,
                ));
            }
            Ok(_) => {
                return Err(Error::Rejected(crate::RejectionReason::NativeDerivation(
                    crate::NativeDerivationRejection::TlsPrfSourcePermissionAbsent,
                )))
            }
            Err(error @ Error::Busy(_)) => {
                drop(prf);
                drop(diagnostic);
                drop(prepaid);
                if matches!(admission, crate::ResourceAdmission::Immediate)
                    && matches!(session_admission, crate::SessionAdmission::Immediate)
                {
                    return Err(error);
                }
            }
            Err(error) => return Err(error),
        }
        // Wait only for local availability with no private candidate. Drop the
        // temporary grant before rebuilding; no native derivation has run yet.
        drop(readers.acquire(session, || session.access_progress(&progress))?);
    }
}

pub(crate) fn derive(
    session: &Session,
    base: &NativeObjectRef,
    request: TlsPrfRequest<'_>,
    limits: InputLimits,
    diagnostic_root: &mut Option<crate::error::PreparedCompletion>,
) -> Result<NativePrfOutput> {
    limits.validate(
        session.inner.crypto_options.limits,
        &[request.seed, request.label],
    )?;
    let (prepared_diagnostic, prepared, state) = prepare(session, base, &request)?;
    // Keep both an unused leaf and its charge at the actual public boundary.
    let diagnostic_owner = diagnostic_root.insert(prepared_diagnostic);
    session.entry(&state)?;
    let handle = session.managed_handle(&state, base)?;
    let native = state.native.table.C_DeriveKey.ok_or(Error::Rejected(
        crate::RejectionReason::NativeDerivation(
            crate::NativeDerivationRejection::CDeriveKeyUnavailable,
        ),
    ))?;
    let call = MutationCall::Derive;
    let diagnostic = diagnostic_owner.take()?;
    let mut frame = NativeFrame::session(state.clone(), prepared)?;
    {
        let (returned, body) = frame.session_parts();
        let access = &body.access;
        let data = &mut body.data.prf;
        data.bind();
        // Preserve creation-family close coordination for this entry even for
        // a PRF whose native contract creates no objects. The call's effect
        // classification remains independent of this conservative history.
        session
            .entry
            .creation_attempted
            .store(true, Ordering::Release);
        access.native.record_derivation_without_objects()?;
        returned.arm();
        // SAFETY: exact byte-output mechanism, stable owned descriptors and
        // output. Its normative contract requires NULL template and phKey.
        let rv = returned.observe(
            unsafe {
                native(
                    session.entry.handle,
                    &mut data.mechanism,
                    handle,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                )
            },
            &access.native,
        );
        let inspection =
            session.inspect_native_inputs(access, call.function(), rv, || data.unchanged());
        let known = inspection.memory_returned();
        if !known {
            returned.recoverable();
            session.poison(access);
            return crate::error::check(rv, call.function(), true).map(|()| unreachable!());
        }
        if inspection.violated() {
            returned.quarantine(&access.native);
            return Err(diagnostic.boundary_failure(
                rv,
                Error::Rejected(crate::RejectionReason::NativeDerivation(
                    crate::NativeDerivationRejection::TlsPrfNativeInputMutation,
                )),
            ));
        }
        // Only success defines the output size. Inspect its advertised writable
        // extent before releasing storage; bounded semantic checks follow below.
        if rv == CKR_OK && data.length > data.expected {
            returned.quarantine(&access.native);
            return Err(diagnostic.boundary_failure(
                rv,
                Error::Rejected(crate::RejectionReason::NativeDerivation(
                    crate::NativeDerivationRejection::TlsPrfOutputLengthChanged,
                )),
            ));
        }
        returned.terminated();
        // TLS/WTLS PRF failure generates no output and creates no objects.
        inspection.check(
            !inspection.no_objects(crate::native_return::protocol::CreationContract::NoObjects),
        )?;
        if data.length != data.expected {
            return diagnostic.finish(Err(Error::Rejected(
                crate::RejectionReason::NativeDerivation(
                    crate::NativeDerivationRejection::TlsPrfOutputLengthChanged,
                ),
            )));
        }
    }
    let ProtectedPrf {
        prf: data,
        _source,
        _credit,
    } = match frame.into_inner() {
        Ok(frame) => frame.data.into_inner(),
        Err(cause) => return diagnostic.finish(Err(cause)),
    };
    let output = NativePrfOutput {
        bytes: data.output,
        mechanism: data.selected,
    };
    diagnostic.finish(base.identity.access().result(session, &state, Ok(output)))
}
