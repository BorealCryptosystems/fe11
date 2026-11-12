// SPDX-License-Identifier: Apache-2.0
//! One Init/use sequence under the shared native completion and context owner.
use super::*;
use crate::{
    bounds,
    error::CompletionStorage,
    native::{derivation::InputBytes, frame::NativeFrame},
    session::{PreparedContextLogin, Sequence},
    symmetric::memory::{Buffer, Credit},
};
use fe11_sys::*;
use std::mem::size_of;

mod diagnostics;
mod input;
mod resolved;
pub(crate) use diagnostics::Invocation;

/// These leaves have no native pointers and must not follow an uncertain frame
/// into quarantine. The root retains their separate credit until its final
/// result transfer. Fields still owned here are destroyed before that credit.
pub(crate) struct Diagnostics {
    completion: crate::error::CompletionCell,
    authentication: Option<crate::session::ContextDiagnostics>,
    _credit: Credit,
}
impl Diagnostics {
    fn allocation_bytes() -> usize {
        // Init, Update, terminal boundary and publication failures are mutually
        // exclusive exits from this synchronous invocation; one leaf suffices.
        CompletionStorage::allocation_bytes()
    }

    fn prepare(prepaid: &mut Credit) -> Result<Self> {
        let credit = prepaid.split(Self::allocation_bytes())?;
        Ok(Self {
            completion: crate::error::CompletionCell::from_storage(CompletionStorage::allocate()?),
            authentication: None,
            _credit: credit,
        })
    }
}

struct Call {
    mechanism: CK_MECHANISM,
    parameters: OwnedGraph,
    input: input::Input,
    signature: InputBytes,
    output: Buffer,
    output_offset: usize,
    produced: usize,
    length: CK_ULONG,
    _credit: Credit,
}
// SAFETY: the frame owns every pointer target; the graph's declaration is
// checked against this module and route before dispatch. No borrowed input stays.
unsafe impl Send for Call {}
impl Call {
    fn unchanged(&self, expected: (CK_MECHANISM_TYPE, CK_VOID_PTR, CK_ULONG)) -> bool {
        let descriptor = (
            self.mechanism.mechanism,
            self.mechanism.pParameter,
            self.mechanism.ulParameterLen,
        );
        let inputs =
            self.parameters.unchanged() & self.input.unchanged() & self.signature.unchanged();
        descriptor == expected && inputs
    }
}
// Matching C typedefs deliberately remain separate routes, not casts between
// function pointers with superficially similar signatures.
enum Route {
    DigestMultipart {
        init: resolved::DigestInit,
        update: resolved::DigestUpdate,
        finish: resolved::DigestFinal,
    },
    EncryptMultipart {
        init: resolved::EncryptInit,
        update: resolved::EncryptUpdate,
        finish: resolved::EncryptFinal,
    },
    DecryptMultipart {
        init: resolved::DecryptInit,
        update: resolved::DecryptUpdate,
        finish: resolved::DecryptFinal,
    },
    VerifySignature(resolved::VerifySignatureInit, resolved::VerifySignature),
    VerifySignatureMultipart {
        init: resolved::VerifySignatureInit,
        update: resolved::VerifySignatureUpdate,
        finish: resolved::VerifySignatureFinal,
    },
    Encrypt(resolved::EncryptInit, resolved::Encrypt),
    Decrypt(resolved::DecryptInit, resolved::Decrypt),
    Sign(resolved::SignInit, resolved::Sign),
    Verify(resolved::VerifyInit, resolved::Verify),
    Digest(resolved::DigestInit, resolved::Digest),
    SignRecover(resolved::SignRecoverInit, resolved::SignRecover),
    VerifyRecover(resolved::VerifyRecoverInit, resolved::VerifyRecover),
    SignMultipart {
        init: resolved::SignInit,
        update: resolved::SignUpdate,
        finish: resolved::SignFinal,
    },
    VerifyMultipart {
        init: resolved::VerifyInit,
        update: resolved::VerifyUpdate,
        finish: resolved::VerifyFinal,
    },
}
impl Route {
    fn new(
        state: &crate::module::State,
        operation: ExtensionOperation,
        multipart: bool,
    ) -> Result<Self> {
        let t = &state.native.table;
        let missing = || {
            Error::Unsupported(crate::UnsupportedReason::MechanismExtensions(
                crate::MechanismExtensionsUnsupported::ExtensionNativeFunctionTuple,
            ))
        };
        if matches!(
            operation,
            ExtensionOperation::VerifySignature | ExtensionOperation::VerifySignatureMultipart
        ) {
            let functions = state.native.verify_signature.ok_or_else(missing)?;
            if functions.init.is_none() {
                return Err(missing());
            }
            return match (operation, multipart) {
                (ExtensionOperation::VerifySignature, false) if functions.single.is_some() => {
                    Ok(Self::VerifySignature(
                        functions.init.ok_or_else(missing)?,
                        functions.single.ok_or_else(missing)?,
                    ))
                }
                (ExtensionOperation::VerifySignatureMultipart, true)
                    if functions.update.is_some() && functions.finish.is_some() =>
                {
                    Ok(Self::VerifySignatureMultipart {
                        init: functions.init.ok_or_else(missing)?,
                        update: functions.update.ok_or_else(missing)?,
                        finish: functions.finish.ok_or_else(missing)?,
                    })
                }
                _ => Err(missing()),
            };
        }
        if multipart {
            return match operation {
                ExtensionOperation::DigestMultipart
                    if t.C_DigestInit.is_some()
                        && t.C_DigestUpdate.is_some()
                        && t.C_DigestFinal.is_some() =>
                {
                    Ok(Self::DigestMultipart {
                        init: t.C_DigestInit.ok_or_else(missing)?,
                        update: t.C_DigestUpdate.ok_or_else(missing)?,
                        finish: t.C_DigestFinal.ok_or_else(missing)?,
                    })
                }
                ExtensionOperation::EncryptMultipart
                    if t.C_EncryptInit.is_some()
                        && t.C_EncryptUpdate.is_some()
                        && t.C_EncryptFinal.is_some() =>
                {
                    Ok(Self::EncryptMultipart {
                        init: t.C_EncryptInit.ok_or_else(missing)?,
                        update: t.C_EncryptUpdate.ok_or_else(missing)?,
                        finish: t.C_EncryptFinal.ok_or_else(missing)?,
                    })
                }
                ExtensionOperation::DecryptMultipart
                    if t.C_DecryptInit.is_some()
                        && t.C_DecryptUpdate.is_some()
                        && t.C_DecryptFinal.is_some() =>
                {
                    Ok(Self::DecryptMultipart {
                        init: t.C_DecryptInit.ok_or_else(missing)?,
                        update: t.C_DecryptUpdate.ok_or_else(missing)?,
                        finish: t.C_DecryptFinal.ok_or_else(missing)?,
                    })
                }

                ExtensionOperation::SignMultipart
                    if t.C_SignInit.is_some()
                        && t.C_SignUpdate.is_some()
                        && t.C_SignFinal.is_some() =>
                {
                    Ok(Self::SignMultipart {
                        init: t.C_SignInit.ok_or_else(missing)?,
                        update: t.C_SignUpdate.ok_or_else(missing)?,
                        finish: t.C_SignFinal.ok_or_else(missing)?,
                    })
                }
                ExtensionOperation::VerifyMultipart
                    if t.C_VerifyInit.is_some()
                        && t.C_VerifyUpdate.is_some()
                        && t.C_VerifyFinal.is_some() =>
                {
                    Ok(Self::VerifyMultipart {
                        init: t.C_VerifyInit.ok_or_else(missing)?,
                        update: t.C_VerifyUpdate.ok_or_else(missing)?,
                        finish: t.C_VerifyFinal.ok_or_else(missing)?,
                    })
                }
                _ => Err(missing()),
            };
        }
        Ok(match operation {
            ExtensionOperation::SignRecover
                if t.C_SignRecoverInit.is_some() && t.C_SignRecover.is_some() =>
            {
                Self::SignRecover(
                    t.C_SignRecoverInit.ok_or_else(missing)?,
                    t.C_SignRecover.ok_or_else(missing)?,
                )
            }
            ExtensionOperation::VerifyRecover
                if t.C_VerifyRecoverInit.is_some() && t.C_VerifyRecover.is_some() =>
            {
                Self::VerifyRecover(
                    t.C_VerifyRecoverInit.ok_or_else(missing)?,
                    t.C_VerifyRecover.ok_or_else(missing)?,
                )
            }
            ExtensionOperation::Encrypt if t.C_EncryptInit.is_some() && t.C_Encrypt.is_some() => {
                Self::Encrypt(
                    t.C_EncryptInit.ok_or_else(missing)?,
                    t.C_Encrypt.ok_or_else(missing)?,
                )
            }
            ExtensionOperation::Decrypt if t.C_DecryptInit.is_some() && t.C_Decrypt.is_some() => {
                Self::Decrypt(
                    t.C_DecryptInit.ok_or_else(missing)?,
                    t.C_Decrypt.ok_or_else(missing)?,
                )
            }
            ExtensionOperation::Sign if t.C_SignInit.is_some() && t.C_Sign.is_some() => Self::Sign(
                t.C_SignInit.ok_or_else(missing)?,
                t.C_Sign.ok_or_else(missing)?,
            ),
            ExtensionOperation::Verify if t.C_VerifyInit.is_some() && t.C_Verify.is_some() => {
                Self::Verify(
                    t.C_VerifyInit.ok_or_else(missing)?,
                    t.C_Verify.ok_or_else(missing)?,
                )
            }
            ExtensionOperation::Digest if t.C_DigestInit.is_some() && t.C_Digest.is_some() => {
                Self::Digest(
                    t.C_DigestInit.ok_or_else(missing)?,
                    t.C_Digest.ok_or_else(missing)?,
                )
            }
            _ => return Err(missing()),
        })
    }
    fn names(&self) -> (&'static str, &'static str) {
        match self {
            Self::DigestMultipart { .. } => ("C_DigestInit", "C_DigestFinal"),
            Self::EncryptMultipart { .. } => ("C_EncryptInit", "C_EncryptFinal"),
            Self::DecryptMultipart { .. } => ("C_DecryptInit", "C_DecryptFinal"),

            Self::VerifySignature(..) => ("C_VerifySignatureInit", "C_VerifySignature"),
            Self::VerifySignatureMultipart { .. } => {
                ("C_VerifySignatureInit", "C_VerifySignatureFinal")
            }
            Self::Encrypt(..) => ("C_EncryptInit", "C_Encrypt"),
            Self::Decrypt(..) => ("C_DecryptInit", "C_Decrypt"),
            Self::Sign(..) => ("C_SignInit", "C_Sign"),
            Self::Verify(..) => ("C_VerifyInit", "C_Verify"),
            Self::Digest(..) => ("C_DigestInit", "C_Digest"),
            Self::SignRecover(..) => ("C_SignRecoverInit", "C_SignRecover"),
            Self::VerifyRecover(..) => ("C_VerifyRecoverInit", "C_VerifyRecover"),
            Self::SignMultipart { .. } => ("C_SignInit", "C_SignFinal"),
            Self::VerifyMultipart { .. } => ("C_VerifyInit", "C_VerifyFinal"),
        }
    }
    unsafe fn init(
        &self,
        session: CK_SESSION_HANDLE,
        data: &mut Call,
        key: CK_OBJECT_HANDLE,
    ) -> CK_RV {
        // SAFETY: caller holds the stable session frame and the exact owned graph.
        unsafe {
            match self {
                Self::VerifySignature(init, _) | Self::VerifySignatureMultipart { init, .. } => {
                    init(
                        session,
                        &mut data.mechanism,
                        key,
                        data.signature.pointer(),
                        data.signature.length(),
                    )
                }
                Self::Encrypt(init, _) | Self::EncryptMultipart { init, .. } => {
                    init(session, &mut data.mechanism, key)
                }
                Self::Decrypt(init, _) | Self::DecryptMultipart { init, .. } => {
                    init(session, &mut data.mechanism, key)
                }
                Self::Sign(init, _) | Self::SignMultipart { init, .. } => {
                    init(session, &mut data.mechanism, key)
                }
                Self::Verify(init, _) | Self::VerifyMultipart { init, .. } => {
                    init(session, &mut data.mechanism, key)
                }
                Self::Digest(init, _) | Self::DigestMultipart { init, .. } => {
                    init(session, &mut data.mechanism)
                }
                Self::SignRecover(init, _) => init(session, &mut data.mechanism, key),
                Self::VerifyRecover(init, _) => init(session, &mut data.mechanism, key),
            }
        }
    }
    fn update(&self) -> Option<(Update, &'static str)> {
        match self {
            Self::VerifySignatureMultipart { update, .. } => {
                Some((Update::Input(*update), "C_VerifySignatureUpdate"))
            }
            Self::SignMultipart { update, .. } => Some((Update::Input(*update), "C_SignUpdate")),
            Self::VerifyMultipart { update, .. } => {
                Some((Update::Input(*update), "C_VerifyUpdate"))
            }
            Self::DigestMultipart { update, .. } => {
                Some((Update::Input(*update), "C_DigestUpdate"))
            }
            Self::EncryptMultipart { update, .. } => {
                Some((Update::Output(*update), "C_EncryptUpdate"))
            }
            Self::DecryptMultipart { update, .. } => {
                Some((Update::Output(*update), "C_DecryptUpdate"))
            }
            _ => None,
        }
    }
    unsafe fn run(
        &self,
        session: CK_SESSION_HANDLE,
        data: &mut Call,
        single_input: Option<(CK_BYTE_PTR, CK_ULONG)>,
    ) -> CK_RV {
        // SAFETY: the caller retains the frame, and verifies the selected input
        // shape before Init. Multipart Final has no whole-message length.
        unsafe {
            match self {
                Self::VerifySignatureMultipart { finish, .. } => finish(session),
                Self::DigestMultipart { finish, .. } => {
                    let output =
                        data.output.as_mut()[data.output_offset + data.produced..].as_mut_ptr();
                    finish(session, output, &mut data.length)
                }
                Self::EncryptMultipart { finish, .. } => {
                    let output =
                        data.output.as_mut()[data.output_offset + data.produced..].as_mut_ptr();
                    finish(session, output, &mut data.length)
                }
                Self::DecryptMultipart { finish, .. } => {
                    let output =
                        data.output.as_mut()[data.output_offset + data.produced..].as_mut_ptr();
                    finish(session, output, &mut data.length)
                }
                Self::SignMultipart { finish, .. } => {
                    let output = data.output.as_mut()[data.output_offset..].as_mut_ptr();
                    finish(session, output, &mut data.length)
                }
                Self::VerifyMultipart { finish, .. } => {
                    finish(session, data.signature.pointer(), data.signature.length())
                }
                _ => {
                    let (input, length) = single_input.expect("single input checked before Init");
                    self.run_single(session, data, input, length)
                }
            }
        }
    }

    unsafe fn run_single(
        &self,
        session: CK_SESSION_HANDLE,
        data: &mut Call,
        input: CK_BYTE_PTR,
        length: CK_ULONG,
    ) -> CK_RV {
        // OTP mechanisms require pData=NULL and ulDataLen=0. A copied empty
        // allocation is not a substitute for that specified pointer value.
        let input = if length == 0
            && matches!(data.mechanism.mechanism, CKM_SECURID | CKM_HOTP | CKM_ACTI)
        {
            std::ptr::null_mut()
        } else {
            input
        };
        let output = data.output.as_mut()[data.output_offset..].as_mut_ptr();
        // SAFETY: caller retains the complete frame through completion; all
        // output capacities and input lengths were checked before initialization.
        unsafe {
            match self {
                Self::VerifySignature(_, run) => run(session, input, length),
                Self::VerifySignatureMultipart { .. }
                | Self::SignMultipart { .. }
                | Self::VerifyMultipart { .. }
                | Self::DigestMultipart { .. }
                | Self::EncryptMultipart { .. }
                | Self::DecryptMultipart { .. } => unreachable!("multipart Final has no input"),
                Self::Encrypt(_, run) => run(session, input, length, output, &mut data.length),
                Self::Decrypt(_, run) => run(session, input, length, output, &mut data.length),
                Self::Sign(_, run) => run(session, input, length, output, &mut data.length),
                Self::Verify(_, run) => run(
                    session,
                    input,
                    length,
                    data.signature.pointer(),
                    data.signature.length(),
                ),
                Self::Digest(_, run) => run(session, input, length, output, &mut data.length),
                Self::SignRecover(_, run) => run(session, input, length, output, &mut data.length),
                Self::VerifyRecover(_, run) => {
                    run(session, input, length, output, &mut data.length)
                }
            }
        }
    }
}
#[derive(Clone, Copy)]
enum Update {
    Input(unsafe extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG) -> CK_RV),
    Output(
        unsafe extern "C" fn(
            CK_SESSION_HANDLE,
            CK_BYTE_PTR,
            CK_ULONG,
            CK_BYTE_PTR,
            CK_ULONG_PTR,
        ) -> CK_RV,
    ),
}
impl Update {
    unsafe fn run(
        self,
        session: CK_SESSION_HANDLE,
        data: &mut Call,
        offset: usize,
        length: CK_ULONG,
    ) -> CK_RV {
        // SAFETY: the caller bounds the fragment within the stable owned input
        // and supplies the unfilled, checked tail of the owned output buffer.
        unsafe {
            let input = data.input.pointer().add(offset);
            match self {
                Self::Input(call) => call(session, input, length),
                Self::Output(call) => {
                    let output =
                        data.output.as_mut()[data.output_offset + data.produced..].as_mut_ptr();
                    call(session, input, length, output, &mut data.length)
                }
            }
        }
    }
}
pub(crate) fn effect(error: Error, mutates: bool) -> Error {
    match error {
        Error::Native {
            function,
            code,
            may_have_effect,
        } => Error::Native {
            function,
            code,
            may_have_effect: may_have_effect || mutates,
        },
        other => other,
    }
}
pub(crate) fn execute(
    session: &crate::Session,
    request: ExtensionRequest<'_>,
    input: ExtensionInput<'_>,
    limits: crate::InputLimits,
    authentication: Option<crate::ContextAuthentication>,
    root: &mut Invocation,
) -> Result<ExtensionResult> {
    if matches!(
        &input,
        ExtensionInput::Encrypt { .. }
            | ExtensionInput::Decrypt { .. }
            | ExtensionInput::EncryptMultipart { .. }
            | ExtensionInput::DecryptMultipart { .. }
    ) {
        return crate::advanced::cipher::batch::execute(
            session,
            request,
            input,
            limits,
            authentication,
            root.cipher(),
        );
    }
    if matches!(
        &input,
        ExtensionInput::Digest { .. } | ExtensionInput::DigestMultipart { .. }
    ) {
        return crate::advanced::digest::batch::execute(
            session,
            request,
            input,
            limits,
            authentication,
            root.digest(),
        );
    }
    if matches!(
        &input,
        ExtensionInput::Sign { .. }
            | ExtensionInput::SignMultipart { .. }
            | ExtensionInput::Verify { .. }
            | ExtensionInput::VerifyMultipart { .. }
            | ExtensionInput::VerifySignature { .. }
            | ExtensionInput::VerifySignatureMultipart { .. }
    ) {
        return crate::advanced::signature::batch::execute(
            session,
            request,
            input,
            limits,
            authentication,
            root.signature(),
        );
    }
    let alignment = if matches!(
        request.contract.mechanism,
        CKM_SECURID | CKM_HOTP | CKM_ACTI
    ) {
        std::mem::align_of::<CK_OTP_SIGNATURE_INFO>()
    } else {
        1
    };
    execute_aligned(
        session,
        request,
        input,
        limits,
        authentication,
        alignment,
        root,
    )
}
// Structured outputs such as OTP contain native pointers. Align their original
// native buffer, then retain its numeric origin for bounded offset decoding.
pub(crate) fn execute_aligned(
    session: &crate::Session,
    request: ExtensionRequest<'_>,
    input: ExtensionInput<'_>,
    limits: crate::InputLimits,
    authentication: Option<crate::ContextAuthentication>,
    alignment: usize,
    root: &mut Invocation,
) -> Result<ExtensionResult> {
    execute_with_sources(
        session,
        request,
        input,
        limits,
        authentication,
        alignment,
        [None; 4],
        root,
    )
}
pub(crate) fn execute_with_sources<'a>(
    session: &crate::Session,
    request: impl Into<super::graph::recipe::Request<'a>>,
    input: ExtensionInput<'_>,
    limits: crate::InputLimits,
    authentication: Option<crate::ContextAuthentication>,
    alignment: usize,
    sources: [Option<&crate::NativeObjectRef>; 4],
    root: &mut Invocation,
) -> Result<ExtensionResult> {
    execute_published(
        session,
        request,
        input,
        limits,
        authentication,
        alignment,
        sources,
        false,
        Ok,
        root,
    )
}

/// Typed signing adapters validate the completed output inside the existing
/// publication boundary. The internal callback must not allocate or acquire
/// resources; all native dispatch and diagnostic storage are already complete.
pub(crate) fn execute_with_sources_and_publish<'a, T>(
    session: &crate::Session,
    request: impl Into<super::graph::recipe::Request<'a>>,
    input: ExtensionInput<'_>,
    limits: crate::InputLimits,
    authentication: Option<crate::ContextAuthentication>,
    alignment: usize,
    sources: [Option<&crate::NativeObjectRef>; 4],
    publish: impl FnOnce(ExtensionResult) -> Result<T>,
    root: &mut Invocation,
) -> Result<T> {
    if !matches!(
        &input,
        ExtensionInput::Sign { .. } | ExtensionInput::SignMultipart { .. }
    ) {
        return Err(Error::Rejected(
            crate::RejectionReason::MechanismExtensions(
                crate::MechanismExtensionsRejection::TypedSignaturePublicationRoute,
            ),
        ));
    }
    execute_published(
        session,
        request,
        input,
        limits,
        authentication,
        alignment,
        sources,
        true,
        publish,
        root,
    )
}

mod invocation;
use invocation::execute_published;
