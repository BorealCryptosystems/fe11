// SPDX-License-Identifier: Apache-2.0
//! One owned contextual login, shared by retained and synchronous operations.
use super::*;

mod preparation;
pub(crate) use preparation::{ContextLoginPlan, ContextLoginStorage};

/// Owned, single-use authentication to perform after a key-using Init and
/// before using that operation. The PIN source and optional user name are
/// explicit; this does not perform a token-wide USER/SO login.
pub struct ContextAuthentication {
    input: crate::pin::LoginFrame,
}
impl ContextAuthentication {
    /// Select C_Login(CKU_CONTEXT_SPECIFIC). Provided empty and protected PINs
    /// remain distinct; supplied secret bytes are owned from construction.
    pub fn login(pin: impl Into<crate::PinRequest>) -> Self {
        Self {
            input: crate::pin::LoginFrame::new(pin.into(), None),
        }
    }
    /// Select C_LoginUser(CKU_CONTEXT_SPECIFIC) with an independently owned,
    /// erased user name. There is no fallback to C_Login if unavailable/refused.
    pub fn login_user(pin: impl Into<crate::PinRequest>, user_name: Vec<u8>) -> Self {
        Self {
            input: crate::pin::LoginFrame::new(pin.into(), Some(user_name)),
        }
    }
    pub(crate) fn check_available(&self, state: &State) -> Result<()> {
        context_login_call(state, &self.input).map(|_| ())
    }
    pub(crate) fn into_input(self) -> crate::pin::LoginFrame {
        self.input
    }
}

fn context_login_call(
    state: &State,
    input: &crate::pin::LoginFrame,
) -> Result<crate::native_return::SessionCall> {
    if input.user_name.is_some() {
        if state.native.login_user.is_none() {
            return Err(Error::Unsupported(
                crate::UnsupportedReason::NativeFunction {
                    function: "C_LoginUser",
                },
            ));
        }
        Ok(crate::native_return::SessionCall::ContextLoginUser)
    } else {
        if state.native.table.C_Login.is_none() {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::CLoginUnavailable,
            )));
        }
        Ok(crate::native_return::SessionCall::ContextLogin)
    }
}

struct ContextLoginInput {
    input: crate::pin::LoginFrame,
    pin_witness: crate::pin::PinWitness,
    name_witness: Option<crate::SecretBytes>,
    // Released after the owned inputs and witnesses, including uncertain calls.
    _credit: crate::symmetric::memory::Credit,
}

/// These leaves are not native-addressable. Keep their credit in the calling
/// operation's scope after login, including while a returned error is handled.
pub(crate) struct ContextDiagnostics {
    failures: Option<crate::error::FailurePair>,
    completion: Option<crate::error::CompletionStorage>,
    _credit: crate::symmetric::memory::Credit,
}

/// Preparation errors are returned normally. Once login has run, return its
/// outcome together with the storage that still funds a possible error chain.
pub(crate) struct ContextLoginOutcome {
    pub(crate) result: Result<()>,
    pub(crate) diagnostics: ContextDiagnostics,
}
impl ContextDiagnostics {
    fn allocation_bytes() -> usize {
        crate::error::FailurePair::allocation_bytes()
            + crate::error::CompletionStorage::allocation_bytes()
    }

    fn prepare(prepaid: &mut crate::symmetric::memory::Credit) -> Result<Self> {
        let credit = prepaid.split(Self::allocation_bytes())?;
        Ok(Self {
            failures: Some(crate::error::FailurePair::allocate()?),
            completion: Some(crate::error::CompletionStorage::allocate()?),
            _credit: credit,
        })
    }
}

pub(crate) struct PreparedContextLogin<'a> {
    frame: Option<
        crate::native::frame::NativeFrame<
            crate::native::frame::SessionFrame<'a, ContextLoginInput>,
        >,
    >,
    call: crate::native_return::SessionCall,
    diagnostics: ContextDiagnostics,
}
impl<'a> PreparedContextLogin<'a> {
    /// Borrow credentials and their prepaid storage through capability,
    /// context, recovery-ticket and stable-allocation checks. An absent request
    /// has no frame or byte credit. Transfer both inputs only on full success.
    pub(crate) fn from_prepared(
        session: &Session,
        access: &SessionAccess<'a>,
        request: &mut Option<ContextAuthentication>,
        storage: &mut Option<ContextLoginStorage>,
    ) -> Result<Option<Self>> {
        let (requested, prepared) = match (request.as_ref(), storage.as_ref()) {
            (None, None) => return Ok(None),
            (Some(request), Some(storage)) => (request, storage),
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::ContextAuthenticationPreparationMismatch,
                )))
            }
        };
        if !access.context_writer_held() {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ContextAuthenticationRequiresTokenWriter,
            )));
        }
        let call = context_login_call(access, &requested.input)?;
        prepared.check_context(session)?;
        let mut diagnostics = None;
        let frame = crate::native::frame::NativeFrame::session_with(
            || {
                let request = request.take().expect("validated contextual authentication");
                let storage = storage.take().expect("validated contextual storage");
                let (input, prepared) = storage.into_input(request.into_input());
                diagnostics = Some(prepared);
                input
            },
            access.clone(),
        )?;
        Ok(Some(Self {
            frame: Some(frame),
            call,
            diagnostics: diagnostics.expect("context diagnostics transferred with frame input"),
        }))
    }

    /// Consumes the native frame once, but leaves diagnostic credit with the
    /// caller. Credentials are still erased/retained at the original call
    /// boundary. The caller keeps this owner until its final error transfer.
    pub(crate) fn perform(&mut self, session: &Session) -> Result<()> {
        let call = self.call;
        let mut frame =
            self.frame
                .take()
                .ok_or(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                    crate::SessionLifecycleRejection::ContextLoginAlreadyPerformed,
                )))?;
        let diagnostic = self
            .diagnostics
            .completion
            .take()
            .expect("context completion prepared for its single call")
            .bind(call.function());
        let (returned, body) = frame.session_parts();
        if !body.access.owns_session(session) {
            return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
                crate::SessionLifecycleRejection::ForeignContextualAuthenticationSession,
            )));
        }
        let ContextLoginInput {
            input,
            pin_witness,
            name_witness,
            ..
        } = &mut *body.data;
        let (pointer, length) = input.pin.arguments()?;
        let s = &body.access;
        Inner::validate(s)?;
        let rv = if matches!(call, crate::native_return::SessionCall::ContextLoginUser) {
            let native = s.native.login_user.ok_or(Error::Unsupported(
                crate::UnsupportedReason::NativeFunction {
                    function: "C_LoginUser",
                },
            ))?;
            let name = input.user_name.as_mut().expect("named login selected");
            let name_length = bounds::ck_length(name.len())?;
            let name_pointer = if name.is_empty() {
                &mut input.empty_name
            } else {
                name.as_mut_ptr()
            };
            s.native.record(call.function())?;
            returned.arm();
            // SAFETY: PIN/name/sentinels belong to this stable frame; the
            // caller's sequence owner and token writer preserve its parent.
            returned.observe(
                unsafe {
                    native(
                        session.entry.handle,
                        CKU_CONTEXT_SPECIFIC,
                        pointer,
                        length,
                        name_pointer,
                        name_length,
                    )
                },
                &s.native,
            )
        } else {
            let native = s.native.table.C_Login.ok_or(Error::Rejected(
                crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::CLoginUnavailable,
                ),
            ))?;
            s.native.record(call.function())?;
            returned.arm();
            // SAFETY: the frame retains the same complete ownership for the
            // ordinary login variant; the writer excludes concurrent calls.
            returned.observe(
                unsafe { native(session.entry.handle, CKU_CONTEXT_SPECIFIC, pointer, length) },
                &s.native,
            )
        };
        let complete = call.completion_known(rv);
        if complete {
            returned.terminated();
        }
        // Account for the normative logout even when PIN input integrity also
        // failed. A witness anomaly must not preserve stale private authority.
        let logout = if rv == CKR_PIN_LOCKED {
            session.context_pin_locked(s)
        } else {
            Ok(())
        };
        let native_result = s.check_session_return(&session.entry, call, rv, true);
        let input_unchanged =
            !complete || (pin_witness.unchanged(&input.pin) && input.name_unchanged(name_witness));
        if !input_unchanged {
            returned.quarantine(&s.native);
            let operation = diagnostic.boundary_failure(
                rv,
                Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::NativeAuthenticationInputChanged,
                )),
            );
            // PIN_LOCKED can also fail while retiring authentication authority.
            // Both prepared leaves remain available: no cause replaces another.
            return match logout {
                Ok(()) => Err(operation),
                Err(cleanup) => Err(self
                    .diagnostics
                    .failures
                    .take()
                    .expect("context compound failure prepared before possession")
                    .finish(operation, cleanup)),
            };
        }
        if let Err(operation) = native_result {
            return match logout {
                Ok(()) => Err(operation),
                Err(cleanup) => Err(self
                    .diagnostics
                    .failures
                    .take()
                    .expect("context compound failure prepared before possession")
                    .finish(operation, cleanup)),
            };
        }
        logout?;
        diagnostic.finish(Inner::validate(s).and_then(|()| session.snapshot.check()))
    }

    /// Retained-login facades keep this non-native owner across their remaining
    /// work. The consumed frame is gone before ownership leaves this helper.
    pub(crate) fn into_diagnostics(self) -> ContextDiagnostics {
        self.diagnostics
    }
}

impl Session {
    // Called only for the contextual role and under the token writer. Ordinary
    // USER/SO login errors must not invoke this transition. Operation stamps
    // make all old continuations stale without dropping their native buffers.
    fn context_pin_locked(&self, s: &State) -> Result<()> {
        let result = (|| {
            self.snapshot.set_role(None)?;
            // Expire observations through the epoch, without locally rejecting
            // a new native attempt merely because it uses an older handle.
            crate::managed::forget_private_origins(
                &self.inner,
                s,
                self.entry.slot,
                self.snapshot.generation,
            )
        })();
        if result.is_err() {
            s.native.mark_uncertain();
        }
        result
    }
}
