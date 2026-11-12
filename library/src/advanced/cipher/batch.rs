// SPDX-License-Identifier: Apache-2.0
//! Complete-input extensions use the same owner as caller-fed cipher streams.
use super::{api, CipherKeyReference, CipherOutputPlan, Direction, Selection};
use crate::advanced::{poll, OperationPacing, OperationProgress};
use crate::{Error, ExtensionInput, ExtensionResult, InputLimits, Result, Session};

/// Separate startup and polling anchors preserve the owner across facade cleanup.
#[derive(Default)]
pub(crate) struct Invocation {
    retirement: poll::PollDiagnostics,
    polling: poll::PollDiagnostics,
    parking: Option<crate::error::PreparedFailurePair>,
    authentication: Option<crate::session::ContextDiagnostics>,
}

pub(crate) fn execute<'a>(
    session: &Session,
    request: impl Into<crate::mechanism_extension::graph::recipe::Request<'a>>,
    input: ExtensionInput<'_>,
    limits: InputLimits,
    authentication: Option<crate::ContextAuthentication>,
    root: &mut Invocation,
) -> Result<ExtensionResult> {
    let request = request.into();
    let single;
    let (key, direction, route, parts, capacity) = match input {
        ExtensionInput::Encrypt {
            key,
            input,
            output_capacity,
        } => {
            single = [input];
            (
                key,
                Direction::Encrypt,
                crate::MessageRoute::Single,
                &single[..],
                output_capacity,
            )
        }
        ExtensionInput::Decrypt {
            key,
            input,
            output_capacity,
        } => {
            single = [input];
            (
                key,
                Direction::Decrypt,
                crate::MessageRoute::Single,
                &single[..],
                output_capacity,
            )
        }
        ExtensionInput::EncryptMultipart {
            key,
            parts,
            output_capacity,
        } => (
            key,
            Direction::Encrypt,
            crate::MessageRoute::Multipart,
            parts,
            output_capacity,
        ),
        ExtensionInput::DecryptMultipart {
            key,
            parts,
            output_capacity,
        } => (
            key,
            Direction::Decrypt,
            crate::MessageRoute::Multipart,
            parts,
            output_capacity,
        ),
        _ => {
            return Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::ExtensionCipherFacadeRoute,
            )))
        }
    };
    let mutates = request.contract.mutates_key();
    let outcome = (|| {
        let (mut ticket, owner, prepared_diagnostic) = api::start_retained(
            session,
            api::CipherKey::Native(CipherKeyReference::Secret(key)),
            Selection::Extension(super::extension::Source::Declared(request)),
            direction,
            route,
            parts,
            limits,
            CipherOutputPlan::Buffer { capacity },
            false,
            &mut 1,
            crate::advanced::input::InputState::closed(),
            None,
            true,
            &mut root.retirement,
        )?;
        root.parking = prepared_diagnostic;
        let continuation_budget = root
            .parking
            .as_ref()
            .expect("facade diagnostic prepared")
            .budget()
            .clone();
        let result = (|| {
            if let Some(authentication) = authentication {
                let completed = session.authenticate_context_with_budget(
                    &ticket,
                    authentication,
                    &continuation_budget,
                )?;
                root.authentication = Some(completed.diagnostics);
                completed.result?;
            }
            match poll::poll_operation_with_diagnostics(
                session,
                &mut ticket,
                crate::session::CleanupAdmission::Ordinary,
                OperationPacing::Eager,
                &mut root.polling,
            )? {
                OperationProgress::ExtensionEncrypted(result)
                | OperationProgress::ExtensionDecrypted(result) => Ok(result),
                OperationProgress::CipherBufferRequired(request) => {
                    Err(Error::CipherBufferRequired(request))
                }
                _ => Err(Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::ExtensionCipherFacadeIncomplete,
                ))),
            }
        })();
        if result.is_err() && ticket.id != 0 {
            // The exact owner remains available even if admission has timed out.
            // Parking never requests another resource or makes a native call.
            let parked = super::synchronous::park(session, &mut ticket, &owner, None);
            if let Err(cleanup) = parked {
                return Err(root
                    .parking
                    .as_mut()
                    .expect("facade diagnostic prepared")
                    .finish(result.err().expect("failed cipher facade"), cleanup));
            }
        }
        result
    })();
    outcome.map_err(|error| crate::mechanism_extension::operation::effect(error, mutates))
}
