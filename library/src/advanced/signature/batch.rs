// SPDX-License-Identifier: Apache-2.0
//! Complete-input facades use the same transitions as caller-fed signatures.
use super::{api, preparation, Kind, SignatureOutputPlan};
use crate::advanced::{poll, progress, OperationPacing, OperationProgress};
use crate::{Error, ExtensionInput, ExtensionResult, InputLimits, MessageRoute, Result, Session};

/// Only complete-input facades need a parking diagnostic. Typed facades also
/// validate the successful output before publishing it to their caller.
#[derive(Clone, Copy)]
pub(super) enum DiagnosticPlan {
    None,
    Facade {
        publication: bool,
        submissions: bool,
    },
}
impl DiagnosticPlan {
    pub(super) fn preparation_bytes(self) -> usize {
        match self {
            Self::None => 0,
            _ => self.allocation_bytes() + crate::symmetric::memory::Budget::observation_bytes(),
        }
    }

    pub(super) fn allocation_bytes(self) -> usize {
        use crate::error::{CompletionStorage, FailurePair};
        match self {
            Self::None => 0,
            Self::Facade {
                publication,
                submissions,
            } => {
                FailurePair::allocation_bytes()
                    + usize::from(publication) * CompletionStorage::allocation_bytes()
                    + usize::from(submissions) * progress::FailureDiagnostics::allocation_bytes()
            }
        }
    }

    pub(super) fn prepare(
        self,
        prepaid: &mut crate::symmetric::memory::Credit,
    ) -> Result<Option<Diagnostics>> {
        let Self::Facade {
            publication,
            submissions,
        } = self
        else {
            return Ok(None);
        };
        let mut credit = prepaid.split(self.allocation_bytes())?;
        Ok(Some(Diagnostics {
            parking: Some(crate::error::FailurePair::allocate()?),
            publication: publication
                .then(crate::error::CompletionStorage::allocate)
                .transpose()?,
            submission: submissions
                .then(|| progress::FailureDiagnostics::from_prepaid(&mut credit))
                .transpose()?,
            _credit: credit,
        }))
    }
}

/// The facade keeps this owner until its final return, including when a leaf
/// is consumed by error composition. Native retention never takes this credit.
pub(super) struct Diagnostics {
    parking: Option<crate::error::FailurePair>,
    publication: Option<crate::error::CompletionStorage>,
    submission: Option<progress::FailureDiagnostics>,
    _credit: crate::symmetric::memory::Credit,
}
impl Diagnostics {
    fn budget(&self) -> &std::sync::Arc<crate::symmetric::memory::Budget> {
        self._credit.budget()
    }
}

/// The public invocation retains all error owners across parking and publication.
#[derive(Default)]
pub(crate) struct Invocation {
    retirement: poll::PollDiagnostics,
    polling: poll::PollDiagnostics,
    diagnostics: Option<Diagnostics>,
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
    execute_with_capture(session, request, input, limits, authentication, false, root)
        .map(|(result, _report)| result)
}

/// Complete-input and incremental calls share the same collector and native owner.
/// Keep the consumed ticket until its terminal report has been transferred.
fn execute_with_capture<'a>(
    session: &Session,
    request: impl Into<crate::mechanism_extension::graph::recipe::Request<'a>>,
    input: ExtensionInput<'_>,
    limits: InputLimits,
    authentication: Option<crate::ContextAuthentication>,
    capture_validation: bool,
    root: &mut Invocation,
) -> Result<(ExtensionResult, Option<crate::ValidationReport>)> {
    execute_published(
        session,
        request,
        input,
        limits,
        authentication,
        capture_validation,
        false,
        Ok,
        root,
    )
}

/// The callback is internal, consumes an already successful output and must
/// neither allocate nor acquire resources. Its diagnostic is admitted with Init.
pub(crate) fn execute_and_publish<'a, T>(
    session: &Session,
    request: impl Into<crate::mechanism_extension::graph::recipe::Request<'a>>,
    input: ExtensionInput<'_>,
    limits: InputLimits,
    authentication: Option<crate::ContextAuthentication>,
    publish: impl FnOnce(ExtensionResult) -> Result<T>,
    root: &mut Invocation,
) -> Result<T> {
    execute_published(
        session,
        request,
        input,
        limits,
        authentication,
        false,
        true,
        publish,
        root,
    )
    .map(|(result, _report)| result)
}

fn execute_published<'a, T>(
    session: &Session,
    request: impl Into<crate::mechanism_extension::graph::recipe::Request<'a>>,
    input: ExtensionInput<'_>,
    limits: InputLimits,
    authentication: Option<crate::ContextAuthentication>,
    capture_validation: bool,
    validate_publication: bool,
    publish: impl FnOnce(ExtensionResult) -> Result<T>,
    root: &mut Invocation,
) -> Result<(T, Option<crate::ValidationReport>)> {
    let request = request.into();
    let (kind, key, initial, parts, signature, capacity) = match input {
        ExtensionInput::Sign {
            key,
            input,
            output_capacity,
        } => (Kind::Sign, key, Some(input), None, None, output_capacity),
        ExtensionInput::SignMultipart {
            key,
            parts,
            output_capacity,
        } => (Kind::Sign, key, None, Some(parts), None, output_capacity),
        ExtensionInput::Verify {
            key,
            input,
            signature,
        } => (Kind::Verify, key, Some(input), None, Some(signature), 0),
        ExtensionInput::VerifyMultipart {
            key,
            parts,
            signature,
        } => (Kind::Verify, key, None, Some(parts), Some(signature), 0),
        ExtensionInput::VerifySignature {
            key,
            input,
            signature,
        } => (
            Kind::VerifySignature,
            key,
            Some(input),
            None,
            Some(signature),
            0,
        ),
        ExtensionInput::VerifySignatureMultipart {
            key,
            parts,
            signature,
        } => (
            Kind::VerifySignature,
            key,
            None,
            Some(parts),
            Some(signature),
            0,
        ),
        _ => {
            return Err(Error::Rejected(
                crate::RejectionReason::SignatureContinuation(
                    crate::SignatureContinuationRejection::ClassicSignatureFacadeRoute,
                ),
            ))
        }
    };
    let single = [initial.unwrap_or(&[])];
    let pieces = parts.unwrap_or(&single);
    // Preserve the complete-input contract and all boundaries before Init.
    // Stream APIs apply the same limits independently to each later submission.
    limits.validate(session.inner.crypto_options.limits, pieces)?;
    let route = if initial.is_some() {
        MessageRoute::Single
    } else {
        MessageRoute::Multipart
    };
    let mutates = request.contract.mutates_key();
    // This anchor deliberately outlives the inner completion/parking closure
    // and the final effect mapping. Returning an error between helpers is not
    // yet the facade's public transfer.
    let outcome = (|| {
        let (mut ticket, owner, prepared_diagnostics) = preparation::start_retained(
            session,
            key,
            request,
            kind,
            route,
            initial,
            signature,
            limits,
            SignatureOutputPlan::Buffer { capacity },
            usize::try_from(fe11_sys::CK_ULONG::MAX).unwrap_or(usize::MAX),
            capture_validation,
            DiagnosticPlan::Facade {
                publication: validate_publication,
                submissions: parts.is_some_and(|parts| !parts.is_empty()),
            },
            &mut 1,
            &mut root.retirement,
        )?;
        root.diagnostics = prepared_diagnostics;
        let continuation_budget = root
            .diagnostics
            .as_ref()
            .expect("facade diagnostics prepared with Init")
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
            let result = if let Some(parts) = parts {
                for part in parts {
                    match api::change_with_budget(
                        session,
                        &mut ticket,
                        api::Change::Update(part),
                        limits,
                        OperationPacing::Eager,
                        &continuation_budget,
                        &mut root
                            .diagnostics
                            .as_mut()
                            .expect("facade diagnostics prepared")
                            .submission,
                        &mut root.polling,
                    )? {
                        OperationProgress::Ready => {}
                        _ => {
                            return Err(Error::Rejected(
                                crate::RejectionReason::SignatureContinuation(crate::SignatureContinuationRejection::SignatureUpdateDidNotEstablishInputBoundary),
                            ))
                        }
                    }
                }
                api::change_with_budget(
                    session,
                    &mut ticket,
                    api::Change::Finish(None),
                    limits,
                    OperationPacing::Eager,
                    &continuation_budget,
                    &mut root
                        .diagnostics
                        .as_mut()
                        .expect("facade diagnostics prepared")
                        .submission,
                    &mut root.polling,
                )?
            } else {
                poll::poll_operation_with_diagnostics(
                    session,
                    &mut ticket,
                    crate::session::CleanupAdmission::Ordinary,
                    OperationPacing::Eager,
                    &mut root.polling,
                )?
            };
            match result {
                OperationProgress::NativeSignature(result)
                | OperationProgress::NativeVerification(result) => Ok(result),
                OperationProgress::SignatureBufferRequired(request) => {
                    let error = Error::SignatureBufferRequired(request);
                    Err(error)
                }
                _ => Err(Error::Rejected(
                    crate::RejectionReason::SignatureContinuation(
                        crate::SignatureContinuationRejection::SignatureFacadeIncomplete,
                    ),
                )),
            }
        })();
        match result {
            Err(error) if ticket.id != 0 => {
                // Local refusal after Init does not erase the native operation.
                // Publish the ticket once; preserve the original diagnostic.
                match api::park_synchronous(session, &mut ticket, &owner) {
                    Ok(()) => Err(error),
                    Err(cleanup) => {
                        let diagnostic = root
                            .diagnostics
                            .as_mut()
                            .and_then(|storage| storage.parking.take())
                            .expect("facade parking diagnostic prepared before Init");
                        Err(diagnostic.finish(error, cleanup))
                    }
                }
            }
            Ok(result) => {
                let publication = publish(result);
                let publication = match root
                    .diagnostics
                    .as_mut()
                    .and_then(|storage| storage.publication.take())
                {
                    Some(storage) => storage.bind(kind.terminal(route)).finish(publication),
                    None => publication,
                }?;
                Ok((publication, ticket.validation_report.take()))
            }
            Err(error) => Err(error),
        }
    })();
    outcome.map_err(|error| crate::mechanism_extension::operation::effect(error, mutates))
}

impl crate::AdvancedSession {
    /// Keep this facade's private capture setting at the advanced boundary.
    /// Callers receive both the owned native result and its optional report.
    pub(crate) fn execute_signature_batch<'a>(
        &self,
        request: crate::ExtensionRequest<'a>,
        input: ExtensionInput<'_>,
        limits: InputLimits,
        authentication: Option<crate::ContextAuthentication>,
        root: &mut Invocation,
    ) -> Result<(ExtensionResult, Option<crate::ValidationReport>)> {
        execute_with_capture(
            &self.session,
            request,
            input,
            limits,
            authentication,
            self.validation_capture == crate::ValidationCaptureMode::Capture,
            root,
        )
    }
}
