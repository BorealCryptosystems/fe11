// SPDX-License-Identifier: Apache-2.0
//! Synchronous facades for registered native object admission.
use super::{input, start_admission};
use crate::advanced::{OperationPacing, OperationProgress};
use crate::{AdvancedSessionMode, Error, Result, Session};

pub(crate) fn generate_kem_synchronous(
    session: &Session,
    prepared: crate::crypto::kem::KemOwnerPlan<'_>,
    diagnostics: &mut crate::advanced::PollDiagnostics,
) -> Result<crate::CreatedObjects<crate::KemKeyPair>> {
    project(
        run_synchronous(
            session,
            input::Input::Kem(Some(prepared)),
            true,
            diagnostics,
        )?,
        |result| match result {
            OperationProgress::KemKeyPair(pair) => Ok(pair),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::MlKemCreationResultOwnerMismatch,
            ))),
        },
    )
}

pub(crate) fn find_kem_synchronous(
    session: &Session,
    prepared: crate::crypto::kem::KemOwnerPlan<'_>,
    diagnostics: &mut crate::advanced::PollDiagnostics,
) -> Result<crate::KemKeyPair> {
    match run_synchronous(
        session,
        input::Input::Kem(Some(prepared)),
        false,
        diagnostics,
    )? {
        OperationProgress::KemKeyPair(pair) => Ok(pair),
        _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
            crate::KeyAdmissionRejection::MlKemSelectionResultOwnerMismatch,
        ))),
    }
}

pub(crate) fn pqc_pair_synchronous(
    session: &Session,
    prepared: crate::crypto::pqc::PqcOwnerPlan<'_>,
    generate: bool,
    diagnostics: &mut crate::advanced::PollDiagnostics,
) -> Result<crate::CreatedObjects<crate::PqcKeyPair>> {
    project(
        run_synchronous(
            session,
            input::Input::Pqc(Some(prepared)),
            generate,
            diagnostics,
        )?,
        |result| match result {
            OperationProgress::PqcKeyPair(pair) => Ok(pair),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::PqcAdmissionResultOwnerMismatch,
            ))),
        },
    )
}

pub(crate) fn classical_pair_synchronous(
    session: &Session,
    prepared: crate::crypto::ClassicalPairPlan<'_>,
    generate: bool,
    diagnostics: &mut crate::advanced::PollDiagnostics,
) -> Result<crate::CreatedObjects<crate::ClassicalKeyPair>> {
    project(
        run_synchronous(
            session,
            input::Input::Classical(Some(prepared)),
            generate,
            diagnostics,
        )?,
        |result| match result {
            OperationProgress::ClassicalKeyPair(pair) => Ok(pair),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::ClassicalAdmissionResultOwnerMismatch,
            ))),
        },
    )
}

pub(crate) fn rsa_transport_synchronous(
    session: &Session,
    prepared: crate::crypto::ClassicalPairPlan<'_>,
    diagnostics: &mut crate::advanced::PollDiagnostics,
) -> Result<crate::CreatedObjects<crate::RsaKeyEncryptionPair>> {
    project(
        run_synchronous(
            session,
            input::Input::Classical(Some(prepared)),
            true,
            diagnostics,
        )?,
        |result| match result {
            OperationProgress::RsaKeyEncryptionPair(pair) => Ok(pair),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::RsaTransportResultOwnerMismatch,
            ))),
        },
    )
}

pub(crate) fn transport_signing_synchronous(
    session: &Session,
    prepared: crate::crypto::ClassicalPairPlan<'_>,
    diagnostics: &mut crate::advanced::PollDiagnostics,
) -> Result<crate::CreatedObjects<crate::TransportSigningKeyPair>> {
    project(
        run_synchronous(
            session,
            input::Input::Classical(Some(prepared)),
            true,
            diagnostics,
        )?,
        |result| match result {
            OperationProgress::TransportSigningKeyPair(pair) => Ok(pair),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::TransportSigningResultOwnerMismatch,
            ))),
        },
    )
}

pub(crate) fn symmetric_synchronous(
    session: &Session,
    spec: crate::SymmetricKeySpec,
    generate: bool,
    diagnostics: &mut crate::advanced::PollDiagnostics,
) -> Result<crate::CreatedObjects<crate::SymmetricKey>> {
    spec.validate()?;
    project(
        run_synchronous(
            session,
            input::Input::symmetric(spec, super::symmetric_publication::Publication::Ordinary),
            generate,
            diagnostics,
        )?,
        |result| match result {
            OperationProgress::SymmetricKey(key) => Ok(key),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::SymmetricAdmissionResultOwnerMismatch,
            ))),
        },
    )
}

pub(crate) fn aes_kek_synchronous(
    session: &Session,
    spec: crate::AesKeyEncryptionSpec,
    generate: bool,
    diagnostics: &mut crate::advanced::PollDiagnostics,
) -> Result<crate::CreatedObjects<crate::AesKeyEncryptionKey>> {
    project(
        run_synchronous(
            session,
            input::Input::Symmetric(Some(input::SymmetricInput::aes_kek(spec)?)),
            generate,
            diagnostics,
        )?,
        |result| match result {
            OperationProgress::AesKeyEncryptionKey(key) => Ok(key),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AesKekAdmissionResultOwnerMismatch,
            ))),
        },
    )
}

pub(crate) fn introduced_symmetric_synchronous(
    session: &Session,
    spec: crate::SymmetricIntroductionSpec,
    generate: bool,
    diagnostics: &mut crate::advanced::PollDiagnostics,
) -> Result<crate::CreatedObjects<crate::IntroducedSymmetricKey>> {
    project(
        run_synchronous(
            session,
            input::Input::Symmetric(Some(input::SymmetricInput::introduced_symmetric(spec)?)),
            generate,
            diagnostics,
        )?,
        |result| match result {
            OperationProgress::IntroducedSymmetricKey(key) => Ok(key),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::IntroducedSymmetricResultOwnerMismatch,
            ))),
        },
    )
}

pub(crate) fn verification_synchronous(
    session: &Session,
    prepared: crate::crypto::VerificationPlan<'_>,
    diagnostics: &mut crate::advanced::PollDiagnostics,
) -> Result<crate::VerificationKey> {
    let policy = input::Input::Verification(Some(prepared));
    match run_synchronous(session, policy, false, diagnostics)? {
        OperationProgress::VerificationKey(key) => Ok(key),
        _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
            crate::KeyAdmissionRejection::VerificationSelectionResultOwnerMismatch,
        ))),
    }
}

pub(crate) fn agreement_pair_synchronous(
    session: &Session,
    prepared: crate::crypto::derivation::AgreementPairPlan,
    diagnostics: &mut crate::advanced::PollDiagnostics,
) -> Result<crate::CreatedObjects<crate::crypto::derivation::AgreementPairResult>> {
    project(
        run_synchronous(
            session,
            input::Input::Agreement(Some(prepared)),
            true,
            diagnostics,
        )?,
        |result| match result {
            OperationProgress::AgreementKeyPair(pair) => Ok(
                crate::crypto::derivation::AgreementPairResult::Weierstrass(pair),
            ),
            OperationProgress::MontgomeryKeyPair(pair) => Ok(
                crate::crypto::derivation::AgreementPairResult::Montgomery(pair),
            ),
            OperationProgress::TransportAgreementKeyPair(pair) => Ok(
                crate::crypto::derivation::AgreementPairResult::Transport(pair),
            ),
            _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AgreementPairResultOwnerMismatch,
            ))),
        },
    )
}

pub(crate) fn derivation_base_synchronous(
    session: &Session,
    prepared: crate::crypto::derivation::DerivationBasePlan,
    generate: bool,
    diagnostics: &mut crate::advanced::PollDiagnostics,
) -> Result<crate::CreatedObjects<crate::crypto::derivation::DerivationBaseResult>> {
    project(
        run_synchronous(
            session,
            input::Input::Base(Some(prepared)),
            generate,
            diagnostics,
        )?,
        |result| match result {
            OperationProgress::AgreementKey(key) => Ok(
                crate::crypto::derivation::DerivationBaseResult::Agreement(key),
            ),
            OperationProgress::MontgomeryKey(key) => Ok(
                crate::crypto::derivation::DerivationBaseResult::Montgomery(key),
            ),
            OperationProgress::HkdfKey(key) => {
                Ok(crate::crypto::derivation::DerivationBaseResult::Hkdf(key))
            }
            OperationProgress::IntroducedAgreementKey(key) => {
                Ok(crate::crypto::derivation::DerivationBaseResult::IntroducedAgreement(key))
            }
            _ => Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::DerivationBaseResultOwnerMismatch,
            ))),
        },
    )
}

fn run_synchronous(
    session: &Session,
    policy: input::Input<'_>,
    generate: bool,
    diagnostics: &mut crate::advanced::PollDiagnostics,
) -> Result<OperationProgress> {
    if session.entry.mode != AdvancedSessionMode::Synchronous {
        return Err(Error::Rejected(crate::RejectionReason::SessionLifecycle(
            crate::SessionLifecycleRejection::SynchronousAdmissionRequiresASynchronousSession,
        )));
    }
    let pacing = OperationPacing::Eager;
    let mut ticket = start_admission(
        session,
        policy,
        generate,
        pacing,
        crate::session::ReferenceMode::SynchronousAdmission,
        diagnostics,
    )?;
    loop {
        let result = super::super::poll::poll_operation_with_diagnostics(
            session,
            &mut ticket,
            crate::session::CleanupAdmission::Ordinary,
            pacing,
            diagnostics,
        );
        let failure = match result {
            Ok(OperationProgress::Ready) => continue,
            Ok(OperationProgress::Pending) => synchronous_pending(generate, diagnostics),
            Ok(result) => return Ok(result),
            Err(error) => error,
        };
        if let Ok(Some(objects)) = ticket.created_objects() {
            return Ok(OperationProgress::CreatedObjects(crate::CreatedObjects {
                objects,
                observation: Err(failure),
                remainder: None,
            }));
        }
        return Err(failure);
    }
}

fn synchronous_pending(
    generate: bool,
    diagnostics: &mut crate::advanced::PollDiagnostics,
) -> Error {
    let cause = Error::Rejected(crate::RejectionReason::KeyAdmission(
        crate::KeyAdmissionRejection::SynchronousAdmissionPendingExplicitCloseRequired,
    ));
    if generate {
        diagnostics
            .pending
            .as_mut()
            .expect("synchronous generation marker")
            .take()
            .expect("one pending result per synchronous facade")
            .mark_remaining(cause)
    } else {
        cause
    }
}

fn project<T>(
    progress: OperationProgress,
    convert: impl FnOnce(OperationProgress) -> Result<T>,
) -> Result<crate::CreatedObjects<T>> {
    match progress {
        OperationProgress::CreatedObjects(outcome) => Ok(outcome
            .map(super::super::GeneratedObjects::into_progress)
            .try_map(convert)),
        value => convert(value).map(|value| crate::CreatedObjects::without_objects(Ok(value))),
    }
}
