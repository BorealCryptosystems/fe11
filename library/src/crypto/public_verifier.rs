// SPDX-License-Identifier: Apache-2.0
//! Lease of the explicitly selected verification engine for public verification.
//! Native object admission never selects or invokes this component.

use crate::VerifyEngine;

pub(super) fn failure(error: crate::Error) -> crate::RejectionReason {
    match error {
        crate::Error::Rejected(reason) => reason,
        _ => crate::RejectionReason::PublicVerification(
            crate::PublicVerificationRejection::VerificationEngineRequestFailed,
        ),
    }
}

pub(super) struct Context {
    engine: VerifyEngine,
}
impl Context {
    pub(super) fn selected(engine: Option<&VerifyEngine>) -> Result<Self, crate::RejectionReason> {
        let engine = engine.ok_or(crate::RejectionReason::PublicVerification(
            crate::PublicVerificationRejection::VerificationEngineNotSelected,
        ))?;
        if !engine.info().verification_service {
            return Err(crate::RejectionReason::VerificationEngine(
                crate::VerificationEngineRejection::VerificationEngineVerificationUnavailable,
            ));
        }
        Ok(Self {
            engine: engine.clone(),
        })
    }
    pub(super) fn engine(&self) -> &VerifyEngine {
        &self.engine
    }
}
