// SPDX-License-Identifier: Apache-2.0
use super::{
    PqcAlgorithm, PqcSignature, PqcSignatureParameters, PqcSigningKey, PqcVerificationKey,
};
use crate::{Error, InputLimits, Result, Session, Verification};
use fe11_sys::*;

impl Session {
    /// Sign the original message or external prehash according to the explicit
    /// parameters. No public proof, local hash, sizing call, fallback or retry.
    pub fn sign_pqc(
        &self,
        key: &PqcSigningKey,
        parameters: &PqcSignatureParameters,
        message: &[u8],
        limits: InputLimits,
    ) -> Result<PqcSignature> {
        let mut diagnostics = super::frame::SigningDiagnostics::default();
        self.sign_pqc_selected(key, parameters, message, limits, None, &mut diagnostics)
    }

    /// Sign after one explicit contextual login between Init and Sign.
    /// Authentication is independent of the cryptographic signature context.
    /// A refused login retains the initialized operation for session closure.
    pub fn sign_pqc_with_context(
        &self,
        key: &PqcSigningKey,
        parameters: &PqcSignatureParameters,
        message: &[u8],
        limits: InputLimits,
        authentication: crate::ContextAuthentication,
    ) -> Result<PqcSignature> {
        let mut diagnostics = super::frame::SigningDiagnostics::default();
        self.sign_pqc_selected(
            key,
            parameters,
            message,
            limits,
            Some(authentication),
            &mut diagnostics,
        )
    }

    fn sign_pqc_selected(
        &self,
        key: &PqcSigningKey,
        parameters: &PqcSignatureParameters,
        message: &[u8],
        limits: InputLimits,
        mut authentication: Option<crate::ContextAuthentication>,
        diagnostics: &mut super::frame::SigningDiagnostics,
    ) -> Result<PqcSignature> {
        let mut prepared_authentication;
        super::parameters::validate_message(
            limits,
            self.inner.crypto_options.limits,
            message.len(),
        )?;
        parameters.validate_input(message.len())?;
        parameters.mechanism_type(key.algorithm)?;

        let epoch = self.snapshot.authentication_stamp();
        let progress = crate::session::AdmissionProgress::default();
        let mut authentication_plan =
            crate::session::ContextLoginPlan::at_epoch(self, authentication.as_ref(), epoch)?;
        let (((prepared, prepared_diagnostic), mut authentication_storage), state) = self
            .prepare_with_roles_prepaid_at_epoch(
                [(
                    Some(&key.managed),
                    crate::session::activity::AccessMode::Read,
                )],
                authentication.is_some(),
                epoch,
                &progress,
                |overhead| {
                    authentication_plan.prepare(self, overhead, |overhead| {
                        super::frame::PreparedPqcCall::signing(
                            self,
                            key.algorithm,
                            parameters,
                            message.len(),
                            &progress,
                            epoch,
                            overhead,
                        )
                    })
                },
            )?;
        let diagnostic = diagnostics.sequence.insert(prepared_diagnostic).cell();
        prepared_authentication = crate::session::PreparedContextLogin::from_prepared(
            self,
            &state,
            &mut authentication,
            &mut authentication_storage,
        )?;

        let handle = self.managed_handle(&state, &key.managed)?;
        let result = self.pqc_sign_native_with_context(
            &state,
            handle,
            key.algorithm,
            parameters,
            message,
            key.managed.identity.access,
            prepared_authentication.as_mut(),
            prepared,
            diagnostic,
        );
        diagnostics.authentication = prepared_authentication.map(|value| value.into_diagnostics());
        result
    }

    pub(super) fn pqc_sign_native_with_context(
        &self,
        state: &crate::session::SessionAccess<'_>,
        key: CK_OBJECT_HANDLE,
        algorithm: PqcAlgorithm,
        parameters: &PqcSignatureParameters,
        message: &[u8],
        access: crate::managed::ObjectAccess,
        authentication: Option<&mut crate::session::PreparedContextLogin<'_>>,
        prepared: super::frame::SigningCall,
        diagnostic: &crate::error::CompletionCell,
    ) -> Result<PqcSignature> {
        parameters.validate_input(message.len())?;
        access.check(&self.snapshot)?;
        let result = self.pqc_sign_parts_guarded(
            state,
            key,
            algorithm,
            parameters,
            &[message],
            false,
            authentication,
            prepared,
            diagnostic,
        );
        access.result(self, state, result)
    }

    /// Verify the explicitly selected PQC mode on the module, without treating a successful
    /// mathematical check as identity, authorization or certificate trust.
    pub fn verify_pqc(
        &self,
        key: &PqcVerificationKey,
        parameters: &PqcSignatureParameters,
        message: &[u8],
        signature: &PqcSignature,
        limits: InputLimits,
    ) -> Result<Verification> {
        super::parameters::validate_message(
            limits,
            self.inner.crypto_options.limits,
            message.len(),
        )?;
        if signature.algorithm() != key.algorithm {
            return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcSignatureAlgorithmMismatch,
            )));
        }
        parameters.validate_input(message.len())?;
        parameters.mechanism_type(key.algorithm)?;

        let epoch = self.snapshot.authentication_stamp();
        let progress = crate::session::AdmissionProgress::default()
            .retaining(signature.retained_bytes(&self.inner.symmetric_budget)?)?;
        let ((prepared, diagnostic), state) = self.prepare_with_roles_prepaid_at_epoch(
            [(
                Some(&key.managed),
                crate::session::activity::AccessMode::Read,
            )],
            false,
            epoch,
            &progress,
            |overhead| {
                super::frame::PreparedPqcCall::verification(
                    self,
                    key.algorithm,
                    parameters,
                    message.len(),
                    signature.as_bytes(),
                    &progress,
                    epoch,
                    overhead,
                )
            },
        )?;
        let handle = self.managed_handle(&state, &key.managed)?;
        let result = self.pqc_verify_parts_guarded(
            &state,
            handle,
            key.algorithm,
            parameters,
            &[message],
            false,
            signature.as_bytes(),
            prepared,
            diagnostic.cell(),
        );
        self.managed_result(&state, &key.managed, result)
    }
}
