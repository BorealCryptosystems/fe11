// SPDX-License-Identifier: Apache-2.0
//! Bounded native multipart operations under one session/object reservation.
use super::{
    PqcSignature, PqcSignatureMode, PqcSignatureParameters, PqcSigningKey, PqcVerificationKey,
};
use crate::{Error, InputLimits, Result, Session, Verification};

// PKCS#11 multipart sequences contain at least one Update. As in the classical
// APIs, an empty list denotes the empty message, represented by one empty part.
pub(super) fn nonempty_parts<'a>(parts: &'a [&'a [u8]]) -> &'a [&'a [u8]] {
    if parts.is_empty() {
        &[&[]]
    } else {
        parts
    }
}

fn multipart_mode(mode: PqcSignatureMode, verification: bool) -> Result<()> {
    match mode {
        PqcSignatureMode::Prehashed(_) => Err(Error::Unsupported(
            crate::UnsupportedReason::PostQuantumKeys(crate::PostQuantumKeysUnsupported::Pkcs11PqcExternalPrehashIsSinglePartOnly),
        )),
        PqcSignatureMode::Pure if verification => Err(Error::Unsupported(
            crate::UnsupportedReason::PostQuantumKeys(crate::PostQuantumKeysUnsupported::PurePqcMultipartVerificationRequiresVerifysignature),
        )),
        PqcSignatureMode::Pure | PqcSignatureMode::HashMessage(_) => Ok(()),
    }
}

impl Session {
    /// Sign available bounded fragments with C_SignUpdate/C_SignFinal.
    /// Pure and token-hashed modes are accepted; an external prehash is not.
    /// Each fragment, including an empty fragment, causes exactly one Update.
    /// A list without fragments represents one empty fragment.
    pub fn sign_pqc_multipart(
        &self,
        key: &PqcSigningKey,
        parameters: &PqcSignatureParameters,
        parts: &[&[u8]],
        limits: InputLimits,
    ) -> Result<PqcSignature> {
        let mut diagnostics = super::frame::SigningDiagnostics::default();
        self.sign_pqc_multipart_selected(key, parameters, parts, limits, None, &mut diagnostics)
    }

    /// Sign fragments after one contextual login following Init and before
    /// the first Update. Native multipart viability rules remain unchanged.
    /// A refused login retains the initialized frame for session closure.
    pub fn sign_pqc_multipart_with_context(
        &self,
        key: &PqcSigningKey,
        parameters: &PqcSignatureParameters,
        parts: &[&[u8]],
        limits: InputLimits,
        authentication: crate::ContextAuthentication,
    ) -> Result<PqcSignature> {
        let mut diagnostics = super::frame::SigningDiagnostics::default();
        self.sign_pqc_multipart_selected(
            key,
            parameters,
            parts,
            limits,
            Some(authentication),
            &mut diagnostics,
        )
    }

    fn sign_pqc_multipart_selected(
        &self,
        key: &PqcSigningKey,
        parameters: &PqcSignatureParameters,
        parts: &[&[u8]],
        limits: InputLimits,
        mut authentication: Option<crate::ContextAuthentication>,
        diagnostics: &mut super::frame::SigningDiagnostics,
    ) -> Result<PqcSignature> {
        let mut prepared_authentication;
        multipart_mode(parameters.mode(), false)?;
        let parts = nonempty_parts(parts);
        limits.validate(self.inner.crypto_options.limits, parts)?;
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
                            parts.iter().map(|part| part.len()).max().unwrap_or(0),
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

        let access = key.managed.identity.access;
        let handle = self.managed_handle(&state, &key.managed)?;
        access.check(&self.snapshot)?;
        let result = self.pqc_sign_parts_guarded(
            &state,
            handle,
            key.algorithm,
            parameters,
            parts,
            true,
            prepared_authentication.as_mut(),
            prepared,
            diagnostic,
        );
        diagnostics.authentication = prepared_authentication.map(|value| value.into_diagnostics());
        access.result(self, &state, result)
    }

    /// Verify token-hashed fragments with C_VerifyUpdate/C_VerifyFinal.
    /// This explicitly selects the traditional verification family. Pure PQC
    /// multipart verification needs the separate VerifySignature family.
    /// A list without fragments represents one empty fragment and one Update.
    pub fn verify_pqc_multipart(
        &self,
        key: &PqcVerificationKey,
        parameters: &PqcSignatureParameters,
        parts: &[&[u8]],
        signature: &PqcSignature,
        limits: InputLimits,
    ) -> Result<Verification> {
        multipart_mode(parameters.mode(), true)?;
        let parts = nonempty_parts(parts);
        limits.validate(self.inner.crypto_options.limits, parts)?;
        if signature.algorithm() != key.algorithm {
            return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcSignatureAlgorithmMismatch,
            )));
        }
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
                    parts.iter().map(|part| part.len()).max().unwrap_or(0),
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
            parts,
            true,
            signature.as_bytes(),
            prepared,
            diagnostic.cell(),
        );
        self.managed_result(&state, &key.managed, result)
    }
}
