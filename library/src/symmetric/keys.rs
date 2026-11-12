// SPDX-License-Identifier: Apache-2.0
use super::*;

use crate::{attributes::RequiredAttributes, Session};

pub(crate) fn validate_required(v: &RequiredAttributes, spec: &SymmetricKeySpec) -> Result<()> {
    v.integer(CKA_CLASS, CKO_SECRET_KEY)?;
    v.integer(CKA_KEY_TYPE, spec.algorithm.key_type(spec.hmac_key_type)?)?;
    // Length is request metadata. Native reads are selected separately in
    // spec.admission.public_attributes and retained as observations.
    Ok(())
}
pub(crate) fn protection_snapshot(
    snapshot: crate::BaseProtection,
    invocation: GenerationInvocation,
) -> SymmetricProtection {
    SymmetricProtection {
        local: snapshot.local,
        always_sensitive: snapshot.historical.always_sensitive,
        never_extractable: snapshot.historical.never_extractable,
        generation: GenerationMechanismReport {
            selection: snapshot.observation_plan,
            invocation,
            observation: snapshot.generation,
        },
        observations: snapshot,
    }
}

pub(crate) fn generation_template_as<T: crate::attributes::TemplateSink>(
    spec: &SymmetricKeySpec,
) -> Result<T> {
    let mut t = T::empty();
    t.integer(CKA_CLASS, CKO_SECRET_KEY);
    t.integer(CKA_KEY_TYPE, spec.algorithm.key_type(spec.hmac_key_type)?);
    t.integer(
        CKA_VALUE_LEN,
        bounds::ck_length(spec.algorithm.key_length())?,
    );
    t.bytes(CKA_ID, &spec.id);
    t.bytes(CKA_LABEL, spec.label.as_bytes());
    for (field, value) in [
        (CKA_TOKEN, spec.persistent),
        (CKA_PRIVATE, spec.visibility.is_private()),
        (CKA_SENSITIVE, spec.protection_request.sensitive),
        (CKA_EXTRACTABLE, spec.protection_request.extractable),
    ] {
        t.boolean(field, value);
    }
    spec.usages.apply(&mut t);
    Ok(t)
}
impl Session {
    /// Generate a native key with explicitly requested protection and admission.
    /// A successful creation returns its references in `CreatedObjects` even
    /// when a requested observation fails. That separate observation error is
    /// not evidence that the created object was destroyed.
    pub fn generate_symmetric_key(
        &self,
        spec: SymmetricKeySpec,
    ) -> Result<crate::CreatedObjects<SymmetricKey>> {
        self.generate_symmetric_for(spec)
    }
    /// Generate an AES key with the observation and controls in its specification.
    /// This does not alter the native key's allowed-mechanism attribute.
    pub fn generate_aes_key(
        &self,
        spec: SymmetricKeySpec,
    ) -> Result<crate::CreatedObjects<SymmetricKey>> {
        require_aes(spec.algorithm)?;
        self.generate_symmetric_for(spec)
    }
    fn generate_symmetric_for(
        &self,
        spec: SymmetricKeySpec,
    ) -> Result<crate::CreatedObjects<SymmetricKey>> {
        let mut diagnostics = crate::advanced::PollDiagnostics::default();
        crate::advanced::symmetric_synchronous(self, spec, true, &mut diagnostics)
    }
    /// Admit one existing key using the explicitly selected provenance controls.
    pub fn find_symmetric_key(&self, spec: SymmetricKeySpec) -> Result<SymmetricKey> {
        self.find_symmetric_for(spec)
    }
    /// Admit AES using the explicit observation plans and controls in its specification.
    pub fn find_aes_key(&self, spec: SymmetricKeySpec) -> Result<SymmetricKey> {
        require_aes(spec.algorithm)?;
        self.find_symmetric_for(spec)
    }
    fn find_symmetric_for(&self, spec: SymmetricKeySpec) -> Result<SymmetricKey> {
        let mut diagnostics = crate::advanced::PollDiagnostics::default();
        crate::advanced::symmetric_synchronous(self, spec, false, &mut diagnostics)
            .and_then(|outcome| outcome.observation)
    }
}
fn require_aes(algorithm: SymmetricAlgorithm) -> Result<()> {
    if matches!(
        algorithm,
        SymmetricAlgorithm::Aes128 | SymmetricAlgorithm::Aes192 | SymmetricAlgorithm::Aes256
    ) {
        Ok(())
    } else {
        Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
            crate::KeyAdmissionRejection::AesKeyRequired,
        )))
    }
}


