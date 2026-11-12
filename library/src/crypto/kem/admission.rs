// SPDX-License-Identifier: Apache-2.0
use super::*;

use crate::{managed, Error, Result, Session};
use fe11_sys::*;


pub(super) fn templates_as<T: crate::attributes::TemplateSink>(
    spec: &KemKeySpec,
    protection: crate::CurrentKeyProtection,
    public_visibility: crate::ObjectVisibility,
) -> (T, T) {
    let mut public = T::empty();
    let mut private = T::empty();
    for (template, class) in [
        (&mut public, CKO_PUBLIC_KEY),
        (&mut private, CKO_PRIVATE_KEY),
    ] {
        template.integer(CKA_CLASS, class);
        template.integer(CKA_KEY_TYPE, CKK_ML_KEM);
        template.bytes(CKA_ID, &spec.id);
        template.bytes(CKA_LABEL, spec.label.as_bytes());
        template.boolean(CKA_TOKEN, spec.persistent);
        template.boolean(
            CKA_PRIVATE,
            if class == CKO_PRIVATE_KEY {
                spec.private_visibility.is_private()
            } else {
                public_visibility.is_private()
            },
        );
    }
    public.integer(CKA_PARAMETER_SET, spec.parameter_set.raw());
    spec.public_usages.apply(&mut public);
    spec.private_usages.apply(&mut private);
    for (field, value) in [
        (CKA_SENSITIVE, protection.sensitive),
        (CKA_EXTRACTABLE, protection.extractable),
    ] {
        private.boolean(field, value);
    }
    (public, private)
}

impl Session {
    /// Admit an imported ML-KEM object for explicit decapsulation operations.
    /// Checks the current attributes and selected 3.2 function without creating
    /// a public object or invoking a KEM operation. This is not a private
    /// possession proof; the administrative alias retains shared revocation.
    /// Returns the operational alias and the explicitly selected destination
    /// property report; the original reference's binding is not rewritten.
    pub fn admit_imported_kem_decapsulation_key(
        &self,
        key: &crate::PqcImportedPrivateKey,
        mechanisms: crate::MechanismObservationPlan,
        admission: crate::ObjectAdmission,
    ) -> Result<(KemDecapsulationKey, crate::ObjectObservationReport)> {
        let crate::PqcPrivateKeyAlgorithm::MlKem(parameter_set) = key.algorithm() else {
            return Err(Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                crate::KeyEncapsulationRejection::MlKemImportedKeyFamily,
            )));
        };

        crate::mechanism_controls::resident::observe(
            self,
            key.managed(),
            &admission,
            &mechanisms,
            |state| {
                let functions = state.native.kem.ok_or(Error::Rejected(
                    crate::RejectionReason::KeyEncapsulation(
                        crate::KeyEncapsulationRejection::MlKemRequiresSelected32Interface,
                    ),
                ))?;
                if functions.decapsulate.is_none() {
                    return Err(Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                        crate::KeyEncapsulationRejection::CDecapsulateKeyUnavailable,
                    )));
                }
                key.check_current(self, state)?;
                Ok(())
            },
            |state, observations, allowed| {
                let managed = key.admitted_alias(self, state)?;
                Ok((
                    KemDecapsulationKey {
                        managed,
                        parameter_set,
                        allowed,
                    },
                    observations,
                ))
            },
        )
    }

    /// Select existing ML-KEM objects using the supplied SPKI's parameter set.
    /// The returned public value comes from native observation, not from retaining
    /// or comparing the supplied declaration. This typed view is not a proof
    /// that the public and private objects correspond. No key creation, private-value
    /// read or encapsulation is implicit. Requested observations and native errors
    /// use the same owner as the advanced method; existing objects are preserved.
    pub fn find_kem_key_pair(
        &self,
        id: &[u8],
        expected_spki: &[u8],
        public_policy: crate::MechanismObservationPlan,
        private_policy: crate::MechanismObservationPlan,
        public_admission: crate::ObjectAdmission,
        private_admission: crate::ObjectAdmission,
    ) -> Result<KemKeyPair> {
        let mut diagnostics = crate::advanced::PollDiagnostics::default();
        let prepared = crate::crypto::kem::KemOwnerPlan::selected(
            id,
            expected_spki,
            public_policy,
            private_policy,
            public_admission,
            private_admission,
        )?;
        crate::advanced::find_kem_synchronous(self, prepared, &mut diagnostics)
    }

    /// Generate a native KEM pair with explicit public/private mechanism policies,
    /// private-key protection and public-object visibility. Requests and admission
    /// observations remain independent; generation requires no KEM operation.
    /// No alternate template follows a refusal. Postcreation failure reports
    /// possible remaining objects for explicit reconciliation.
    pub fn generate_kem_key_pair(
        &self,
        spec: KemKeySpec,
        public_policy: crate::MechanismAttributes<'_>,
        private_policy: crate::MechanismAttributes<'_>,
        protection: crate::CurrentKeyProtection,
        public_visibility: crate::ObjectVisibility,
    ) -> Result<crate::CreatedObjects<KemKeyPair>> {
        let mut diagnostics = crate::advanced::PollDiagnostics::default();
        let prepared = crate::crypto::kem::KemOwnerPlan::generating(
            spec,
            public_policy,
            private_policy,
            protection,
            public_visibility,
        )?;
        crate::advanced::generate_kem_synchronous(self, prepared, &mut diagnostics)
    }

    /// Import an immutable public encapsulation key with explicit native requests
    /// and independent object/mechanism controls. No observation is implied by the
    /// creation request. Recipient authentication belongs to the consuming protocol.
    pub fn import_kem_public_key(
        &self,
        public_key: &KemPublicKey,
        policy: crate::MechanismAttributes<'_>,
        options: crate::PublicKeyImportOptions,
    ) -> Result<crate::CreatedObjects<KemEncapsulationKey>> {
        let mut diagnostics = None;
        policy.validate()?;
        let epoch = self.snapshot.authentication_stamp();
        let reference_admission = self.reference_admission_at_epoch(
            crate::session::ReferenceMode::Synchronous,
            epoch,
            |state| {
                state.native.table.C_CreateObject.ok_or(Error::Rejected(
                    crate::RejectionReason::PublicVerification(
                        crate::PublicVerificationRejection::CCreateObjectUnavailable,
                    ),
                ))?;
                Ok(())
            },
        )?;
        let metadata = options
            .metadata
            .plan_with_fingerprint(|| public_key.spki_fingerprint())?;
        let id = metadata.identifier()?;
        let label = metadata.label();
        let planned = import_template::<crate::attributes::TemplateSize>(
            public_key, id, label, &options, &policy,
        )?
        .owned_bytes()?;
        let identity = [
            (CKA_CLASS, CKO_PUBLIC_KEY),
            (CKA_KEY_TYPE, CKK_ML_KEM),
            (CKA_PARAMETER_SET, public_key.parameter_set().raw()),
        ];
        managed::create_public_prepared(
            self,
            id,
            label,
            &options.admission,
            crate::crypto::public_import::observation::Spec {
                identity: &identity,

                maximum: options.admission.metadata.maximum_bytes,
                mechanisms: &policy.admission,
            },
            Some(crate::crypto::public_import::publication::Plan::Kem(
                public_key,
            )),
            planned,
            || import_template(public_key, id, label, &options, &policy),
            &reference_admission,
            epoch,
            &mut diagnostics,
            |access| reference_admission.check(access),
            |managed, allowed, publication| {
                let Some(crate::crypto::public_import::publication::Prepared::Kem {
                    key: public,
                    credit: _credit,
                }) = publication
                else {
                    return Err(Error::Rejected(crate::RejectionReason::KeyEncapsulation(
                        crate::KeyEncapsulationRejection::KemPublicPublicationPairing,
                    )));
                };
                Ok(KemEncapsulationKey {
                    managed,
                    // This is the caller's key, copied during preparation. Native
                    // readback observes class/type/parameter and selected attributes;
                    // it does not establish equality with the module's key bytes.
                    public,
                    allowed,
                })
            },
        )
    }
}


// The same borrowed recipe measures and materializes native inputs. No native
// access or allocation is needed when T is TemplateSize.
fn import_template<T: crate::attributes::TemplateSink>(
    public_key: &KemPublicKey,
    id: crate::attributes::ByteParts<'_>,
    label: &[u8],
    options: &crate::PublicKeyImportOptions,
    policy: &crate::MechanismAttributes<'_>,
) -> Result<T> {
    let mut template = T::empty();
    template.integer(CKA_CLASS, CKO_PUBLIC_KEY);
    template.integer(CKA_KEY_TYPE, CKK_ML_KEM);
    template.integer(CKA_PARAMETER_SET, public_key.parameter_set().raw());
    template.bytes(CKA_VALUE, public_key.as_raw());
    template.byte_parts(CKA_ID, id);
    template.bytes(CKA_LABEL, label);
    let policy_fields = [
        (CKA_TOKEN, options.persistent),
        (CKA_PRIVATE, options.visibility.is_private()),
        (CKA_MODIFIABLE, options.modifiable),
        (CKA_COPYABLE, options.copyable),
        (CKA_DESTROYABLE, options.destroyable),
    ];
    for (field, value) in policy_fields {
        template.boolean(field, value);
    }
    options.usages.apply(&mut template);
    policy.apply_borrowed(&mut template)?;
    Ok(template)
}


