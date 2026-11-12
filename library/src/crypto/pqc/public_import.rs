// SPDX-License-Identifier: Apache-2.0
use super::{PqcPublicKey, PqcVerificationKey};
use crate::{managed, Error, Result, Session};
use fe11_sys::*;
use sha2::{Digest, Sha256};
impl Session {
    /// Import a canonical public PQC key with explicit native requests and
    /// independent object/mechanism observations. The creation result retains
    /// the native object even if a subsequent optional observation fails.
    /// This grants no private signing permission or certificate trust.
    pub fn import_pqc_verification_key(
        &self,
        spki: &[u8],
        mechanism_policy: crate::MechanismAttributes<'_>,
        options: crate::PublicKeyImportOptions,
    ) -> Result<crate::CreatedObjects<PqcVerificationKey>> {
        let mut diagnostics = None;
        mechanism_policy.validate()?;
        let (algorithm, raw) = PqcPublicKey::borrow_spki(spki)?;
        let fingerprint: [u8; 32] = Sha256::digest(spki).into();
        let metadata = options.metadata.plan(spki)?;
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
        let id = metadata.identifier()?;
        let label = metadata.label();
        let planned = import_template::<crate::attributes::TemplateSize>(
            algorithm,
            raw,
            id,
            label,
            &options,
            &mechanism_policy,
        )?
        .owned_bytes()?;
        let identity = [
            (CKA_CLASS, CKO_PUBLIC_KEY),
            (CKA_KEY_TYPE, algorithm.key_type()),
            (CKA_PARAMETER_SET, algorithm.description().parameter),
        ];
        // borrow_spki established the input encoding. The supplied identity
        // describes the typed view; no public-material equality check follows.
        managed::create_public(
            self,
            id,
            label,
            &options.admission,
            crate::crypto::public_import::observation::Spec {
                identity: &identity,

                maximum: options.admission.metadata.maximum_bytes,
                mechanisms: &mechanism_policy.admission,
            },
            planned,
            || import_template(algorithm, raw, id, label, &options, &mechanism_policy),
            &reference_admission,
            epoch,
            &mut diagnostics,
            |access| reference_admission.check(access),
            |managed, policy| {
                Ok(PqcVerificationKey {
                    managed,
                    algorithm,
                    fingerprint,
                    policy,
                })
            },
        )
    }
}

// The same borrowed recipe measures and materializes native inputs. No native
// access or allocation is needed when T is TemplateSize.
fn import_template<T: crate::attributes::TemplateSink>(
    algorithm: super::PqcAlgorithm,
    raw: &[u8],
    id: crate::attributes::ByteParts<'_>,
    label: &[u8],
    options: &crate::PublicKeyImportOptions,
    mechanism_policy: &crate::MechanismAttributes<'_>,
) -> Result<T> {
    let mut template = T::empty();
    template.integer(CKA_CLASS, CKO_PUBLIC_KEY);
    template.integer(CKA_KEY_TYPE, algorithm.key_type());
    template.integer(CKA_PARAMETER_SET, algorithm.description().parameter);
    template.bytes(CKA_VALUE, raw);
    template.byte_parts(CKA_ID, id);
    template.bytes(CKA_LABEL, label);
    let policy = [
        (CKA_PRIVATE, options.visibility.is_private()),
        (CKA_TOKEN, options.persistent),
        (CKA_MODIFIABLE, options.modifiable),
        (CKA_COPYABLE, options.copyable),
        (CKA_DESTROYABLE, options.destroyable),
    ];
    for (field, value) in policy {
        template.boolean(field, value);
    }
    options.usages.apply(&mut template);
    mechanism_policy.apply_borrowed(&mut template)?;
    Ok(template)
}
