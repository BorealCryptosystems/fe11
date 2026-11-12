// SPDX-License-Identifier: Apache-2.0
//! Specialized PQC admissions share object reservations and creation tickets.

use super::{PqcKeyPair, PqcKeySpec};

use crate::{Result, Session};
use fe11_sys::*;

pub(super) fn templates_as<T: crate::attributes::TemplateSink>(
    spec: &PqcKeySpec,
    protection: crate::CurrentKeyProtection,
    public_visibility: crate::ObjectVisibility,
) -> (T, T) {
    let mut public = T::empty();
    let mut private = T::empty();
    // The parameterless generation mechanism contributes CLASS/KEY_TYPE.
    // PARAMETER_SET belongs only in the public generation template (§6.67/6.69).
    public.integer(CKA_PARAMETER_SET, spec.algorithm.description().parameter);
    for template in [&mut public, &mut private] {
        template.bytes(CKA_ID, &spec.id);
        template.bytes(CKA_LABEL, spec.label.as_bytes());
        template.boolean(CKA_TOKEN, spec.persistent);
    }
    public.boolean(CKA_PRIVATE, public_visibility.is_private());
    spec.public_usages.apply(&mut public);
    private.boolean(CKA_PRIVATE, spec.private_visibility.is_private());
    spec.private_usages.apply(&mut private);
    private.boolean(CKA_SENSITIVE, protection.sensitive);
    private.boolean(CKA_EXTRACTABLE, protection.extractable);
    (public, private)
}


impl Session {
    /// Generate a native PQC pair with explicit public/private mechanism policies,
    /// private-key protection and public visibility.
    /// Attribute requests do not imply observations or comparisons. Native refusal
    /// is preserved without an alternate template. CreatedObjects retains the
    /// published pair independently of a failed requested observation. No
    /// challenge signature or proof of possession is performed by this method.
    pub fn generate_pqc_key_pair(
        &self,
        spec: PqcKeySpec,

        public_policy: crate::MechanismAttributes<'_>,
        private_policy: crate::MechanismAttributes<'_>,
        protection: crate::CurrentKeyProtection,
        public_visibility: crate::ObjectVisibility,
    ) -> Result<crate::CreatedObjects<PqcKeyPair>> {
        self.generate_pqc_key_pair_selected(
            spec,
            public_policy,
            private_policy,
            protection,
            public_visibility,
        )
    }

    fn generate_pqc_key_pair_selected(
        &self,
        spec: PqcKeySpec,

        public_policy: crate::MechanismAttributes<'_>,
        private_policy: crate::MechanismAttributes<'_>,
        protection: crate::CurrentKeyProtection,
        public_visibility: crate::ObjectVisibility,
    ) -> Result<crate::CreatedObjects<PqcKeyPair>> {
        let mut diagnostics = crate::advanced::PollDiagnostics::default();
        let prepared = crate::crypto::pqc::PqcOwnerPlan::generating(
            spec,
            public_policy,
            private_policy,
            protection,
            public_visibility,
        )?;
        crate::advanced::pqc_pair_synchronous(self, prepared, true, &mut diagnostics)
    }

    /// Readmit one existing generated pair by class/ID and independently supplied
    /// canonical SPKI. Possession and property observations follow the caller selections;
    /// an absent or inconclusive witness does not attest private correspondence.
    pub fn find_pqc_key_pair(
        &self,
        id: &[u8],
        expected_spki: &[u8],

        public_policy: crate::MechanismObservationPlan,
        private_policy: crate::MechanismObservationPlan,
        public_admission: crate::ObjectAdmission,
        private_admission: crate::ObjectAdmission,
    ) -> Result<PqcKeyPair> {
        self.find_pqc_key_pair_selected(
            id,
            expected_spki,
            public_policy,
            private_policy,
            public_admission,
            private_admission,
        )
    }

    fn find_pqc_key_pair_selected(
        &self,
        id: &[u8],
        expected_spki: &[u8],

        public_policy: crate::MechanismObservationPlan,
        private_policy: crate::MechanismObservationPlan,
        public_admission: crate::ObjectAdmission,
        private_admission: crate::ObjectAdmission,
    ) -> Result<PqcKeyPair> {
        let mut diagnostics = crate::advanced::PollDiagnostics::default();
        let prepared = crate::crypto::pqc::PqcOwnerPlan::selected(
            id,
            expected_spki,
            public_policy,
            private_policy,
            public_admission,
            private_admission,
        )?;
        crate::advanced::pqc_pair_synchronous(self, prepared, false, &mut diagnostics)
            .and_then(|outcome| outcome.observation)
    }
}
