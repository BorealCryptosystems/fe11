// SPDX-License-Identifier: Apache-2.0
//! Operational aliases share the imported object's lifetime and native observations.
use super::{PqcAlgorithm, PqcPublicKey, PqcSigningKey};
use crate::{Error, PqcImportedPrivateKey, PqcPrivateKeyAlgorithm, Result, Session};
use sha2::{Digest, Sha256};

impl Session {
    /// Observe an imported ML-DSA key and return a signing alias sharing its
    /// revocation and activity guards. The supplied public bytes identify the
    /// caller's declaration; no signature witness or private/public comparison
    /// is performed. The observation report does not rewrite the original view.
    pub fn admit_imported_pqc_signing_key(
        &self,
        key: &PqcImportedPrivateKey,
        mechanisms: crate::MechanismObservationPlan,
        admission: crate::ObjectAdmission,
    ) -> Result<(PqcSigningKey, crate::ObjectObservationReport)> {
        let PqcPrivateKeyAlgorithm::MlDsa(parameter_set) = key.algorithm() else {
            return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::MlDsaImportedKeyFamily,
            )));
        };
        let algorithm = PqcAlgorithm::MlDsa(parameter_set);
        let public = PqcPublicKey::from_raw(algorithm, key.input_public_key())?;
        let fingerprint = Sha256::digest(public.to_spki()?).into();
        crate::mechanism_controls::resident::observe(
            self,
            key.managed(),
            &admission,
            &mechanisms,
            |access| key.check_current(self, access).map(|_| ()),
            |access, observations, policy| {
                let stamp = self.snapshot.authentication_stamp();
                let managed = key.admitted_alias(self, access)?;
                self.snapshot.check_authentication_unchanged(stamp)?;
                self.entry(access)?;
                Ok((
                    PqcSigningKey {
                        managed,
                        algorithm,
                        fingerprint,
                        policy,
                    },
                    observations,
                ))
            },
        )
    }
}
