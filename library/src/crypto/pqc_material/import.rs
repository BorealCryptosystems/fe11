// SPDX-License-Identifier: Apache-2.0
//! Private object introduction without a generation or operational admission claim.
use super::*;

use crate::module::State;

use crate::{managed, CurrentKeyProtection, MechanismAttributes, SecretBytes, TransportProtection};

#[doc = include_str!("../../../docs/api/crypto/pqc_material/import/PqcPrivateInput.md")]
pub enum PqcPrivateInput {
    /// Supply only the normative seed.
    Seed {
        /// Exact family and parameter set.
        algorithm: PqcPrivateKeyAlgorithm,
        /// 32 bytes for ML-DSA or 64-byte d||z for ML-KEM.
        seed: SecretBytes,
    },
    /// Supply only the FIPS expanded private encoding.
    Value {
        /// Exact family and parameter set.
        algorithm: PqcPrivateKeyAlgorithm,
        /// Exact-length expanded signing or decapsulation key.
        value: SecretBytes,
    },
    /// Supply both representations unchanged; Fe11 does not compare their contents.
    SeedAndValue {
        /// Exact family and parameter set.
        algorithm: PqcPrivateKeyAlgorithm,
        /// Normative seed.
        seed: SecretBytes,
        /// Expanded key; correspondence to the seed is not checked locally.
        value: SecretBytes,
    },
}

impl PqcPrivateInput {
    /// Exact caller-selected algorithm.
    pub fn algorithm(&self) -> PqcPrivateKeyAlgorithm {
        match self {
            Self::Seed { algorithm, .. }
            | Self::Value { algorithm, .. }
            | Self::SeedAndValue { algorithm, .. } => *algorithm,
        }
    }

    fn validate(&self) -> Result<()> {
        let algorithm = self.algorithm();
        let seed = |value: &SecretBytes| -> Result<()> {
            if value.len() != algorithm.seed_length() {
                return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                    crate::PostQuantumKeysRejection::PqcImportSeedLength,
                )));
            }
            Ok(())
        };
        let value = |bytes: &SecretBytes| -> Result<()> {
            if bytes.len() != algorithm.value_length() {
                return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                    crate::PostQuantumKeysRejection::PqcImportValueLength,
                )));
            }
            Ok(())
        };
        match self {
            Self::Seed { seed: bytes, .. } => seed(bytes),
            Self::Value { value: bytes, .. } => value(bytes),
            Self::SeedAndValue {
                seed: s, value: v, ..
            } => {
                seed(s)?;
                value(v)
            }
        }
    }
}

/// Explicit metadata, protection and family-specific private usage for import.
pub struct PqcPrivateImportSpec {
    /// Explicit native history/protection reads and their aggregate budget.
    pub history_observation: crate::HistoryObservationPlan,
    /// Explicit observations for the resulting object.
    pub admission: crate::ObjectAdmission,
    /// Native CKA_ID bytes; destination observations are selected independently.
    pub id: Vec<u8>,
    /// UTF-8 native label; no library-defined presentation policy.
    pub label: String,
    /// Token object when true; otherwise owned by the creating session.
    pub persistent: bool,
    /// Requested CKA_SENSITIVE and CKA_EXTRACTABLE; observations are selected separately.
    pub protection: CurrentKeyProtection,
    /// Native usage attributes; omitted fields remain absent from the template.
    pub usages: crate::KeyUsageRequest,
    /// Native CKA_PRIVATE request, independent of selected observation controls.
    pub visibility: crate::ObjectVisibility,
}

impl PqcPrivateImportSpec {
    fn validate(&self) -> Result<()> {
        crate::bounds::metadata_lengths(&self.id, self.label.as_bytes())?;
        Ok(())
    }

    fn template<T: crate::attributes::TemplateSink>(&self, algorithm: PqcPrivateKeyAlgorithm) -> T {
        let (kind, parameter) = algorithm.native();
        let mut template = T::empty();
        template.integer(CKA_CLASS, CKO_PRIVATE_KEY);
        template.integer(CKA_KEY_TYPE, kind);
        template.integer(CKA_PARAMETER_SET, parameter);
        template.bytes(CKA_ID, &self.id);
        template.bytes(CKA_LABEL, self.label.as_bytes());
        template.boolean(CKA_TOKEN, self.persistent);
        template.boolean(CKA_PRIVATE, self.visibility.is_private());
        template.boolean(CKA_SENSITIVE, self.protection.sensitive);
        template.boolean(CKA_EXTRACTABLE, self.protection.extractable);
        self.usages.apply(&mut template);
        template
    }
}

#[doc = include_str!("../../../docs/api/crypto/pqc_material/import/PqcImportedPrivateKey.md")]
pub struct PqcImportedPrivateKey {
    managed: ManagedObjectRef,
    algorithm: PqcPrivateKeyAlgorithm,
    public: Vec<u8>,
    protection: TransportProtection,
    allowed: crate::MechanismObservationReport,
}

impl PqcImportedPrivateKey {
    /// Administrative reference, with no native handle or private bytes exposed.
    pub fn managed(&self) -> &ManagedObjectRef {
        &self.managed
    }
    /// Exact imported family and parameter set.
    pub fn algorithm(&self) -> PqcPrivateKeyAlgorithm {
        self.algorithm
    }
    /// Public FIPS encoding supplied with the private input. No mathematical
    /// correspondence or native private possession is inferred from these bytes.
    pub fn input_public_key(&self) -> &[u8] {
        &self.public
    }
    /// Actual current protection, origin and historical attributes.
    pub fn protection(&self) -> TransportProtection {
        self.protection
    }
    /// Admission-time observation of the family-specific native usage.
    pub fn private_operation(&self) -> crate::Observation<bool> {
        let field = match self.algorithm {
            PqcPrivateKeyAlgorithm::MlDsa(_) => crate::ObjectBooleanAttribute::Sign,
            PqcPrivateKeyAlgorithm::MlKem(_) => crate::ObjectBooleanAttribute::Decapsulate,
        };
        self.managed.object_observations().observation(field)
    }
    /// Admission-time mechanism evidence; None is not a permission guarantee.
    pub fn allowed_mechanisms(&self) -> Option<Vec<u64>> {
        match self.allowed.observation() {
            crate::Observation::Observed(values) => Some(values.clone()),
            _ => None,
        }
    }
    /// Actual native observation and exact read selection used at import.
    pub fn mechanism_report(&self) -> &crate::MechanismObservationReport {
        &self.allowed
    }

    // The caller retains object activity and session state while validating
    // this reference's lifetime. No private possession proof follows.
    pub(crate) fn check_current(
        &self,
        session: &Session,
        state: &State,
    ) -> Result<CK_OBJECT_HANDLE> {
        let handle = session.managed_handle(state, &self.managed)?;
        Ok(handle)
    }

    // Preserve one identity, creator and revocation bit across administrative
    // and operational aliases; no new native object or registry entry exists.
    pub(crate) fn admitted_alias(
        &self,
        session: &Session,
        state: &State,
    ) -> Result<ManagedObjectRef> {
        self.check_current(session, state)?;
        Ok(ManagedObjectRef {
            native: self.managed.native_object(),
            inner: self.managed.inner.clone(),
            handle: self.managed.handle,
            identity: self.managed.identity.clone(),
            mutation_report: None,
            content_report: None,
            destination_report: None,
            search_report: None,
        })
    }
}

impl PqcPrivateKeyAlgorithm {
    fn native(self) -> (CK_KEY_TYPE, CK_ULONG) {
        match self {
            Self::MlDsa(MlDsaParameterSet::MlDsa44) => (CKK_ML_DSA, CKP_ML_DSA_44),
            Self::MlDsa(MlDsaParameterSet::MlDsa65) => (CKK_ML_DSA, CKP_ML_DSA_65),
            Self::MlDsa(MlDsaParameterSet::MlDsa87) => (CKK_ML_DSA, CKP_ML_DSA_87),
            Self::MlKem(MlKemParameterSet::MlKem512) => (CKK_ML_KEM, CKP_ML_KEM_512),
            Self::MlKem(MlKemParameterSet::MlKem768) => (CKK_ML_KEM, CKP_ML_KEM_768),
            Self::MlKem(MlKemParameterSet::MlKem1024) => (CKK_ML_KEM, CKP_ML_KEM_1024),
        }
    }
}

impl Session {
    /// Import exactly the supplied seed, value or both as one private object.
    /// Length checks establish the selected representation only; mathematical
    /// validity and native import permission are left to the module. No generation dependency,
    /// automatic representation substitution, private readback or retry.
    /// The returned administrative object requires separate operational admission.
    pub fn import_pqc_private_key(
        &self,
        spec: PqcPrivateImportSpec,
        input: PqcPrivateInput,
        expected_public: &[u8],
        policy: MechanismAttributes<'_>,
    ) -> Result<crate::CreatedObjects<PqcImportedPrivateKey>> {
        let mut diagnostics = None;
        spec.validate()?;
        let algorithm = input.algorithm();
        if expected_public.len() != algorithm.public_length() {
            return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcImportPublicLength,
            )));
        }
        policy.validate()?;
        input.validate()?;
        let epoch = self.snapshot.authentication_stamp();
        let reference_admission = self.reference_admission_at_epoch(
            crate::session::ReferenceMode::Synchronous,
            epoch,
            |state| {
                state.native.table.C_CreateObject.ok_or(Error::Unsupported(
                    crate::UnsupportedReason::PostQuantumKeys(
                        crate::PostQuantumKeysUnsupported::CCreateObjectUnavailable,
                    ),
                ))?;
                Ok(())
            },
        )?;
        let mut public_plan = spec.template::<crate::attributes::TemplateSize>(algorithm);
        policy.apply_borrowed(&mut public_plan)?;
        let single;
        let pair;
        let components = match &input {
            PqcPrivateInput::Seed { seed, .. } => {
                single = [(CKA_SEED, seed.as_slice())];
                &single[..]
            }
            PqcPrivateInput::Value { value, .. } => {
                single = [(CKA_VALUE, value.as_slice())];
                &single[..]
            }
            PqcPrivateInput::SeedAndValue { seed, value, .. } => {
                pair = [(CKA_SEED, seed.as_slice()), (CKA_VALUE, value.as_slice())];
                &pair[..]
            }
        };
        let (kind, parameter) = algorithm.native();
        let identity = [
            (CKA_CLASS, CKO_PRIVATE_KEY),
            (CKA_KEY_TYPE, kind),
            (CKA_PARAMETER_SET, parameter),
        ];
        let prepared = managed::prepare_private_creation(
            self,
            ManagedClass::PrivateKey,
            &spec.id,
            spec.label.as_bytes(),
            &spec.admission,
            crate::crypto::key_evidence::Spec {
                order: crate::crypto::key_evidence::Order::HistoryThenMechanisms,
                introduction: None,
                identity: &identity,
                maximum: spec.admission.metadata.maximum_bytes,
                history: spec.history_observation,
                mechanisms: Some(&policy.admission),
            },
            &public_plan,
            components,
            expected_public,
            || {
                let mut template = spec.template(algorithm);
                policy.apply_borrowed(&mut template)?;
                Ok(template)
            },
            &reference_admission,
            epoch,
            None,
            |access| reference_admission.check(access),
        )?;
        drop(input);
        prepared.finish(
            self,
            &spec.admission,
            reference_admission.progress(),
            &mut diagnostics,
            |managed, evidence, public| {
                Ok(PqcImportedPrivateKey {
                    managed,
                    algorithm,
                    public: public.into_bytes(),
                    protection: evidence.history,
                    allowed: evidence.mechanisms.ok_or(Error::Rejected(
                        crate::RejectionReason::KeyTransport(
                            crate::KeyTransportRejection::KeyMechanismReportAbsent,
                        ),
                    ))?,
                })
            },
        )
    }
}
