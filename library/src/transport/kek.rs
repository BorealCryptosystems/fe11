// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::{
    attributes::Template, bounds, managed, module::State, ManagedClass, SecretBytes, Session,
};
use fe11_sys::*;
use std::sync::Arc;

/// Explicit convenience views to expose; native usages are requested separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyTransportUsage {
    /// Expose a wrapping view.
    Wrap,
    /// Expose an unwrapping view.
    Unwrap,
    /// Expose both operation views.
    WrapAndUnwrap,
}
impl KeyTransportUsage {
    fn wrap(self) -> bool {
        self != Self::Unwrap
    }
    fn unwrap(self) -> bool {
        self != Self::Wrap
    }
}
/// AES key-encryption-key requests and explicit observations.
/// The algorithm must select AES128/192/256; that selection alone does not
/// attest a native key length. Generation transmits the size request, while
/// lookup does not implicitly compare the native length. Import checks both
/// the supplied material length and, on successful observation, the length
/// reported by the module. For Unwrap, see [`crate::Session::unwrap_aes_key_encryption_key`].
pub struct AesKeyEncryptionSpec {
    /// Native SENSITIVE/EXTRACTABLE request, independent of observations and routing.
    pub native_protection: crate::CurrentKeyProtection,
    /// Explicit native history/protection reads and their aggregate budget.
    pub history_observation: crate::HistoryObservationPlan,
    /// Requested AES size, identity, usages and object/mechanism observations.
    /// AES Unwrap on tables through 3.1 omits CKA_VALUE_LEN; select ValueLen in
    /// key.admission.public_attributes when a length observation is required.
    /// HMAC type must be None. Outer protection/history fields govern this request;
    /// key.protection_request and key.history are not applied.
    pub key: SymmetricKeySpec,
    /// Convenience views; does not override key.usages or native permissions.
    pub usage: KeyTransportUsage,
}
impl AesKeyEncryptionSpec {
    pub(crate) fn validate(&self) -> Result<()> {
        self.key.validate()?;
        if !matches!(
            self.key.algorithm,
            crate::SymmetricAlgorithm::Aes128
                | crate::SymmetricAlgorithm::Aes192
                | crate::SymmetricAlgorithm::Aes256
        ) {
            return Err(Error::Rejected(crate::RejectionReason::KeyTransport(
                crate::KeyTransportRejection::AesKekAlgorithm,
            )));
        }
        Ok(())
    }
}
pub(super) struct Kek {
    pub key: ManagedObjectRef,
    pub usage: KeyTransportUsage,
    pub report: IntroductionReport,
    pub mechanism_report: crate::MechanismObservationReport,
}
/// Dedicated AES KEK; no conversion to an encryption/MAC key is available.
/// This owner does not attest a key size by its type. Its introduction path and
/// selected observations determine what length evidence is available. Compare
/// an explicit CKA_VALUE_LEN observation when the application requires a size
/// before wrapping further keys; see [`AesKeyEncryptionSpec`].
pub struct AesKeyEncryptionKey {
    pub(super) inner: Arc<Kek>,
}
impl AesKeyEncryptionKey {
    pub(crate) fn from_parts(
        key: ManagedObjectRef,
        usage: KeyTransportUsage,
        report: IntroductionReport,
        mechanism_report: crate::MechanismObservationReport,
    ) -> Self {
        // Retain the admitted identity and its evidence. Creation-only inputs
        // must not become implicit gates on later native transport operations.
        Self {
            inner: Arc::new(Kek {
                key,
                usage,
                report,
                mechanism_report,
            }),
        }
    }

    /// Actual mechanism observation, without a local authorization policy.
    pub fn mechanism_report(&self) -> &crate::MechanismObservationReport {
        &self.inner.mechanism_report
    }
    /// Administrative identity, without a native handle or value.
    pub fn managed(&self) -> &ManagedObjectRef {
        &self.inner.key
    }
    /// Exact current and historical observations.
    pub fn report(&self) -> IntroductionReport {
        self.inner.report.clone()
    }
    /// Wrapping view selected by the caller; native permissions remain separate.
    pub fn wrapping(&self) -> Option<WrappingKey> {
        self.inner.usage.wrap().then(|| WrappingKey {
            inner: TransportKek::Aes(self.inner.clone()),
        })
    }
    /// Unwrapping view selected by the caller; native permissions remain separate.
    pub fn unwrapping(&self) -> Option<UnwrappingKey> {
        self.inner.usage.unwrap().then(|| UnwrappingKey {
            inner: TransportKek::Aes(self.inner.clone()),
        })
    }
}
/// Opaque reference restricted to native protected wrapping.
pub struct WrappingKey {
    pub(super) inner: TransportKek,
}
impl WrappingKey {
    /// Mechanism admission retained by the actual transport key owner.
    pub fn mechanism_report(&self) -> &crate::MechanismObservationReport {
        self.inner.mechanism_report()
    }
    /// Public administrative identity.
    pub fn managed(&self) -> &ManagedObjectRef {
        self.inner.managed()
    }
}
/// Opaque reference restricted to native unwrapping into a typed destination.
pub struct UnwrappingKey {
    pub(super) inner: TransportKek,
}
impl UnwrappingKey {
    /// Mechanism admission retained by the actual transport key owner.
    pub fn mechanism_report(&self) -> &crate::MechanismObservationReport {
        self.inner.mechanism_report()
    }
    /// Public administrative identity.
    pub fn managed(&self) -> &ManagedObjectRef {
        self.inner.managed()
    }
}
pub(super) fn template(spec: &AesKeyEncryptionSpec, length: bool) -> Result<Template> {
    template_recipe(spec, length)
}

pub(super) fn template_size(
    spec: &AesKeyEncryptionSpec,
    length: bool,
) -> Result<crate::attributes::TemplateSize> {
    template_recipe(spec, length)
}

fn template_recipe<T: crate::attributes::TemplateSink>(
    spec: &AesKeyEncryptionSpec,
    length: bool,
) -> Result<T> {
    let k = &spec.key;
    let mut t = T::empty();
    t.integer(CKA_CLASS, CKO_SECRET_KEY);
    t.integer(CKA_KEY_TYPE, CKK_AES);
    if length {
        t.integer(CKA_VALUE_LEN, bounds::ck_length(k.algorithm.key_length())?);
    }
    t.bytes(CKA_ID, &k.id);
    t.bytes(CKA_LABEL, k.label.as_bytes());
    for (a, v) in [
        (CKA_TOKEN, k.persistent),
        (CKA_PRIVATE, k.visibility.is_private()),
        (CKA_SENSITIVE, spec.native_protection.sensitive),
        (CKA_EXTRACTABLE, spec.native_protection.extractable),
    ] {
        t.boolean(a, v);
    }
    k.usages.apply(&mut t);
    Ok(t)
}
pub(super) fn validate_live(s: &State, session: &Session, k: &Kek) -> Result<CK_OBJECT_HANDLE> {
    let h = session.managed_handle(s, &k.key)?;
    super::operations::bound(s, session, &k.key, h)?;
    Ok(h)
}
impl Session {
    /// Generate a dedicated AES KEK with caller-selected native usages and views.
    pub fn generate_aes_key_encryption_key(
        &self,
        spec: AesKeyEncryptionSpec,
    ) -> Result<crate::CreatedObjects<AesKeyEncryptionKey>> {
        let mut diagnostics = crate::advanced::PollDiagnostics::default();
        crate::advanced::aes_kek_synchronous(self, spec, true, &mut diagnostics)
    }
    /// Import owned AES material; copies owned here are erased on return.
    /// Checks the supplied material length against the requested size. A successful
    /// observation also compares the module's reported CKA_VALUE_LEN with that size.
    /// Creation and observation results remain distinct in [`crate::CreatedObjects`];
    /// this import-specific comparison is not an implicit guarantee of Unwrap.
    pub fn import_aes_key_encryption_key(
        &self,
        spec: AesKeyEncryptionSpec,
        material: SecretBytes,
    ) -> Result<crate::CreatedObjects<AesKeyEncryptionKey>> {
        let mut diagnostics = None;
        spec.validate()?;
        if material.as_slice().len() != spec.key.algorithm.key_length() {
            return Err(Error::Rejected(crate::RejectionReason::KeyTransport(
                crate::KeyTransportRejection::AesKekMaterialLength,
            )));
        }
        self.introduce_aes_kek(spec, material, &mut diagnostics)
    }
    /// Resolve a dedicated AES KEK using the caller's discovery and observation plan.
    /// Class and key type are checked; the requested size is not automatically
    /// compared with the module's length. Select CKA_VALUE_LEN explicitly when needed.
    /// Local/non-local observations do not claim an introduction invocation.
    pub fn find_aes_key_encryption_key(
        &self,
        spec: AesKeyEncryptionSpec,
    ) -> Result<AesKeyEncryptionKey> {
        let mut diagnostics = crate::advanced::PollDiagnostics::default();
        crate::advanced::aes_kek_synchronous(self, spec, false, &mut diagnostics)
            .and_then(|outcome| outcome.observation)
    }
    fn introduce_aes_kek(
        &self,
        spec: AesKeyEncryptionSpec,
        material: SecretBytes,
        diagnostics: &mut crate::error::ObjectCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<AesKeyEncryptionKey>> {
        let epoch = self.snapshot.authentication_stamp();
        let reference_admission = self.reference_admission_at_epoch(
            crate::session::ReferenceMode::Synchronous,
            epoch,
            |state| {
                state.native.table.C_CreateObject.ok_or(Error::Rejected(
                    crate::RejectionReason::KeyTransport(
                        crate::KeyTransportRejection::NativeKekCreationUnavailable,
                    ),
                ))?;
                Ok(())
            },
        )?;
        let public = template_recipe::<crate::attributes::TemplateSize>(&spec, false)?;
        let identity = [
            (CKA_CLASS, CKO_SECRET_KEY),
            (CKA_KEY_TYPE, CKK_AES),
            (
                CKA_VALUE_LEN,
                bounds::ck_length(spec.key.algorithm.key_length())?,
            ),
        ];
        let prepared = managed::prepare_private_creation(
            self,
            ManagedClass::SecretKey,
            &spec.key.id,
            spec.key.label.as_bytes(),
            &spec.key.admission,
            crate::crypto::key_evidence::Spec {
                order: crate::crypto::key_evidence::Order::HistoryThenMechanisms,
                introduction: Some(crate::crypto::key_evidence::Introduction {
                    origin: IntroductionOrigin::Imported,
                }),
                identity: &identity,
                maximum: spec.key.admission.metadata.maximum_bytes,
                history: spec.history_observation,
                mechanisms: Some(&spec.key.mechanisms),
            },
            &public,
            &[(CKA_VALUE, material.as_slice())],
            &[],
            || template(&spec, false),
            &reference_admission,
            epoch,
            None,
            |access| reference_admission.check(access),
        )?;
        drop(material);
        prepared.finish(
            self,
            &spec.key.admission,
            reference_admission.progress(),
            diagnostics,
            |key, evidence, _public| {
                let report = evidence.introduction.ok_or(Error::Rejected(
                    crate::RejectionReason::KeyTransport(
                        crate::KeyTransportRejection::ImportedKekHistoryReportAbsent,
                    ),
                ))?;

                let mechanisms = evidence.mechanisms.ok_or(Error::Rejected(
                    crate::RejectionReason::KeyTransport(
                        crate::KeyTransportRejection::KeyMechanismReportAbsent,
                    ),
                ))?;

                Ok(AesKeyEncryptionKey::from_parts(
                    key, spec.usage, report, mechanisms,
                ))
            },
        )
    }
}

// Each view retains its native identity and observations; the module decides usage validity.
pub(super) enum TransportKek {
    Aes(Arc<Kek>),
    RsaWrapping(Arc<super::rsa::RsaKek<()>>),
    RsaUnwrapping(Arc<super::rsa::RsaKek<IntroductionReport>>),
}
impl TransportKek {
    fn mechanism_report(&self) -> &crate::MechanismObservationReport {
        match self {
            Self::Aes(k) => &k.mechanism_report,
            Self::RsaWrapping(k) => &k.mechanism_report,
            Self::RsaUnwrapping(k) => &k.mechanism_report,
        }
    }

    pub(super) fn managed(&self) -> &ManagedObjectRef {
        match self {
            Self::Aes(k) => &k.key,
            Self::RsaWrapping(k) => &k.key,
            Self::RsaUnwrapping(k) => &k.key,
        }
    }

    /// Resolve the retained identity without pre-empting native mechanism or usage checks.
    pub(super) fn native_handle(&self, s: &State, session: &Session) -> Result<CK_OBJECT_HANDLE> {
        match self {
            Self::Aes(k) => validate_live(s, session, k),
            Self::RsaWrapping(k) => super::rsa::validate_live(s, session, k),
            Self::RsaUnwrapping(k) => super::rsa::validate_live(s, session, k),
        }
    }
}
