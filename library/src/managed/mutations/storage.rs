// SPDX-License-Identifier: Apache-2.0

use super::*;
use x509_cert::{
    der::{asn1::ObjectIdentifier, Decode, Encode},
    Certificate,
};

/// Native data storage. The type OID is not an object-instance identifier.
pub struct DataSpec {
    /// Native CKA_MODIFIABLE request, independent of observations.
    pub modifiable: bool,
    /// Native CKA_COPYABLE request.
    pub copyable: bool,
    /// Native CKA_DESTROYABLE request.
    pub destroyable: bool,

    /// Independent observation and control selection for the created object.
    pub admission: crate::ObjectAdmission,
    /// Independent post-creation content observation or comparison.
    pub content: crate::ContentObservation,
    /// Independent destination query, cardinality and recorded-role choices.
    pub destination: crate::DestinationPlan,
    /// Application tag supplied as UTF-8 bytes; native length must fit CK_ULONG.
    pub application: String,
    /// DER type OID representable by the ASN.1 codec, or empty for unspecified.
    pub object_type: Vec<u8>,
    /// Label supplied as UTF-8 bytes; no presentation policy is imposed.
    pub label: String,
    /// Requested native visibility; native access refusals are preserved.
    pub private: bool,
    /// Persistent objects require a read-write session.
    pub persistent: bool,
}
/// Certificate storage metadata, never a trust decision or authorization to issue.
/// Subject/issuer/serial are derived exclusively from canonical X.509 DER.
/// For raw certificate attributes without DER extraction, use `Session::create_object`.
/// This facade does not validate a chain, signature, identity or issuance policy.
pub struct CertificateSpec {
    /// Native CKA_TRUSTED request. The module enforces any required role.
    pub trusted: bool,
    /// Native CKA_CERTIFICATE_CATEGORY value; not an organizational trust decision.
    pub category: u64,
    /// Native CKA_MODIFIABLE request, independent of observations.
    pub modifiable: bool,
    /// Native CKA_COPYABLE request.
    pub copyable: bool,
    /// Native CKA_DESTROYABLE request.
    pub destroyable: bool,

    /// Independent observation and control selection for the created object.
    pub admission: crate::ObjectAdmission,
    /// Independent post-creation content observation or comparison.
    pub content: crate::ContentObservation,
    /// Independent destination query, cardinality and recorded-role choices.
    pub destination: crate::DestinationPlan,
    /// Exact caller-supplied CKA_ID bytes, subject to ABI width and selected resource limits.
    pub id: Vec<u8>,
    /// Label supplied as UTF-8 bytes; no presentation policy is imposed.
    pub label: String,
    /// Requested native visibility; native access refusals are preserved.
    pub private: bool,
    /// Persistent objects require a read-write session.
    pub persistent: bool,
}
struct CertificateFields {
    subject: Vec<u8>,
    issuer: Vec<u8>,
    serial: Vec<u8>,
}
fn certificate_fields(der: &[u8]) -> Result<CertificateFields> {
    if der.is_empty() {
        return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
            crate::ObjectMutationRejection::CertificateSize,
        )));
    }
    let certificate = Certificate::from_der(der).map_err(|_| {
        Error::Rejected(crate::RejectionReason::ObjectMutation(
            crate::ObjectMutationRejection::CertificateDer,
        ))
    })?;
    if certificate.to_der().map_err(|_| {
        Error::Rejected(crate::RejectionReason::ObjectMutation(
            crate::ObjectMutationRejection::CertificateEncoding,
        ))
    })? != der
    {
        return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
            crate::ObjectMutationRejection::NoncanonicalCertificate,
        )));
    }
    let tbs = certificate.tbs_certificate;
    Ok(CertificateFields {
        subject: tbs.subject.to_der().map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::SubjectEncoding,
            ))
        })?,
        issuer: tbs.issuer.to_der().map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::IssuerEncoding,
            ))
        })?,
        serial: tbs.serial_number.to_der().map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::SerialEncoding,
            ))
        })?,
    })
}
fn type_oid(der: &[u8]) -> Result<()> {
    if !der.is_empty() {
        let oid = ObjectIdentifier::from_der(der).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::DataTypeOid,
            ))
        })?;
        if oid.to_der().map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::DataTypeOidEncoding,
            ))
        })? != der
        {
            return Err(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::NoncanonicalDataType,
            )));
        }
    }
    Ok(())
}
// Immutable metadata recipe; native value/witness copies are transient and
// are constructed together with the protected content only after admission.
struct ContentTemplate {
    private: bool,
    modifiable: bool,
    copyable: bool,
    destroyable: bool,
    kind: ContentKind,
}
enum ContentKind {
    Data,
    Certificate {
        trusted: bool,
        category: CK_ULONG,
        fields: CertificateFields,
    },
}
// Borrowed destination operands are validated by each public facade. Their
// credited representation is built only after local admission and the publication quota.
enum ContentDestination<'a> {
    Data {
        application: &'a str,
        object_type: &'a [u8],
        label: &'a str,
    },
    Certificate(&'a [u8]),
}
impl<'a> ContentDestination<'a> {
    fn build(self, session: &Session) -> Result<DestinationRecipe<'a>> {
        match self {
            Self::Data {
                application,
                object_type,
                label,
            } => DestinationRecipe::new(
                session,
                ManagedClass::Data,
                &[application.as_bytes(), object_type, label.as_bytes()],
            ),
            Self::Certificate(id) => {
                DestinationRecipe::new(session, ManagedClass::Certificate, &[id])
            }
        }
    }
}
impl ContentTemplate {
    fn build<T: crate::attributes::TemplateSink>(
        &self,
        destination: &DestinationRecipe<'_>,
        label: &str,
        persistent: bool,
    ) -> Result<T> {
        let mut template = destination.template::<T>()?;
        if matches!(self.kind, ContentKind::Certificate { .. }) {
            template.bytes(CKA_LABEL, label.as_bytes());
        }
        template.boolean(CKA_PRIVATE, self.private);
        template.boolean(CKA_TOKEN, persistent);
        for (attribute, value) in [
            (CKA_MODIFIABLE, self.modifiable),
            (CKA_COPYABLE, self.copyable),
            (CKA_DESTROYABLE, self.destroyable),
        ] {
            template.boolean(attribute, value);
        }
        if let ContentKind::Certificate {
            trusted,
            category,
            fields,
        } = &self.kind
        {
            template.integer(CKA_CERTIFICATE_TYPE, CKC_X_509);
            template.boolean(CKA_TRUSTED, *trusted);
            template.integer(CKA_CERTIFICATE_CATEGORY, *category);
            template.bytes(CKA_SUBJECT, &fields.subject);
            template.bytes(CKA_ISSUER, &fields.issuer);
            template.bytes(CKA_SERIAL_NUMBER, &fields.serial);
        }
        Ok(template)
    }
}

impl Session {
    /// Store bounded data without exporting keys or exposing an arbitrary native template.
    /// Input and read-back content stay in protected buffers, including public data.
    pub fn create_data(
        &self,
        spec: DataSpec,
        content: SecretBytes,
    ) -> Result<crate::CreatedObjects<ManagedObjectRef>> {
        let mut diagnostics = None;
        label_valid(&spec.application)?;
        label_valid(&spec.label)?;
        type_oid(&spec.object_type)?;
        let destination = ContentDestination::Data {
            application: &spec.application,
            object_type: &spec.object_type,
            label: &spec.label,
        };
        let template = ContentTemplate {
            private: spec.private,
            modifiable: spec.modifiable,
            copyable: spec.copyable,
            destroyable: spec.destroyable,
            kind: ContentKind::Data,
        };
        self.create_content(
            destination,
            &spec.label,
            spec.persistent,
            template,
            content,
            spec.admission,
            spec.content,
            spec.destination,
            &mut diagnostics,
        )
    }
    /// Store exactly one canonical X.509 DER certificate; no chain/profile/key-link validation.
    /// Native trust/category requests and optional observations are caller selected.
    pub fn create_certificate(
        &self,
        spec: CertificateSpec,
        content: SecretBytes,
    ) -> Result<crate::CreatedObjects<ManagedObjectRef>> {
        let mut diagnostics = None;
        id_valid(&spec.id)?;
        label_valid(&spec.label)?;
        let fields = certificate_fields(content.as_slice())?;
        let destination = ContentDestination::Certificate(&spec.id);
        let template = ContentTemplate {
            private: spec.private,
            modifiable: spec.modifiable,
            copyable: spec.copyable,
            destroyable: spec.destroyable,
            kind: ContentKind::Certificate {
                trusted: spec.trusted,
                category: spec.category.try_into().map_err(|_| {
                    Error::Rejected(crate::RejectionReason::ObjectMutation(
                        crate::ObjectMutationRejection::CertificateCategoryNativeWidth,
                    ))
                })?,
                fields,
            },
        };
        self.create_content(
            destination,
            &spec.label,
            spec.persistent,
            template,
            content,
            spec.admission,
            spec.content,
            spec.destination,
            &mut diagnostics,
        )
    }
    fn create_content(
        &self,
        destination: ContentDestination<'_>,
        label: &str,
        persistent: bool,
        template: ContentTemplate,
        content: SecretBytes,
        admission: crate::ObjectAdmission,
        check: crate::ContentObservation,
        destination_plan: crate::DestinationPlan,
        invocation: &mut crate::error::ObjectCreationDiagnostics,
    ) -> Result<crate::CreatedObjects<ManagedObjectRef>> {
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
        let progress = reference_admission.progress();
        let destination = destination.build(self)?;
        let class = ManagedClass::from_raw(destination.class.ok_or(Error::Rejected(
            crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::ContentClassAbsent,
            ),
        ))?);
        let public =
            template.build::<crate::attributes::TemplateSize>(&destination, label, persistent)?;
        let components = [(CKA_VALUE, content.as_slice())];
        use super::create::resident::Initial;
        use crate::native::creation::ObjectCreation;
        use crate::session::recovery::observations::{context, Prepared};
        use crate::transport::secret_template::NativeSecretStorage;
        let fixed = Initial::fixed_bytes()?
            .checked_add(ObjectCreation::private_frame_bytes())
            .and_then(|bytes| {
                bytes.checked_add(crate::error::PreparedCompletion::allocation_bytes())
            })
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::ContentCreationStorageSize,
            )))?;
        let observation_bytes = destination.with_identity(label, |identity| {
            Initial::requested(class, &admission, &destination_plan, &identity, true)
        })?;
        let mut required = fixed
            .checked_add(NativeSecretStorage::allocation_bytes(&public, &components)?)
            .and_then(|bytes| bytes.checked_add(observation_bytes))
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                crate::ObjectMutationRejection::ContentCreationStorageSize,
            )))?;
        let (((diagnostic, call, observations, registry, permit, prepaid), reservation), access) =
            Reservation::prepare_mutation_prepaid(
                self,
                &[destination],
                1,
                None,
                [],
                false,
                epoch,
                progress,
                |overhead, current| loop {
                    context(self, Some(epoch), epoch)?;
                    let admitted = required.checked_add(overhead).ok_or(Error::Rejected(
                        crate::RejectionReason::ObjectCreation(
                            crate::ObjectCreationRejection::CreationAggregateAccounting,
                        ),
                    ))?;
                    let group =
                        reference_admission.managed_with_observation_storage(1, admitted, || {
                            context(self, Some(epoch), epoch)?;
                            if !current()? {
                                return Err(Error::Busy(crate::BusyReason::ObjectMutation(
                                    crate::ObjectMutationBusy::ContentCreationPlanChanged,
                                )));
                            }
                            Ok(())
                        });
                    let (permit, mut prepaid) = match group {
                        Ok(group) => group,
                        Err(Error::Busy(crate::BusyReason::ObjectMutation(
                            crate::ObjectMutationBusy::ContentCreationPlanChanged,
                        ))) => return Ok(None),
                        Err(error) => return Err(error),
                    };
                    let native = NativeSecretStorage::allocate(
                        template.build(&destination, label, persistent)?,
                        &components,
                    )?;
                    let observations = destination.with_identity(label, |identity| {
                        Initial::allocate(class, &admission, &destination_plan, &identity, true)
                    })?;
                    let observation_bytes = observations.allocated_bytes()?;
                    let actual = fixed
                        .checked_add(native.allocated_bytes()?)
                        .and_then(|bytes| bytes.checked_add(observation_bytes))
                        .and_then(|bytes| bytes.checked_add(overhead))
                        .ok_or(Error::Rejected(crate::RejectionReason::ObjectMutation(
                            crate::ObjectMutationRejection::ContentCreationStorageSize,
                        )))?;
                    if actual > admitted {
                        drop((native, observations));
                        drop((prepaid, permit));
                        required = actual.checked_sub(overhead).ok_or(Error::Rejected(
                            crate::RejectionReason::ObjectCreation(
                                crate::ObjectCreationRejection::CreationAggregateAccounting,
                            ),
                        ))?;
                        continue;
                    }
                    prepaid.release(admitted - actual);
                    prepaid.observation_budget()?;
                    let diagnostic =
                        crate::error::PreparedCompletion::prepare("C_CreateObject", &mut prepaid)?;
                    let call =
                        ObjectCreation::private_prepaid(native.bind(&mut prepaid)?, &mut prepaid)?;
                    let registry = Prepared::allocate(&self.inner.symmetric_budget, &mut prepaid)?;
                    let coordination = prepaid.split(overhead)?;
                    return Ok(Some((
                        (diagnostic, call, observations, registry, permit, prepaid),
                        coordination,
                    )));
                },
                |access| reference_admission.check(access),
            )?;
        drop(content);
        reference_admission.check(&access)?;
        let content_plan = match &check {
            crate::ContentObservation::NotRequested => None,
            crate::ContentObservation::Observe(read) => Some(*read),
        };
        let (coordination, access, cleanup) = observations.publish(
            self,
            access,
            call,
            &reservation,
            class,
            admission.clone(),
            check,
            destination_plan,
            permit,
            epoch,
            registry,
            prepaid,
        )?;
        drop((reservation, template));
        let (diagnostic, cleanup) = invocation.insert((diagnostic, cleanup));
        super::create::resident::runner::run(
            self,
            &admission,
            class,
            content_plan,
            progress,
            epoch,
            coordination,
            access,
            diagnostic,
            cleanup,
        )
    }
}
