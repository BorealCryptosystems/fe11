// SPDX-License-Identifier: Apache-2.0
use crate::{bounds, module::State, Error, Observation, ObservationIssue, Result};

use fe11_sys::*;

mod byte_parts;
pub(crate) mod owned;
mod template_plan;
pub(crate) use byte_parts::ByteParts;
pub(crate) use owned::{ClassReadStorage, PreparedClassRead};
pub(crate) use template_plan::{OwnedTemplateStorage, TemplateSink, TemplateSize};

/// The closed set of readable public and policy attributes. No private key
/// material can be requested through this type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Attribute {
    /// Object class.
    Class,
    /// Application identifier.
    Id,
    /// Public label bytes.
    Label,
    /// Persistent object flag.
    Token,
    /// Private visibility flag.
    Private,
    /// Key type.
    KeyType,
    /// RSA public modulus.
    Modulus,
    /// RSA public exponent.
    PublicExponent,
    /// Sensitive policy flag.
    Sensitive,
    /// Export policy flag.
    Extractable,
    /// Native generation flag.
    Local,
    /// Historical sensitive policy flag.
    AlwaysSensitive,
    /// Historical non-exportability flag.
    NeverExtractable,
    /// Signing permission.
    Sign,
    /// Verification permission.
    Verify,
    /// Provider-assigned object identity.
    UniqueId,
    /// Data application tag; not an authorization.
    Application,
    /// Optional DER OID of data type, never instance identity.
    ObjectType,
    /// Copy policy.
    Copyable,
    /// Mutation policy.
    Modifiable,
    /// Deletion policy.
    Destroyable,
    /// Encryption usage.
    Encrypt,
    /// Decryption usage.
    Decrypt,
    /// Wrapping usage.
    Wrap,
    /// Unwrapping usage.
    Unwrap,
    /// Derivation usage.
    Derive,
    /// Signature recovery usage.
    SignRecover,
    /// Verification recovery usage.
    VerifyRecover,
    /// Mechanism restrictions.
    AllowedMechanisms,
    /// Trusted wrapping requirement.
    WrapWithTrusted,
    /// Provider trust flag; not settable here.
    Trusted,
    /// Provider certificate category.
    CertificateCategory,
    /// Native certificate format.
    CertificateType,
    /// Public elliptic curve parameters.
    EcParams,
    /// Public elliptic curve point.
    EcPoint,
    /// Public SubjectPublicKeyInfo.
    PublicKeyInfo,
    /// Public post-quantum parameter set.
    ParameterSet,
    /// Public subject encoding.
    Subject,
    /// Public issuer encoding.
    Issuer,
    /// Public certificate serial number encoding.
    SerialNumber,
    /// Native start date encoding.
    StartDate,
    /// Native end date encoding.
    EndDate,
    /// Native key generation mechanism.
    KeyGenMechanism,
    /// Per-operation authentication policy.
    AlwaysAuthenticate,
    /// Native secret-key length metadata, not the secret CKA_VALUE itself.
    /// Select its read explicitly in ObjectAdmission; the caller interprets the value.
    ValueLen,
}
impl Attribute {
    pub(crate) fn raw(self) -> CK_ATTRIBUTE_TYPE {
        (match self {
            Self::Class => CKA_CLASS,
            Self::Id => CKA_ID,
            Self::Label => CKA_LABEL,
            Self::Token => CKA_TOKEN,
            Self::Private => CKA_PRIVATE,
            Self::KeyType => CKA_KEY_TYPE,
            Self::Modulus => CKA_MODULUS,
            Self::PublicExponent => CKA_PUBLIC_EXPONENT,
            Self::Sensitive => CKA_SENSITIVE,
            Self::Extractable => CKA_EXTRACTABLE,
            Self::Local => CKA_LOCAL,
            Self::AlwaysSensitive => CKA_ALWAYS_SENSITIVE,
            Self::NeverExtractable => CKA_NEVER_EXTRACTABLE,
            Self::Sign => CKA_SIGN,
            Self::Verify => CKA_VERIFY,
            Self::UniqueId => CKA_UNIQUE_ID,
            Self::Application => CKA_APPLICATION,
            Self::ObjectType => CKA_OBJECT_ID,
            Self::Copyable => CKA_COPYABLE,
            Self::Modifiable => CKA_MODIFIABLE,
            Self::Destroyable => CKA_DESTROYABLE,
            Self::Encrypt => CKA_ENCRYPT,
            Self::Decrypt => CKA_DECRYPT,
            Self::Wrap => CKA_WRAP,
            Self::Unwrap => CKA_UNWRAP,
            Self::Derive => CKA_DERIVE,
            Self::SignRecover => CKA_SIGN_RECOVER,
            Self::VerifyRecover => CKA_VERIFY_RECOVER,
            Self::AllowedMechanisms => CKA_ALLOWED_MECHANISMS,
            Self::WrapWithTrusted => CKA_WRAP_WITH_TRUSTED,
            Self::Trusted => CKA_TRUSTED,
            Self::CertificateCategory => CKA_CERTIFICATE_CATEGORY,
            Self::CertificateType => CKA_CERTIFICATE_TYPE,
            Self::EcParams => CKA_EC_PARAMS,
            Self::EcPoint => CKA_EC_POINT,
            Self::PublicKeyInfo => CKA_PUBLIC_KEY_INFO,
            Self::ParameterSet => CKA_PARAMETER_SET,
            Self::Subject => CKA_SUBJECT,
            Self::Issuer => CKA_ISSUER,
            Self::SerialNumber => CKA_SERIAL_NUMBER,
            Self::StartDate => CKA_START_DATE,
            Self::EndDate => CKA_END_DATE,
            Self::KeyGenMechanism => CKA_KEY_GEN_MECHANISM,
            Self::AlwaysAuthenticate => CKA_ALWAYS_AUTHENTICATE,
            Self::ValueLen => CKA_VALUE_LEN,
        }) as CK_ATTRIBUTE_TYPE
    }
}
/// Explicit strategy for attributes whose batched response has no precise cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttributeClarification {
    /// Preserve indeterminate results; issue no individual clarification reads.
    BatchOnly,
    /// Read each indeterminate field individually once, within the remaining budget.
    ClarifyIndeterminate,
}

/// Caller-selected public metadata observation; no application policy or Default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttributeReadPlan {
    /// Total value bytes, including repeated values returned to the caller.
    /// An inventory shares this budget across all returned object metadata.
    pub maximum_bytes: usize,
    /// Whether to clarify an indeterminate batch result with an individual read.
    pub clarification: AttributeClarification,
}

/// Attribute status is distinct from a present zero-length value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AttributeValue {
    /// This field was not requested; it is not evidence of native unavailability.
    NotRequested,
    /// Public/policy bytes exactly returned by the provider.
    Available(Vec<u8>),
    /// Provider reports CKR_ATTRIBUTE_SENSITIVE.
    Sensitive,
    /// An individual read established CKR_ATTRIBUTE_TYPE_INVALID.
    Unsupported,
    /// The response did not establish an individual cause for unavailable data.
    Indeterminate,
}
// Internal cause information must not be lost before a security decision.
// Explicitly unrequested fields have no native status to interpret.
pub(crate) enum PreciseAttributeValue {
    Available(Vec<u8>),
    Sensitive,
    Unsupported,
    Indeterminate,
}
impl PreciseAttributeValue {
    pub(crate) fn public(self) -> AttributeValue {
        match self {
            Self::Available(value) => AttributeValue::Available(value),
            Self::Sensitive => AttributeValue::Sensitive,
            Self::Unsupported => AttributeValue::Unsupported,
            Self::Indeterminate => AttributeValue::Indeterminate,
        }
    }
}
// RUSTSEC-2026-0286: native ulValueLen is a byte count, never an element count.
// No typed pointer/slice cast, alignment dependency or extra allocation here.
fn mechanism_chunks<const WIDTH: usize>(bytes: &[u8]) -> Result<std::slice::ChunksExact<'_, u8>> {
    if !matches!(WIDTH, 4 | 8) || bytes.len() % WIDTH != 0 {
        return Err(Error::Rejected(
            crate::RejectionReason::AttributePreparation(
                crate::AttributePreparationRejection::MechanismAttributeWidth,
            ),
        ));
    }
    Ok(bytes.chunks_exact(WIDTH))
}
pub(crate) fn mechanisms(bytes: &[u8]) -> Result<impl Iterator<Item = CK_MECHANISM_TYPE> + '_> {
    Ok(
        mechanism_chunks::<{ std::mem::size_of::<CK_MECHANISM_TYPE>() }>(bytes)?.map(|chunk| {
            // Exact-sized chunks established above, including when the list is empty.
            CK_MECHANISM_TYPE::from_ne_bytes(
                chunk.try_into().expect("exact native mechanism width"),
            )
        }),
    )
}

// The caller owns the module/token/session/object guards. Recheck only the
// already-held local context; no ledger scan or provider capability query.
pub(crate) fn record(s: &State, session: &crate::Session) -> Result<()> {
    session.entry(s)?;
    s.native.record("C_GetAttributeValue")
}

fn reserved<T>(capacity: usize) -> Result<Vec<T>> {
    let mut values = Vec::new();
    values.try_reserve_exact(capacity).map_err(|_| {
        Error::Rejected(crate::RejectionReason::AttributePreparation(
            crate::AttributePreparationRejection::AttributeAllocation,
        ))
    })?;
    Ok(values)
}
fn partial_status(s: &State, session: CK_SESSION_HANDLE, rv: CK_RV) -> Result<()> {
    match rv {
        CKR_OK | CKR_ATTRIBUTE_SENSITIVE | CKR_ATTRIBUTE_TYPE_INVALID | CKR_BUFFER_TOO_SMALL => {
            Ok(())
        }
        _ => s.check_attribute_return(session, rv),
    }
}
fn add_attribute_size(total: usize, length: CK_ULONG, budget: usize) -> Result<(usize, usize)> {
    let n = bounds::count(length, budget)?;
    let next = total.checked_add(n).ok_or(Error::Rejected(
        crate::RejectionReason::AttributePreparation(
            crate::AttributePreparationRejection::AttributeTotal,
        ),
    ))?;
    if next > budget {
        return Err(Error::Rejected(
            crate::RejectionReason::AttributePreparation(
                crate::AttributePreparationRejection::AttributeTotal,
            ),
        ));
    }
    Ok((n, next))
}

// Closed public-material domain: CKA_VALUE deliberately has no variant.
// Content readers must use protected storage for that attribute, even after a
// public class observation, because another native client can replace a handle.
#[derive(Clone, Copy)]
pub(crate) enum FingerprintAttribute {
    Class,
    KeyType,
    Modulus,
    PublicExponent,
    Prime,
    Subprime,
    Base,
    EcParams,
    EcPoint,
    ParameterSet,
    PublicKeyInfo,
}
impl FingerprintAttribute {
    pub(crate) fn raw(self) -> CK_ATTRIBUTE_TYPE {
        match self {
            Self::Class => CKA_CLASS,
            Self::KeyType => CKA_KEY_TYPE,
            Self::Modulus => CKA_MODULUS,
            Self::PublicExponent => CKA_PUBLIC_EXPONENT,
            Self::Prime => CKA_PRIME,
            Self::Subprime => CKA_SUBPRIME,
            Self::Base => CKA_BASE,
            Self::EcParams => CKA_EC_PARAMS,
            Self::EcPoint => CKA_EC_POINT,
            Self::ParameterSet => CKA_PARAMETER_SET,
            Self::PublicKeyInfo => CKA_PUBLIC_KEY_INFO,
        }
    }
}

// One guarded object's actual observations. Missing values are retained rather
// than replaced by expectations. No Debug/Clone exposes or copies raw bytes.
pub(crate) enum ObservedAttributes {
    Resident(owned::resident::ResidentValues),
    Prepared(owned::resident::AttributeSnapshot),
}
impl ObservedAttributes {
    pub(crate) fn empty() -> Self {
        Self::Prepared(owned::resident::AttributeSnapshot::default())
    }
    pub(crate) fn from_snapshot(values: owned::resident::AttributeSnapshot) -> Self {
        Self::Prepared(values)
    }
    pub(crate) fn from_resident(values: owned::resident::ResidentValues) -> Self {
        Self::Resident(values)
    }
    pub(crate) fn into_selected_public(
        self,
        selected: &[crate::Attribute],
    ) -> Result<owned::resident::AttributeSnapshot> {
        match self {
            Self::Prepared(values) => Ok(values.select(selected)),
            Self::Resident(values) => Ok(values.into_public()),
        }
    }

    pub(crate) fn bytes(&self, kind: CK_ATTRIBUTE_TYPE) -> Observation<&[u8]> {
        match self {
            Self::Prepared(values) => values.bytes(kind),
            Self::Resident(values) => values.bytes(kind),
        }
    }

    pub(crate) fn boolean(&self, kind: CK_ATTRIBUTE_TYPE) -> Observation<bool> {
        self.bytes(kind).interpret(|bytes| match bytes {
            [CK_TRUE] => Observation::Observed(true),
            [CK_FALSE] => Observation::Observed(false),
            _ => Observation::Unusable(ObservationIssue::BooleanEncoding),
        })
    }

    pub(crate) fn integer(&self, kind: CK_ATTRIBUTE_TYPE) -> Observation<u64> {
        self.bytes(kind).interpret(|bytes| match bytes.try_into() {
            Ok(raw) => Observation::Observed(CK_ULONG::from_ne_bytes(raw) as u64),
            Err(_) => Observation::Unusable(ObservationIssue::IntegerEncoding),
        })
    }

    // Existing admission families still explicitly require all fields. They
    // must migrate to their own selected evaluations before accepting partial
    // reports; constructing an observation alone does not relax their contract.
    pub(crate) fn require_all(self) -> Result<RequiredAttributes> {
        let all_available = match &self {
            Self::Prepared(values) => values.all_available(),
            Self::Resident(values) => values.all_available(),
        };
        if !all_available {
            return Err(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::RequiredAttributeUnavailable,
                ),
            ));
        }
        Ok(RequiredAttributes(self))
    }
}

// Existing strict admission view, built from the same observation constructor
// for synchronous and advanced native reads. No expectation supplies a value.
pub(crate) struct RequiredAttributes(ObservedAttributes);
impl RequiredAttributes {
    pub(crate) fn bytes(&self, kind: CK_ATTRIBUTE_TYPE) -> Result<&[u8]> {
        match self.0.bytes(kind) {
            Observation::Observed(bytes) => Ok(bytes),
            _ => Err(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::AttributeAbsentFromAdmissionSnapshot,
                ),
            )),
        }
    }

    pub(crate) fn integer(&self, kind: CK_ATTRIBUTE_TYPE, expected: CK_ULONG) -> Result<()> {
        // A typed view requires the actual native class/type and its ABI width.
        // This is a representation check, not a policy on key properties.
        let bytes: [u8; std::mem::size_of::<CK_ULONG>()] =
            self.bytes(kind)?.try_into().map_err(|_| {
                Error::Rejected(crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::KeyTypeIntegerEncoding,
                ))
            })?;
        if CK_ULONG::from_ne_bytes(bytes) != expected {
            return Err(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::KeyTypeMismatch,
                ),
            ));
        }
        Ok(())
    }
}

// All input template storage is public or policy data, never PIN/private material.
#[derive(PartialEq, Eq)]
enum InputValue {
    Bytes(Vec<u8>),
    Boolean(CK_BBOOL),
    Integer(CK_ULONG),
    Mechanisms(Vec<CK_MECHANISM_TYPE>),
}
// Native inputs own their descriptor referents and an exact independent witness.
// This is only for public/policy templates; private components use SecretTemplate.
pub(crate) struct OwnedTemplate {
    template: Template,
    witness: Template,
    descriptors: Vec<CK_ATTRIBUTE>,
    _credit: crate::symmetric::memory::Credit,
}
// SAFETY: descriptor pointers address only this owner's heap allocations. Those
// allocations never move or resize after construction, including across threads.
unsafe impl Send for OwnedTemplate {}
impl OwnedTemplate {
    pub(crate) fn count(&self) -> Result<CK_ULONG> {
        bounds::ck_length(self.descriptors.len())
    }
    pub(crate) fn as_mut_ptr(&mut self) -> *mut CK_ATTRIBUTE {
        self.descriptors.as_mut_ptr()
    }
    pub(crate) fn unchanged(&self) -> bool {
        self.template.0 == self.witness.0
            && self.descriptors.len() == self.template.0.len()
            && self
                .descriptors
                .iter()
                .zip(&self.template.0)
                .all(|(descriptor, (kind, value))| {
                    let (pointer, length) = match value {
                        InputValue::Bytes(bytes) => (bytes.as_ptr().cast_mut().cast(), bytes.len()),
                        InputValue::Boolean(value) => (
                            (value as *const CK_BBOOL).cast_mut().cast(),
                            std::mem::size_of::<CK_BBOOL>(),
                        ),
                        InputValue::Integer(value) => (
                            (value as *const CK_ULONG).cast_mut().cast(),
                            std::mem::size_of::<CK_ULONG>(),
                        ),
                        InputValue::Mechanisms(values) => (
                            values.as_ptr().cast_mut().cast(),
                            std::mem::size_of_val(values.as_slice()),
                        ),
                    };
                    descriptor.r#type == *kind
                        && descriptor.pValue == pointer
                        && descriptor.ulValueLen as usize == length
                })
    }
}

// A failed builder retains its partial storage until drop, but can never expose
// descriptors. Keeping the first allocation error avoids changing every caller
// into an unchecked chain of individual template insertions.
pub(crate) struct Template(
    Vec<(CK_ATTRIBUTE_TYPE, InputValue)>,
    Option<crate::RejectionReason>,
);

/// Empty storage for the fixed CLASS/ID selector. The caller admits its complete
/// measured capacity before bind copies the ID or forms any native pointer.
pub(crate) struct KeySelectorStorage {
    template: Box<Template>,
    values: Vec<(CK_ATTRIBUTE_TYPE, InputValue)>,
    id: Vec<u8>,
    descriptors: Vec<CK_ATTRIBUTE>,
}
impl KeySelectorStorage {
    pub(crate) fn requested_bytes(id_len: usize) -> Result<usize> {
        Self::bytes(2, id_len, 2)
    }
    fn bytes(values: usize, id: usize, descriptors: usize) -> Result<usize> {
        values
            .checked_mul(std::mem::size_of::<(CK_ATTRIBUTE_TYPE, InputValue)>())
            .and_then(|n| {
                descriptors
                    .checked_mul(std::mem::size_of::<CK_ATTRIBUTE>())
                    .and_then(|d| n.checked_add(d))
            })
            .and_then(|n| n.checked_add(id))
            .and_then(|n| n.checked_add(std::mem::size_of::<Template>()))
            .ok_or(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::TemplateAllocationSize,
                ),
            ))
    }
    pub(crate) fn allocate(id_len: usize) -> Result<Self> {
        bounds::ck_length(id_len)?;
        Ok(Self {
            template: crate::allocation::boxed(Template::new())?,
            values: reserved(2)?,
            id: reserved(id_len)?,
            descriptors: reserved(2)?,
        })
    }
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        Self::bytes(
            self.values.capacity(),
            self.id.capacity(),
            self.descriptors.capacity(),
        )
    }
    pub(crate) fn bind(
        mut self,
        class: CK_ULONG,
        id: &[u8],
    ) -> Result<(Box<Template>, Vec<CK_ATTRIBUTE>)> {
        if id.len() > self.id.capacity() {
            return Err(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::TemplateAllocationSize,
                ),
            ));
        }
        self.id.extend_from_slice(id);
        self.values.push((CKA_CLASS, InputValue::Integer(class)));
        self.values.push((CKA_ID, InputValue::Bytes(self.id)));
        *self.template = Template(self.values, None);
        let descriptors = self.template.descriptors_into(self.descriptors)?;
        Ok((self.template, descriptors))
    }
}

impl Template {
    /// Minimum owned storage for a public identity template and its descriptors.
    /// Scalar identity values live inline; `payload` counts only byte values.
    pub(crate) fn identity_allocation_bytes(fields: usize, payload: usize) -> Result<usize> {
        fields
            .checked_mul(
                std::mem::size_of::<(CK_ATTRIBUTE_TYPE, InputValue)>()
                    + std::mem::size_of::<CK_ATTRIBUTE>(),
            )
            .and_then(|n| n.checked_add(std::mem::size_of::<Self>()))
            .and_then(|n| n.checked_add(payload))
            .ok_or(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::TemplateAllocationSize,
                ),
            ))
    }

    // Copies only public/policy inputs, using fallible allocations throughout.
    pub(crate) fn try_duplicate(&self) -> Result<Self> {
        if let Some(cause) = self.1 {
            return Err(Error::Rejected(cause));
        }
        let mut values = reserved(self.0.len())?;
        for (kind, value) in &self.0 {
            let value = match value {
                InputValue::Bytes(bytes) => {
                    let mut copy = reserved(bytes.len())?;
                    copy.extend_from_slice(bytes);
                    InputValue::Bytes(copy)
                }
                InputValue::Boolean(value) => InputValue::Boolean(*value),
                InputValue::Integer(value) => InputValue::Integer(*value),
                InputValue::Mechanisms(mechanisms) => {
                    let mut copy = reserved(mechanisms.len())?;
                    copy.extend_from_slice(mechanisms);
                    InputValue::Mechanisms(copy)
                }
            };
            values.push((*kind, value));
        }
        Ok(Self(values, None))
    }
    pub(crate) fn same_values(&self, other: &Self) -> bool {
        self.1.is_none() && other.1.is_none() && self.0 == other.0
    }
    pub(crate) fn retained_bytes(&self) -> Result<usize> {
        let mut bytes = self
            .0
            .capacity()
            .checked_mul(std::mem::size_of::<(CK_ATTRIBUTE_TYPE, InputValue)>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>()))
            .ok_or(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::TemplateAllocationSize,
                ),
            ))?;
        for (_, value) in &self.0 {
            let capacity = match value {
                InputValue::Bytes(value) => value.capacity(),
                InputValue::Mechanisms(value) => value
                    .capacity()
                    .checked_mul(std::mem::size_of::<CK_MECHANISM_TYPE>())
                    .ok_or(Error::Rejected(
                        crate::RejectionReason::AttributePreparation(
                            crate::AttributePreparationRejection::TemplateAllocationSize,
                        ),
                    ))?,
                _ => 0,
            };
            bytes = bytes.checked_add(capacity).ok_or(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::TemplateAllocationSize,
                ),
            ))?;
        }
        Ok(bytes)
    }

    pub fn new() -> Self {
        Self(Vec::new(), None)
    }
    fn push(&mut self, k: CK_ATTRIBUTE_TYPE, value: InputValue) {
        if self.1.is_some() {
            return;
        }
        if self.0.try_reserve(1).is_err() {
            self.1 = Some(crate::RejectionReason::AttributePreparation(
                crate::AttributePreparationRejection::TemplateFieldAllocation,
            ));
            return;
        }
        self.0.push((k, value));
    }
    pub fn bytes(&mut self, k: CK_ATTRIBUTE_TYPE, v: &[u8]) {
        if self.1.is_some() {
            return;
        }
        if bounds::ck_length(v.len()).is_err() {
            self.1 = Some(crate::RejectionReason::AttributePreparation(
                crate::AttributePreparationRejection::TemplateByteLengthConversion,
            ));
            return;
        }
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(v.len()).is_err() {
            self.1 = Some(crate::RejectionReason::AttributePreparation(
                crate::AttributePreparationRejection::TemplateByteAllocation,
            ));
            return;
        }
        bytes.extend_from_slice(v);
        self.push(k, InputValue::Bytes(bytes));
    }
    // Reference-check templates contain only the seven typed public identity fields.
    // Preserve CK_ULONG alignment rather than passing a byte Vec for scalars.
    pub(crate) fn try_identity_attribute(
        &mut self,
        field: crate::IdentityAttribute,
        bytes: &[u8],
    ) -> Result<()> {
        self.try_identity_parts(field, bytes.into())
    }
    // Borrowing segments changes storage preparation only. Keep the same
    // immediate allocation errors and aligned scalar representation.
    fn try_identity_parts(
        &mut self,
        field: crate::IdentityAttribute,
        bytes: ByteParts<'_>,
    ) -> Result<()> {
        if let Some(cause) = self.1 {
            return Err(Error::Rejected(cause));
        }
        let value = match field {
            crate::IdentityAttribute::Class | crate::IdentityAttribute::KeyType => {
                InputValue::Integer(CK_ULONG::from_ne_bytes(
                    bytes
                        .contiguous()
                        .ok_or(Error::Rejected(
                            crate::RejectionReason::AttributePreparation(
                                crate::AttributePreparationRejection::ReferenceTemplateIntegerWidth,
                            ),
                        ))?
                        .try_into()
                        .map_err(|_| {
                            Error::Rejected(crate::RejectionReason::AttributePreparation(
                                crate::AttributePreparationRejection::ReferenceTemplateIntegerWidth,
                            ))
                        })?,
                ))
            }
            crate::IdentityAttribute::Id
            | crate::IdentityAttribute::Label
            | crate::IdentityAttribute::UniqueId
            | crate::IdentityAttribute::Application
            | crate::IdentityAttribute::ObjectId => {
                let mut owned = Vec::new();
                owned.try_reserve_exact(bytes.len()).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::AttributePreparation(
                        crate::AttributePreparationRejection::ReferenceTemplateBytesAllocation,
                    ))
                })?;
                for segment in bytes.segments() {
                    owned.extend_from_slice(segment);
                }
                InputValue::Bytes(owned)
            }
        };
        self.0.try_reserve(1).map_err(|_| {
            Error::Rejected(crate::RejectionReason::AttributePreparation(
                crate::AttributePreparationRejection::ReferenceTemplateFieldsAllocation,
            ))
        })?;
        self.0.push((field.attribute().raw(), value));
        Ok(())
    }
    pub fn mechanisms(&mut self, k: CK_ATTRIBUTE_TYPE, v: &[CK_MECHANISM_TYPE]) -> Result<()> {
        if let Some(cause) = self.1 {
            return Err(Error::Rejected(cause));
        }
        let mut owned = Vec::new();
        owned.try_reserve_exact(v.len()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::AttributePreparation(
                crate::AttributePreparationRejection::MechanismTemplateAllocation,
            ))
        })?;
        owned.extend_from_slice(v);
        self.0.try_reserve(1).map_err(|_| {
            Error::Rejected(crate::RejectionReason::AttributePreparation(
                crate::AttributePreparationRejection::TemplateDescriptorAllocation,
            ))
        })?;
        self.0.push((k, InputValue::Mechanisms(owned)));
        Ok(())
    }
    pub fn boolean(&mut self, k: CK_ATTRIBUTE_TYPE, v: bool) {
        self.push(k, InputValue::Boolean(if v { CK_TRUE } else { CK_FALSE }));
    }
    pub fn integer(&mut self, k: CK_ATTRIBUTE_TYPE, v: CK_ULONG) {
        self.push(k, InputValue::Integer(v));
    }
    // Caller must keep this owner and its inner Vec allocations unchanged until
    // dispatch completes. No descriptor escapes the enclosing native operation.
    pub fn descriptors(&mut self) -> Result<Vec<CK_ATTRIBUTE>> {
        if let Some(cause) = self.1 {
            return Err(Error::Rejected(cause));
        }
        bounds::ck_length(self.0.len())?;
        let descriptors = reserved(self.0.len())?;
        self.descriptors_into(descriptors)
    }
    fn descriptors_into(
        &mut self,
        mut descriptors: Vec<CK_ATTRIBUTE>,
    ) -> Result<Vec<CK_ATTRIBUTE>> {
        if let Some(cause) = self.1 {
            return Err(Error::Rejected(cause));
        }
        bounds::ck_length(self.0.len())?;
        if descriptors.capacity() < self.0.len() || !descriptors.is_empty() {
            return Err(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::TemplateAllocationSize,
                ),
            ));
        }
        for (kind, value) in &mut self.0 {
            let (pointer, length) = match value {
                InputValue::Bytes(bytes) => (bytes.as_mut_ptr().cast(), bytes.len()),
                InputValue::Boolean(value) => (
                    (value as *mut CK_BBOOL).cast(),
                    std::mem::size_of::<CK_BBOOL>(),
                ),
                InputValue::Integer(value) => (
                    (value as *mut CK_ULONG).cast(),
                    std::mem::size_of::<CK_ULONG>(),
                ),
                InputValue::Mechanisms(values) => (
                    values.as_mut_ptr().cast(),
                    std::mem::size_of_val(values.as_slice()),
                ),
            };
            descriptors.push(CK_ATTRIBUTE {
                r#type: *kind,
                pValue: pointer,
                ulValueLen: bounds::ck_length(length)?,
            });
        }
        Ok(descriptors)
    }
}

// All readable types are bytes, CK_BBOOL or CK_ULONG. A byte Vec alone would
// promise only alignment 1, even if today's allocator happens to align it more.
pub(crate) struct AlignedOutput {
    words: Vec<CK_ULONG>,
    pub(crate) capacity: usize,
    // Present for a value prepared outside possession; older aggregate owners
    // retain this charge in their enclosing credit instead.
    credit: Option<crate::symmetric::memory::Credit>,
}
impl AlignedOutput {
    pub(crate) fn new(capacity: usize) -> Result<Self> {
        let width = std::mem::size_of::<CK_ULONG>();
        let words = capacity.checked_add(width - 1).ok_or(Error::Rejected(
            crate::RejectionReason::AttributePreparation(
                crate::AttributePreparationRejection::AttributeAlignmentSize,
            ),
        ))? / width;
        let mut storage = reserved(words)?;
        storage.resize(words, 0);
        Ok(Self {
            words: storage,
            capacity,
            credit: None,
        })
    }
    pub(crate) fn bind_prepaid(
        mut self,
        prepaid: &mut crate::symmetric::memory::Credit,
    ) -> Result<Self> {
        self.credit = Some(prepaid.split(self.allocated_bytes()?)?);
        Ok(self)
    }
    pub(crate) fn pointer(&mut self) -> CK_VOID_PTR {
        self.words.as_mut_ptr().cast()
    }
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        self.words
            .capacity()
            .checked_mul(std::mem::size_of::<CK_ULONG>())
            .ok_or(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::AttributeAlignmentSize,
                ),
            ))
    }

    /// Copy completed public output into storage prepared by the caller. This
    /// does not allocate and never reads a pointer returned by the module.
    pub(crate) fn copy_into(&self, output: &mut [u8]) -> Result<()> {
        output.copy_from_slice(self.completed_bytes(output.len())?);
        Ok(())
    }
    /// Borrow completed public output while its aligned allocation and credit
    /// remain owned. Callers establish native completion before borrowing.
    pub(crate) fn completed_bytes(&self, length: usize) -> Result<&[u8]> {
        if length > self.capacity {
            return Err(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::AttributeFinalLength,
                ),
            ));
        }
        // SAFETY: initialized word storage covers the checked logical length;
        // byte reads are valid for every CK_ULONG representation. The owning
        // frame has already established native completion before this copy.
        Ok(unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), length) })
    }
}
