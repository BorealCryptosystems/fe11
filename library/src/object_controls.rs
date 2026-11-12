// SPDX-License-Identifier: Apache-2.0
//! Explicit native object observations, without application predicates.

use crate::{attributes::ObservedAttributes, Error, Observation, Result};
use fe11_sys::*;
use std::sync::Arc;

/// Native boolean attributes represented by an object observation report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectBooleanAttribute {
    /// CKA_PRIVATE; independent of the cryptographic object class.
    Private,
    /// CKA_TOKEN; independent of the known creation session.
    Token,
    /// CKA_MODIFIABLE.
    Modifiable,
    /// CKA_COPYABLE.
    Copyable,
    /// CKA_DESTROYABLE.
    Destroyable,
    /// CKA_ENCRYPT; observed only when explicitly requested.
    Encrypt,
    /// CKA_DECRYPT; observed only when explicitly requested.
    Decrypt,
    /// CKA_SIGN; observed only when explicitly requested.
    Sign,
    /// CKA_VERIFY; observed only when explicitly requested.
    Verify,
    /// CKA_SIGN_RECOVER; observed only when explicitly requested.
    SignRecover,
    /// CKA_VERIFY_RECOVER; observed only when explicitly requested.
    VerifyRecover,
    /// CKA_WRAP; observed only when explicitly requested.
    Wrap,
    /// CKA_UNWRAP; observed only when explicitly requested.
    Unwrap,
    /// CKA_DERIVE; observed only when explicitly requested.
    Derive,
    /// CKA_SENSITIVE; observed only when explicitly requested.
    Sensitive,
    /// CKA_EXTRACTABLE; observed only when explicitly requested.
    Extractable,
    /// CKA_LOCAL; observed only when explicitly requested.
    Local,
    /// CKA_ALWAYS_SENSITIVE; observed only when explicitly requested.
    AlwaysSensitive,
    /// CKA_NEVER_EXTRACTABLE; observed only when explicitly requested.
    NeverExtractable,
    /// CKA_ALWAYS_AUTHENTICATE; observed only when explicitly requested.
    AlwaysAuthenticate,
    /// CKA_TRUSTED; observed only when explicitly requested.
    Trusted,
    /// CKA_ENCAPSULATE; observed only when explicitly requested.
    Encapsulate,
    /// CKA_DECAPSULATE; observed only when explicitly requested.
    Decapsulate,
    /// CKA_WRAP_WITH_TRUSTED.
    WrapWithTrusted,
}
impl ObjectBooleanAttribute {
    const ALL: [Self; 24] = [
        Self::Private,
        Self::Token,
        Self::Modifiable,
        Self::Copyable,
        Self::Destroyable,
        Self::Encrypt,
        Self::Decrypt,
        Self::Sign,
        Self::Verify,
        Self::SignRecover,
        Self::VerifyRecover,
        Self::Wrap,
        Self::Unwrap,
        Self::Derive,
        Self::Sensitive,
        Self::Extractable,
        Self::Local,
        Self::AlwaysSensitive,
        Self::NeverExtractable,
        Self::AlwaysAuthenticate,
        Self::Trusted,
        Self::Encapsulate,
        Self::Decapsulate,
        Self::WrapWithTrusted,
    ];
    fn index(self) -> usize {
        match self {
            Self::Private => 0,
            Self::Token => 1,
            Self::Modifiable => 2,
            Self::Copyable => 3,
            Self::Destroyable => 4,
            Self::Encrypt => 5,
            Self::Decrypt => 6,
            Self::Sign => 7,
            Self::Verify => 8,
            Self::SignRecover => 9,
            Self::VerifyRecover => 10,
            Self::Wrap => 11,
            Self::Unwrap => 12,
            Self::Derive => 13,
            Self::Sensitive => 14,
            Self::Extractable => 15,
            Self::Local => 16,
            Self::AlwaysSensitive => 17,
            Self::NeverExtractable => 18,
            Self::AlwaysAuthenticate => 19,
            Self::Trusted => 20,
            Self::Encapsulate => 21,
            Self::Decapsulate => 22,
            Self::WrapWithTrusted => 23,
        }
    }
    pub(crate) fn attribute(self) -> CK_ATTRIBUTE_TYPE {
        match self {
            Self::Private => CKA_PRIVATE,
            Self::Token => CKA_TOKEN,
            Self::Modifiable => CKA_MODIFIABLE,
            Self::Copyable => CKA_COPYABLE,
            Self::Destroyable => CKA_DESTROYABLE,
            Self::Encrypt => CKA_ENCRYPT,
            Self::Decrypt => CKA_DECRYPT,
            Self::Sign => CKA_SIGN,
            Self::Verify => CKA_VERIFY,
            Self::SignRecover => CKA_SIGN_RECOVER,
            Self::VerifyRecover => CKA_VERIFY_RECOVER,
            Self::Wrap => CKA_WRAP,
            Self::Unwrap => CKA_UNWRAP,
            Self::Derive => CKA_DERIVE,
            Self::Sensitive => CKA_SENSITIVE,
            Self::Extractable => CKA_EXTRACTABLE,
            Self::Local => CKA_LOCAL,
            Self::AlwaysSensitive => CKA_ALWAYS_SENSITIVE,
            Self::NeverExtractable => CKA_NEVER_EXTRACTABLE,
            Self::AlwaysAuthenticate => CKA_ALWAYS_AUTHENTICATE,
            Self::Trusted => CKA_TRUSTED,
            Self::Encapsulate => CKA_ENCAPSULATE,
            Self::Decapsulate => CKA_DECAPSULATE,
            Self::WrapWithTrusted => CKA_WRAP_WITH_TRUSTED,
        }
    }
}

/// Explicit native reads and their aggregate resource budget.
/// Unrequested or unavailable values remain unknown. Unknown visibility keeps
/// the reference tied to its original authentication context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectObservationPlan {
    /// Read CKA_PRIVATE.
    pub private: bool,
    /// Read CKA_TOKEN.
    pub token: bool,
    /// Read CKA_MODIFIABLE.
    pub modifiable: bool,
    /// Read CKA_COPYABLE.
    pub copyable: bool,
    /// Read CKA_DESTROYABLE.
    pub destroyable: bool,
    /// Read CKA_ENCRYPT; does not imply a comparison or native creation request.
    pub encrypt: bool,
    /// Read CKA_DECRYPT; does not imply a comparison or native creation request.
    pub decrypt: bool,
    /// Read CKA_SIGN; does not imply a comparison or native creation request.
    pub sign: bool,
    /// Read CKA_VERIFY; does not imply a comparison or native creation request.
    pub verify: bool,
    /// Read CKA_SIGN_RECOVER; does not imply a comparison or native creation request.
    pub sign_recover: bool,
    /// Read CKA_VERIFY_RECOVER; does not imply a comparison or native creation request.
    pub verify_recover: bool,
    /// Read CKA_WRAP; does not imply a comparison or native creation request.
    pub wrap: bool,
    /// Read CKA_UNWRAP; does not imply a comparison or native creation request.
    pub unwrap: bool,
    /// Read CKA_DERIVE; does not imply a comparison or native creation request.
    pub derive: bool,
    /// Read CKA_SENSITIVE; does not imply a comparison or native creation request.
    pub sensitive: bool,
    /// Read CKA_EXTRACTABLE; does not imply a comparison or native creation request.
    pub extractable: bool,
    /// Read CKA_LOCAL; does not imply a comparison or native creation request.
    pub local: bool,
    /// Read CKA_ALWAYS_SENSITIVE; does not imply a comparison or native creation request.
    pub always_sensitive: bool,
    /// Read CKA_NEVER_EXTRACTABLE; does not imply a comparison or native creation request.
    pub never_extractable: bool,
    /// Read CKA_ALWAYS_AUTHENTICATE; does not imply a comparison or native creation request.
    pub always_authenticate: bool,
    /// Read CKA_TRUSTED; does not imply a comparison or native creation request.
    pub trusted: bool,
    /// Read CKA_ENCAPSULATE; does not imply a comparison or native creation request.
    pub encapsulate: bool,
    /// Read CKA_DECAPSULATE; does not imply a comparison or native creation request.
    pub decapsulate: bool,
    /// Read CKA_WRAP_WITH_TRUSTED.
    pub wrap_with_trusted: bool,

    /// Aggregate native value byte budget for the selected properties.
    pub maximum_bytes: usize,
}
impl ObjectObservationPlan {
    fn requested(self, field: ObjectBooleanAttribute) -> bool {
        match field {
            ObjectBooleanAttribute::Private => self.private,
            ObjectBooleanAttribute::Token => self.token,
            ObjectBooleanAttribute::Modifiable => self.modifiable,
            ObjectBooleanAttribute::Copyable => self.copyable,
            ObjectBooleanAttribute::Destroyable => self.destroyable,
            ObjectBooleanAttribute::Encrypt => self.encrypt,
            ObjectBooleanAttribute::Decrypt => self.decrypt,
            ObjectBooleanAttribute::Sign => self.sign,
            ObjectBooleanAttribute::Verify => self.verify,
            ObjectBooleanAttribute::SignRecover => self.sign_recover,
            ObjectBooleanAttribute::VerifyRecover => self.verify_recover,
            ObjectBooleanAttribute::Wrap => self.wrap,
            ObjectBooleanAttribute::Unwrap => self.unwrap,
            ObjectBooleanAttribute::Derive => self.derive,
            ObjectBooleanAttribute::Sensitive => self.sensitive,
            ObjectBooleanAttribute::Extractable => self.extractable,
            ObjectBooleanAttribute::Local => self.local,
            ObjectBooleanAttribute::AlwaysSensitive => self.always_sensitive,
            ObjectBooleanAttribute::NeverExtractable => self.never_extractable,
            ObjectBooleanAttribute::AlwaysAuthenticate => self.always_authenticate,
            ObjectBooleanAttribute::Trusted => self.trusted,
            ObjectBooleanAttribute::Encapsulate => self.encapsulate,
            ObjectBooleanAttribute::Decapsulate => self.decapsulate,
            ObjectBooleanAttribute::WrapWithTrusted => self.wrap_with_trusted,
        }
    }
    pub(crate) fn field_iter(self) -> impl Iterator<Item = CK_ATTRIBUTE_TYPE> {
        ObjectBooleanAttribute::ALL
            .into_iter()
            .filter(move |field| self.requested(*field))
            .map(|field| field.attribute())
    }
}

/// Observation and resource choices for resolving an object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectAdmission {
    /// Public attributes to read, sharing observation.maximum_bytes.
    /// No expected values or comparisons are retained. Each attribute may
    /// occur once in this list; a boolean observation of the same attribute
    /// shares that native read without losing either view.
    pub public_attributes: Arc<Vec<crate::Attribute>>,
    /// Resource plan for admission/discovery paths using this selection.
    /// set_label/copy_object instead use their required ObjectMutationPlan's
    /// source.search/destination.search; this field is inactive in those calls.
    /// DataSpec/CertificateSpec creation uses its own destination plan as well.
    /// This selection is not evidence that a search was performed.
    pub search: crate::SearchPlan,
    /// Explicit result position in initial discovery, with the observed count.
    /// Creation and administrative mutations do not use this selection.
    pub selection: crate::ObjectSearchSelection,
    /// Destination observations for key generation, import and derivation.
    /// Discovery and administrative mutations do not use this selection.
    pub destination: crate::DestinationPlan,
    /// Plan for the additional administrative metadata read, when generic
    /// managed-reference publication requires one. Typed advanced admission
    /// already owns its validation observations and does not add this read.
    /// maximum_bytes also bounds required typed-key attribute snapshots.
    /// clarification applies to the administrative metadata read only.
    pub metadata: crate::AttributeReadPlan,
    /// Selected reads and their aggregate byte budget.
    pub observation: ObjectObservationPlan,
}

/// Native observations at the time of the read, not permissions for later calls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectObservationReport {
    selection: ObjectAdmission,
    observations: [Observation<bool>; 24],
    public_values: crate::attributes::owned::resident::AttributeSnapshot,
}
impl ObjectObservationReport {
    /// Public bytes actually requested. Missing and empty values remain distinct.
    pub fn attribute_observation(&self, attribute: crate::Attribute) -> &crate::AttributeValue {
        self.public_values.get(attribute.raw())
    }
    /// Exact read choices.
    pub fn selection(&self) -> &ObjectAdmission {
        &self.selection
    }
    /// Actual boolean value, or its explicit unavailable/unrequested state.
    pub fn observation(&self, field: ObjectBooleanAttribute) -> Observation<bool> {
        self.observations[field.index()]
    }
}
impl ObjectAdmission {
    pub(crate) fn public_attribute_retained_bytes(&self) -> Result<usize> {
        self.public_attributes
            .capacity()
            .checked_mul(std::mem::size_of::<crate::Attribute>())
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectObservation(
                crate::ObjectObservationRejection::PublicAttributeSelectionSizeOverflow,
            )))
    }
    pub(crate) fn validate_public_selection(&self) -> Result<()> {
        for (index, field) in self.public_attributes.iter().enumerate() {
            if self.public_attributes[..index].contains(field) {
                return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::DuplicateAttribute,
                )));
            }
        }
        Ok(())
    }
    pub(crate) fn observation_field_iter(&self) -> impl Iterator<Item = CK_ATTRIBUTE_TYPE> + '_ {
        self.observation
            .field_iter()
            .chain(self.public_attributes.iter().filter_map(|field| {
                (!self
                    .observation
                    .field_iter()
                    .any(|native| native == field.raw()))
                .then_some(field.raw())
            }))
    }
    pub(crate) fn observe_owned(
        &self,
        values: ObservedAttributes,
    ) -> Result<ObjectObservationReport> {
        let observations = ObjectBooleanAttribute::ALL.map(|field| {
            if self.observation.requested(field) {
                values.boolean(field.attribute())
            } else {
                Observation::NotRequested
            }
        });
        // Preserve native failure separately from unknown/unsupported attributes.
        for observation in &observations {
            if let Observation::NativeError {
                function,
                code,
                may_have_effect,
            } = observation
            {
                return Err(Error::Native {
                    function: *function,
                    code: *code,
                    may_have_effect: *may_have_effect,
                });
            }
        }
        Ok(ObjectObservationReport {
            selection: self.clone(),
            observations,
            public_values: values.into_selected_public(&self.public_attributes)?,
        })
    }
}
