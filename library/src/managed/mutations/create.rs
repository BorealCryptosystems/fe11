// SPDX-License-Identifier: Apache-2.0
//! Generic standard object creation through the shared native creation owner.
use crate::{
    AttributeInput, AttributeInputValue, AttributeTemplateLimits, ContentObservation,
    DestinationPlan, Error, ManagedClass, ManagedObjectRef, ObjectAdmission, Result, Session,
    StandardAttribute,
};
pub(crate) use resident::{
    create_public, create_public_prepared, create_public_with_publication,
    prepare_private_creation, prepare_rsa_creation, prepare_signing_creation,
};

// CKA_CLASS is mandatory for C_CreateObject (PKCS#11 Tables 13/14). It is
// structural ownership information, not a default or application policy.
fn object_class(input: &[AttributeInput<'_>]) -> Result<ManagedClass> {
    let mut selected = None;
    for attribute in input
        .iter()
        .filter(|attribute| attribute.attribute == StandardAttribute::CLASS)
    {
        let AttributeInputValue::Unsigned(value) = &attribute.value else {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::CreationClassAbiRepresentation,
            )));
        };
        let class = ManagedClass::from_identifier(*value).ok_or(Error::Unsupported(
            crate::UnsupportedReason::ObjectCreation(
                crate::ObjectCreationUnsupported::CreationClassRequiresAnExtensionContract,
            ),
        ))?;
        if selected.is_some_and(|previous| previous != class) {
            return Err(Error::Rejected(crate::RejectionReason::ObjectCreation(
                crate::ObjectCreationRejection::ConflictingCreationClasses,
            )));
        }
        selected = Some(class);
    }
    selected.ok_or(Error::Rejected(crate::RejectionReason::ObjectCreation(
        crate::ObjectCreationRejection::CreationClassIsRequired,
    )))
}

impl Session {
    /// Create a typed standard object from the exact caller template.
    /// CKA_CLASS is decoded to select this typed representation. The generic
    /// create_native_object route does not require this descriptive conversion.
    /// Repeated attributes remain in their original order for the module to decide.
    /// No ID, visibility, persistence, key policy or PKI profile is added.
    ///
    /// Input storage owns and erases private components and nested templates.
    /// The caller retains responsibility for its original copies. Native read-only
    /// session restrictions and attribute refusals remain native errors.
    ///
    /// After native success, publish the generic reference before optional reads.
    /// CreatedObjects separates that ownership from the observation result; an
    /// observation failure neither destroys the object nor authorizes creation replay.
    /// Resource waits release coordination guards while retaining completed results.
    pub fn create_object<'a>(
        &self,
        input: &'a [AttributeInput<'a>],
        limits: AttributeTemplateLimits,
        admission: ObjectAdmission,
        content: ContentObservation,
        destination_plan: DestinationPlan,
    ) -> Result<crate::CreatedObjects<ManagedObjectRef>> {
        let mut diagnostics = None;
        resident::create(
            self,
            input,
            limits,
            admission,
            content,
            destination_plan,
            &mut diagnostics,
        )
    }
}

impl crate::AdvancedSession {
    /// Synchronous standard object creation, with the same contract as Session.
    /// This method neither enables PKCS#11 native asynchronous mode nor adds a worker thread.
    pub fn create_object<'a>(
        &self,
        input: &'a [AttributeInput<'a>],
        limits: AttributeTemplateLimits,
        admission: ObjectAdmission,
        content: ContentObservation,
        destination: DestinationPlan,
    ) -> Result<crate::CreatedObjects<ManagedObjectRef>> {
        let mut diagnostics = None;
        resident::create(
            &self.session,
            input,
            limits,
            admission,
            content,
            destination,
            &mut diagnostics,
        )
    }
}

pub(super) mod resident;
pub(crate) use resident::CreationOwner;

pub(crate) use resident::restoration;

pub(crate) use resident::kem as kem_creation;
