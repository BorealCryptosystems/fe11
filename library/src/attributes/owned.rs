// SPDX-License-Identifier: Apache-2.0
//! Owned storage for the two C_GetAttributeValue phases.
//!
//! The caller retains object activity in SessionAccess before entry. A completed
//! size query permits binding the value buffers; an uncertain return permits no
//! output inspection and transfers the entire owner to recovery or quarantine.
//! Attribute absence and the caller's clarification policy remain separate from
//! native completion: a completed call can still report unavailable values.
use super::*;
use crate::native::frame::{NativeFrame, SessionFrame};
use crate::session::SessionAccess;
use crate::symmetric::memory::Credit;

pub(crate) mod resident;

#[derive(Clone, Copy)]
enum Phase {
    Size,
    Values,
}

// Individual reads can identify Sensitive/Unsupported precisely. A grouped
// return describes the template as a whole, so it cannot assign that cause to
// any particular missing attribute. Encoding the request preserves that distinction.

fn individual_capacity_return(rv: CK_RV) -> Result<()> {
    if rv == CKR_BUFFER_TOO_SMALL {
        crate::error::check(rv, "C_GetAttributeValue", false)?;
    }
    Ok(())
}
fn individual_refusal(rv: CK_RV) -> Option<PreciseAttributeValue> {
    match rv {
        CKR_ATTRIBUTE_SENSITIVE => Some(PreciseAttributeValue::Sensitive),
        CKR_ATTRIBUTE_TYPE_INVALID => Some(PreciseAttributeValue::Unsupported),
        _ => None,
    }
}

struct ReadCall {
    kinds: Vec<CK_ATTRIBUTE_TYPE>,
    descriptors: Vec<CK_ATTRIBUTE>,
    indices: Vec<usize>,
    buffers: Vec<Option<AlignedOutput>>,
    diagnostic: Option<crate::error::CompletionStorage>,
    _credit: Credit,
}
// SAFETY: native pointers address only owned aligned buffers. Descriptor/index
// allocations are never resized during an armed call; no caller slice escapes.
unsafe impl Send for ReadCall {}

impl ReadCall {
    fn descriptors_valid(&mut self, phase: Phase, rv: CK_RV) -> bool {
        for (descriptor, index) in self.descriptors.iter().zip(&self.indices) {
            if descriptor.r#type != self.kinds[*index] {
                return false;
            }
            match phase {
                Phase::Size if !descriptor.pValue.is_null() => return false,
                Phase::Size => {}
                Phase::Values => {
                    let buffer = self.buffers[*index].as_mut().expect("selected owned value");
                    if descriptor.pValue != buffer.pointer() {
                        return false;
                    }
                    // BUFFER_TOO_SMALL may describe a larger required buffer.
                    // A partial return can still contain bounded values for other
                    // entries; materialization checks each length independently.
                    if matches!(
                        rv,
                        CKR_OK | CKR_ATTRIBUTE_SENSITIVE | CKR_ATTRIBUTE_TYPE_INVALID
                    ) && descriptor.ulValueLen != CK_UNAVAILABLE_INFORMATION
                        && descriptor.ulValueLen as u128 > buffer.capacity as u128
                    {
                        return false;
                    }
                }
            }
        }
        true
    }
}

fn dispatch(
    frame: &mut NativeFrame<SessionFrame<'_, ReadCall>>,
    session: &crate::Session,
    object: CK_OBJECT_HANDLE,
    phase: Phase,
) -> Result<CK_RV> {
    let (returned, body) = frame.session_parts();
    let access = &body.access;
    let get = access
        .native
        .table
        .C_GetAttributeValue
        .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
            crate::AttributeValuesRejection::CGetAttributeValueUnavailable,
        )))?;
    let data = &mut *body.data;
    let count = bounds::ck_length(data.descriptors.len())?;
    record(access, session)?;
    returned.arm();
    // SAFETY: stable, aligned descriptors and every addressed value are owned
    // by this frame, as are the session and object activity protections.
    let rv = returned.observe(
        unsafe {
            get(
                session.entry.handle,
                object,
                data.descriptors.as_mut_ptr(),
                count,
            )
        },
        &access.native,
    );
    if crate::native_return::attribute_completion_known(rv) {
        if !data.descriptors_valid(phase, rv) {
            returned.quarantine(&access.native);
            // Publish the native failure scope before combining both causes.
            let _ = access.check_attribute_return(session.entry.handle, rv);
            return Err(data.diagnostic.take().expect("attribute diagnostic prepared before possession")
                .bind("C_GetAttributeValue").boundary_failure(rv, Error::Rejected(
                crate::RejectionReason::AttributePreparation(crate::AttributePreparationRejection::AttributeNativeDescriptorOrCapacityChanged),
            )));
        }
        returned.terminated();
    } else {
        // Do not inspect an output or descriptor after an uncertain return.
        returned.recoverable();
        session.poison(access);
    }
    partial_status(access, session.entry.handle, rv)?;
    Ok(rv)
}

/// The ABI fixes CKA_CLASS to one CK_OBJECT_CLASS. Keeping its descriptor and
/// scalar inline avoids a dynamic read graph for the post-mutation observation.
pub(crate) struct ClassReadStorage {
    descriptor: CK_ATTRIBUTE,
    value: CK_OBJECT_CLASS,
    protection: Option<crate::session::observation_protection::ObservationProtection>,
    _credit: Credit,
}
// SAFETY: the descriptor is NULL until the stable CallData allocation exists.
// Once bound it points only to that allocation's inline scalar; an armed frame
// retains the complete allocation and the common native-return protections.
unsafe impl Send for ClassReadStorage {}

impl ClassReadStorage {
    pub(crate) fn with_protection(
        mut self,
        protection: crate::session::observation_protection::ObservationProtection,
    ) -> Self {
        self.protection = Some(protection);
        self
    }

    pub(crate) fn allocation_bytes(maximum_bytes: usize) -> Result<usize> {
        if maximum_bytes < std::mem::size_of::<CK_OBJECT_CLASS>() {
            return Err(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::MutationClassObservationBudget,
                ),
            ));
        }
        Self::storage_bytes()
    }

    // CallData owns the scalar storage; its enclosing SessionFrame is a
    // separate allocation. Retain both credits with the native-addressed data
    // so an uncertain return cannot release either reservation prematurely.
    fn storage_bytes() -> Result<usize> {
        std::mem::size_of::<Self>()
            .checked_add(SessionFrame::<'_, Self>::allocation_bytes())
            .ok_or(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::ClassObservationStorageSize,
                ),
            ))
    }

    pub(crate) fn prepaid(prepaid: &mut Credit) -> Result<Self> {
        Ok(Self {
            descriptor: CK_ATTRIBUTE {
                r#type: CKA_CLASS,
                pValue: std::ptr::null_mut(),
                ulValueLen: bounds::ck_length(std::mem::size_of::<CK_OBJECT_CLASS>())?,
            },
            value: 0,
            protection: None,
            _credit: prepaid.split(Self::storage_bytes()?)?,
        })
    }
}

/// Fixed-width observation bound to access only after the complete mutation
/// graph has acquired its credit and possession. Checking needs no new buffer.
pub(crate) struct PreparedClassRead<'a> {
    frame: NativeFrame<SessionFrame<'a, ClassReadStorage>>,
}

impl<'a> PreparedClassRead<'a> {
    pub(crate) fn from_storage(
        access: &SessionAccess<'a>,
        session: &crate::Session,
        storage: ClassReadStorage,
    ) -> Result<Self> {
        if !access.owns_session(session) {
            return Err(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::AttributeObservationAccessOwner,
                ),
            ));
        }
        if access.native.table.C_GetAttributeValue.is_none() {
            return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::CGetAttributeValueUnavailable,
            )));
        }
        Ok(Self {
            frame: NativeFrame::session(access.clone(), storage)?,
        })
    }

    pub(crate) fn check(
        mut self,
        session: &crate::Session,
        object: CK_OBJECT_HANDLE,
        expected: CK_OBJECT_CLASS,
    ) -> Result<()> {
        let (returned, body) = self.frame.session_parts();
        let access = &body.access;
        let get = access
            .native
            .table
            .C_GetAttributeValue
            .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::CGetAttributeValueUnavailable,
            )))?;
        let data = &mut *body.data;
        let pointer = std::ptr::addr_of_mut!(data.value).cast();
        data.descriptor.pValue = pointer;
        record(access, session)?;
        returned.arm();
        // SAFETY: the descriptor and its aligned scalar are in the same stable
        // owned allocation. Unknown completion transfers both to recovery.
        let rv = returned.observe(
            unsafe { get(session.entry.handle, object, &mut data.descriptor, 1) },
            &access.native,
        );
        if crate::native_return::attribute_completion_known(rv) {
            let descriptor = &data.descriptor;
            let bounded = !matches!(
                rv,
                CKR_OK | CKR_ATTRIBUTE_SENSITIVE | CKR_ATTRIBUTE_TYPE_INVALID
            ) || descriptor.ulValueLen == CK_UNAVAILABLE_INFORMATION
                || descriptor.ulValueLen as u128 <= std::mem::size_of::<CK_OBJECT_CLASS>() as u128;
            if descriptor.r#type != CKA_CLASS || descriptor.pValue != pointer || !bounded {
                returned.quarantine(&access.native);
                let _ = access.check_attribute_return(session.entry.handle, rv);
                return Err(Error::AttributeReadInvalid {
                    call: crate::AttributeBatchCall {
                        code: rv as u64,
                        attribute_count: 1,
                    },
                    reason: crate::RejectionReason::AttributePreparation(
                        crate::AttributePreparationRejection::AttributeNativeDescriptorOrCapacityChanged,
                    ),
                });
            }
            returned.terminated();
        } else {
            // Never inspect a descriptor or value after uncertain completion.
            returned.recoverable();
            session.poison(access);
        }
        partial_status(access, session.entry.handle, rv)?;
        crate::error::check(rv, "C_GetAttributeValue", false)?;
        let data = self.frame.into_inner()?.data.into_inner();
        if data.descriptor.ulValueLen != std::mem::size_of::<CK_OBJECT_CLASS>() as CK_ULONG {
            return Err(Error::AttributeReadInvalid {
                call: crate::AttributeBatchCall {
                    code: rv as u64,
                    attribute_count: 1,
                },
                reason: crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::MutationClassObservationUnavailableOrMalformed,
                ),
            });
        }
        if data.value != expected {
            return Err(Error::AttributeReadInvalid {
                call: crate::AttributeBatchCall {
                    code: rv as u64,
                    attribute_count: 1,
                },
                reason: crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::MutationClassIdentityChanged,
                ),
            });
        }
        Ok(())
    }
}

// A global partial refusal describes no individual cause. A non-sentinel,
// bounded length identifies a usable value only when another descriptor could
// explain that refusal. Never use a reported required size as a slice length.
fn available_length(
    length: CK_ULONG,
    capacity: usize,
    code: CK_RV,
    count: usize,
) -> Result<Option<usize>> {
    if length == CK_UNAVAILABLE_INFORMATION
        || (count == 1 && code != CKR_OK)
        || (code == CKR_BUFFER_TOO_SMALL && length as u128 > capacity as u128)
    {
        return Ok(None);
    }
    bounds::final_length(length, capacity).map(Some)
}
