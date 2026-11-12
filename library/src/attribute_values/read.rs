// SPDX-License-Identifier: Apache-2.0
//! At most two grouped calls; each descriptor and native referent stays owned.
use super::storage::erase_descriptors;
pub(crate) mod owner;
mod preparation;
mod runner;
use super::*;
use crate::native::frame::{NativeFrame, SessionFrame};
use crate::symmetric::memory::Credit;

// Only value slots own a buffer. Query descriptors always carry a NULL pointer.
enum Phase {
    Size,
    Value(AttributeBytes),
}
struct Slot {
    index: usize,
    attribute: AttributeType,
    phase: Phase,
}
struct ReadCall {
    slots: Vec<Slot>,
    descriptors: Vec<CK_ATTRIBUTE>,
    _slots_credit: Credit,
    _descriptors_credit: Credit,
}
// SAFETY: each pValue is NULL or refers to its slot's aligned buffer. Both
// vectors are complete before dispatch and cannot move/reallocate while armed.
unsafe impl Send for ReadCall {}
impl ReadCall {
    fn metadata_bytes(count: usize) -> Result<usize> {
        count
            .checked_mul(std::mem::size_of::<Slot>() + std::mem::size_of::<CK_ATTRIBUTE>())
            .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeCallMetadataAccounting,
            )))
    }
    fn push(&mut self, index: usize, attribute: AttributeType, mut phase: Phase) -> Result<()> {
        if self.slots.len() == self.slots.capacity()
            || self.descriptors.len() == self.descriptors.capacity()
        {
            return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeCallMetadataCapacity,
            )));
        }
        let (pointer, length) = match &mut phase {
            Phase::Size => (std::ptr::null_mut(), 0),
            Phase::Value(bytes) => (bytes.pointer(), bounds::ck_length(bytes.capacity())?),
        };
        self.descriptors.push(CK_ATTRIBUTE {
            r#type: attribute.native(),
            pValue: pointer,
            ulValueLen: length,
        });
        self.slots.push(Slot {
            index,
            attribute,
            phase,
        });
        Ok(())
    }
    fn valid_return(&mut self, code: CK_RV) -> bool {
        self.slots
            .iter_mut()
            .zip(&self.descriptors)
            .all(|(slot, descriptor)| {
                if descriptor.r#type != slot.attribute.native() {
                    return false;
                }
                match &mut slot.phase {
                    Phase::Size => descriptor.pValue.is_null(),
                    Phase::Value(bytes) => {
                        descriptor.pValue == bytes.pointer()
                            && (code == CKR_BUFFER_TOO_SMALL
                                || descriptor.ulValueLen == CK_UNAVAILABLE_INFORMATION
                                || descriptor.ulValueLen as u128 <= bytes.capacity() as u128)
                    }
                }
            })
    }
}

impl Drop for ReadCall {
    fn drop(&mut self) {
        erase_descriptors(&mut self.descriptors);
    }
}

// Attribute reads do not advance a parked cooperative operation. A step in
// progress holds the same session possession and serializes native dispatch.
// The caller validates the object's identity before creating the frame.
// Recheck mode and context without requiring the operation ticket to be absent.
fn record_observation(
    access: &crate::session::SessionAccess<'_>,
    session: &crate::Session,
) -> Result<()> {
    session.check_synchronous_dispatch()?;
    session.entry_common(access)?;
    access.native.record("C_GetAttributeValue")
}

fn dispatch(
    frame: &mut NativeFrame<SessionFrame<'_, ReadCall>>,
    session: &crate::Session,
    object: CK_OBJECT_HANDLE,
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
    record_observation(access, session)?;
    returned.arm();
    // SAFETY: the armed frame owns every descriptor and aligned value buffer,
    // the image/session references and the object's retained activity permit.
    let code = returned.observe(
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
    if crate::native_return::attribute_completion_known(code) {
        if !data.valid_return(code) {
            returned.quarantine(&access.native);
            // Publish the native scope before preserving both observations.
            // Its error must not hide the descriptor violation just detected.
            let _ = access.check_attribute_return(session.entry.handle, code);
            return Err(Error::AttributeReadInvalid {
                call: AttributeBatchCall {
                    code: code as u64,
                    attribute_count: data.descriptors.len(),
                },
                reason: crate::RejectionReason::AttributeValues(
                    crate::AttributeValuesRejection::AttributeDescriptorOrReturnedCapacityChanged,
                ),
            });
        }
        returned.terminated();
    } else {
        // Unknown completion never permits inspecting output or freeing referents.
        returned.recoverable();
        session.poison(access);
    }
    match code {
        CKR_OK | CKR_ATTRIBUTE_SENSITIVE | CKR_ATTRIBUTE_TYPE_INVALID | CKR_BUFFER_TOO_SMALL => {}
        _ => access.check_attribute_return(session.entry.handle, code)?,
    }
    Ok(code)
}

// A multi-entry return code cannot identify which unavailable entry caused it.
// A bounded non-sentinel length remains usable despite another entry's refusal.
fn unavailable(code: CK_RV, length: CK_ULONG, count: usize) -> Option<FlatAttributeValue> {
    let cause = match (count, code) {
        (1, CKR_ATTRIBUTE_SENSITIVE) => AttributeUnavailableCause::Sensitive,
        (1, CKR_ATTRIBUTE_TYPE_INVALID) => AttributeUnavailableCause::Unsupported,
        _ if length == CK_UNAVAILABLE_INFORMATION => AttributeUnavailableCause::Unspecified,
        _ => return None,
    };
    Some(FlatAttributeValue::Unavailable(cause))
}
fn reported_size(length: CK_ULONG) -> Result<Option<usize>> {
    if length == CK_UNAVAILABLE_INFORMATION {
        return Ok(None);
    }
    usize::try_from(length).map(Some).map_err(|_| {
        Error::Rejected(crate::RejectionReason::AttributeValues(
            crate::AttributeValuesRejection::AttributeNativeSizeWidth,
        ))
    })
}

pub(super) fn observe(
    session: &crate::Session,
    object: &crate::NativeObjectRef,
    attribute: AttributeType,
    plan: FlatAttributeReadPlan,
) -> Result<FlatAttributeObservation> {
    let maximum = match plan {
        FlatAttributeReadPlan::LengthOnly => 0,
        FlatAttributeReadPlan::Buffer { capacity } => capacity,
        FlatAttributeReadPlan::Value { maximum_bytes } => maximum_bytes,
    };
    observe_batch(
        session,
        object,
        &[FlatAttributeRequest { attribute, plan }],
        maximum,
    )?
    .into_iter()
    .next()
    .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
        crate::AttributeValuesRejection::SingleAttributeResultMissing,
    )))
}

fn validate_requests(
    session: &crate::Session,
    requests: &[FlatAttributeRequest],
    maximum_value_bytes: usize,
) -> Result<usize> {
    // Reject nested layouts and over-budget direct requests before any native
    // effect. Duplicates are intentional caller requests with independent owners.
    bounds::ck_length(requests.len())?;
    let mut allocated = 0usize;
    for request in requests {
        request
            .attribute
            .check_scope(session.inner.attribute_extension_scope.get().copied())?;
        if request.attribute.layout() == AttributeLayout::Template {
            return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::NestedAttributeRequiresARecursiveReader,
            )));
        }
        if let FlatAttributeReadPlan::Buffer { capacity } = request.plan {
            bounds::ck_length(capacity)?;
            allocated = allocated
                .checked_add(capacity)
                .filter(|total| *total <= maximum_value_bytes)
                .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                    crate::AttributeValuesRejection::DirectAttributeBatchAllocationCeiling,
                )))?;
        }
    }
    Ok(allocated)
}

pub(super) fn observe_batch(
    session: &crate::Session,
    object: &crate::NativeObjectRef,
    requests: &[FlatAttributeRequest],
    maximum_value_bytes: usize,
) -> Result<FlatAttributeBatch> {
    runner::observe_batch(session, object, requests, maximum_value_bytes)
}

enum QueryDecision {
    Result(FlatAttributeValue),
    Read(usize),
}
fn query_decision(
    request: &FlatAttributeRequest,
    length: CK_ULONG,
    code: CK_RV,
    count: usize,
    maximum: usize,
    allocated: usize,
) -> Result<QueryDecision> {
    if count == 1 && code == CKR_BUFFER_TOO_SMALL {
        return Ok(QueryDecision::Result(FlatAttributeValue::BufferTooSmall {
            supplied: 0,
            required: reported_size(length)?,
        }));
    }
    if let Some(value) = unavailable(code, length, count) {
        return Ok(QueryDecision::Result(value));
    }
    let required =
        reported_size(length)?.ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
            crate::AttributeValuesRejection::AttributeSizeUnavailable,
        )))?;
    let value = match request.plan {
        FlatAttributeReadPlan::LengthOnly => FlatAttributeValue::SizeKnown { required },
        FlatAttributeReadPlan::Value { maximum_bytes } if required > maximum_bytes => {
            FlatAttributeValue::AllocationLimit {
                required,
                maximum_bytes,
            }
        }
        FlatAttributeReadPlan::Value { .. } if required > maximum - allocated => {
            FlatAttributeValue::AggregateAllocationLimit {
                required,
                remaining_bytes: maximum - allocated,
            }
        }
        FlatAttributeReadPlan::Value { .. } => {
            return Ok(QueryDecision::Read(required));
        }

        FlatAttributeReadPlan::Buffer { .. } => {
            return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::DirectAttributeUnexpectedlyQueried,
            )));
        }
    };
    Ok(QueryDecision::Result(value))
}

fn value_result(
    mut bytes: AttributeBytes,
    length: CK_ULONG,
    code: CK_RV,
    count: usize,
) -> Result<FlatAttributeValue> {
    let supplied = bytes.capacity();
    if code == CKR_BUFFER_TOO_SMALL
        && (count == 1
            || (length != CK_UNAVAILABLE_INFORMATION && length as u128 > supplied as u128))
    {
        return Ok(FlatAttributeValue::BufferTooSmall {
            supplied,
            required: reported_size(length)?,
        });
    }
    if let Some(value) = unavailable(code, length, count) {
        return Ok(value);
    }
    bytes.set_length(bounds::final_length(length, supplied)?)?;
    Ok(FlatAttributeValue::Available(bytes))
}

fn after_observation(error: Error, calls: AttributeBatchCalls) -> Error {
    use crate::AttributeAdmissionFailure as Failure;
    let cause = match error {
        Error::Busy(reason) => Failure::Busy(reason),
        Error::ResourceLimitExceeded {
            resource,
            requested,
            limit,
        } => Failure::ResourceLimitExceeded {
            resource,
            requested,
            limit,
        },
        Error::AdmissionCancelled => Failure::Cancelled,
        Error::AdmissionDeadline => Failure::Deadline,
        other => return other,
    };
    Error::AttributeReadInterrupted { calls, cause }
}
