// SPDX-License-Identifier: Apache-2.0
//! Validate reachable parents before inspecting child descriptors or values.

use super::{
    prepare::{ReadCall, Storage},
    *,
};
use crate::native::frame::{NativeFrame, SessionFrame};
use std::mem::size_of;

fn partial(code: CK_RV) -> bool {
    matches!(
        code,
        CKR_OK | CKR_ATTRIBUTE_SENSITIVE | CKR_ATTRIBUTE_TYPE_INVALID | CKR_BUFFER_TOO_SMALL
    )
}
fn length(value: CK_ULONG) -> Option<usize> {
    // Supported targets have usize at least as wide as CK_ULONG. The sentinel
    // must be recognized before widening or interpreting a template length.
    (value != CK_UNAVAILABLE_INFORMATION).then_some(value as usize)
}
fn is_template(identifier: CK_ATTRIBUTE_TYPE) -> bool {
    StandardAttribute::from_identifier(identifier as u64)
        .is_some_and(|a| a.layout() == AttributeLayout::Template)
}
impl ReadCall {
    fn valid_return(&mut self, code: CK_RV) -> bool {
        let array = self.descriptors.values.as_mut_ptr();
        // Parent indices always precede children, even when sibling groups are
        // constructed in a different order. Unreachable metadata is never read.
        for index in 0..self.nodes.len() {
            if !self.nodes[index].visible {
                continue;
            }
            let descriptor = &self.descriptors.values[index];
            let node = &mut self.nodes[index];
            let (pointer, capacity) = match &mut node.storage {
                Storage::Query => (std::ptr::null_mut(), None),
                Storage::Buffer(bytes) => (bytes.pointer(), Some(bytes.capacity())),
                Storage::Template { start, count } => {
                    // SAFETY: this is our original, measured child range; the
                    // returned pValue is only compared, never dereferenced.
                    (
                        unsafe { array.add(*start) }.cast(),
                        Some(*count * size_of::<CK_ATTRIBUTE>()),
                    )
                }
            };
            if descriptor.pValue != pointer {
                return false;
            }
            if index == 0 && node.expected.map(AttributeType::native) != Some(descriptor.r#type) {
                return false;
            }
            let reported = length(descriptor.ulValueLen);
            if let (Some(capacity), Some(reported)) = (capacity, reported) {
                if reported > capacity && code != CKR_BUFFER_TOO_SMALL {
                    return false;
                }
            }
            // Child types are output. A changed type is a bounded observation,
            // not a reason to follow bytes that are no longer child descriptors.
            if node
                .expected
                .is_some_and(|a| a.native() != descriptor.r#type)
            {
                continue;
            }
            if let (Storage::Template { start, count }, Some(reported)) = (&node.storage, reported)
            {
                let width = size_of::<CK_ATTRIBUTE>();
                if reported % width == 0 && reported / width <= *count {
                    let start = *start;
                    let end = start + reported / width;
                    for child in &mut self.nodes[start..end] {
                        child.visible = true;
                    }
                }
            }
        }
        true
    }

    fn finish(mut self, code: CK_RV) -> Result<TemplateAttributeTree> {
        self.tree.call.code = code as u64;
        for (index, node) in self.nodes.iter_mut().enumerate() {
            if !node.visible {
                continue;
            }
            let descriptor = &self.descriptors.values[index];
            let value = observe_node(index, node, descriptor, code).map_err(|_| {
                Error::AttributeReadInvalid {
                    call: self.tree.call,
                    reason: crate::RejectionReason::AttributeValues(crate::AttributeValuesRejection::ValidatedTemplateResultCouldNotBeRepresented),
                }
            })?;
            self.tree.records[index] = Record::Returned {
                identifier: descriptor.r#type as u64,
                value,
            };
        }
        // Nonpublished buffers and native descriptor bytes are erased before
        // returning the result. The public tree owns only observations/credits.
        Ok(self.tree)
    }
}

fn observe_node(
    index: usize,
    node: &mut prepare::Node,
    descriptor: &CK_ATTRIBUTE,
    code: CK_RV,
) -> Result<Observed> {
    if let Some(expected) = node.expected.filter(|a| a.native() != descriptor.r#type) {
        return Ok(Observed::TypeChanged {
            expected: expected.identifier(),
        });
    }
    let reported = length(descriptor.ulValueLen);
    if index == 0 && matches!(node.storage, Storage::Query) && code == CKR_BUFFER_TOO_SMALL {
        return Ok(Observed::BufferTooSmall {
            supplied: 0,
            required: reported,
        });
    }
    if index == 0
        && (matches!(node.storage, Storage::Query) || reported == Some(0))
        && matches!(code, CKR_ATTRIBUTE_SENSITIVE | CKR_ATTRIBUTE_TYPE_INVALID)
    {
        // With no supplied/returned children the global refusal belongs to this
        // root. Otherwise a child may have caused the global partial code.
        return Ok(Observed::Unavailable(if code == CKR_ATTRIBUTE_SENSITIVE {
            AttributeUnavailableCause::Sensitive
        } else {
            AttributeUnavailableCause::Unsupported
        }));
    }
    let Some(reported) = reported else {
        // One outer descriptor can contain many failing children; its global
        // code does not identify the reason this position is unavailable.
        return Ok(Observed::Unavailable(
            AttributeUnavailableCause::Unspecified,
        ));
    };
    match &node.storage {
        Storage::Query => {
            if (node
                .expected
                .is_some_and(|a| a.layout() == AttributeLayout::Template)
                || is_template(descriptor.r#type))
                && reported % size_of::<CK_ATTRIBUTE>() != 0
            {
                Ok(Observed::InvalidTemplateLength(reported))
            } else {
                Ok(Observed::SizeKnown(reported))
            }
        }
        Storage::Buffer(bytes) if reported > bytes.capacity() => Ok(Observed::BufferTooSmall {
            supplied: bytes.capacity(),
            required: Some(reported),
        }),
        Storage::Buffer(_) => {
            let attribute =
                node.expected
                    .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
                        crate::AttributeValuesRejection::KnownTemplateValueTypeMissing,
                    )))?;
            let Storage::Buffer(mut bytes) = std::mem::replace(&mut node.storage, Storage::Query)
            else {
                unreachable!("matched buffer storage")
            };
            bytes.set_length(reported)?;
            Ok(Observed::Flat(FlatAttributeObservation {
                attribute,
                calls: AttributeReadCalls::Direct { code: code as u64 },
                value: FlatAttributeValue::Available(bytes),
            }))
        }
        Storage::Template { start, count } => {
            let supplied = count * size_of::<CK_ATTRIBUTE>();
            if reported > supplied {
                Ok(Observed::BufferTooSmall {
                    supplied,
                    required: Some(reported),
                })
            } else if reported % size_of::<CK_ATTRIBUTE>() != 0 {
                Ok(Observed::InvalidTemplateLength(reported))
            } else {
                Ok(Observed::Template {
                    start: *start,
                    count: reported / size_of::<CK_ATTRIBUTE>(),
                })
            }
        }
    }
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
    crate::attributes::record(access, session)?;
    returned.arm();
    // SAFETY: the frame owns the complete wired graph, session/module and object
    // activity; root count is one and no allocation can move during this call.
    let code = returned.observe(
        unsafe {
            get(
                session.entry.handle,
                object,
                body.data.descriptors.values.as_mut_ptr(),
                1,
            )
        },
        &access.native,
    );
    if !crate::native_return::attribute_completion_known(code) {
        returned.recoverable();
        session.poison(access);
        access.check_attribute_return(session.entry.handle, code)?;
        return Err(Error::AttributeReadInvalid {
            call: AttributeBatchCall {
                code: code as u64,
                attribute_count: 1,
            },
            reason: crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::TemplateReadCompletionUnknown,
            ),
        });
    }
    if !partial(code) {
        // Ordinary errors need not have populated child metadata. Do not turn
        // undefined output into a descriptor anomaly or a published value.
        returned.terminated();
        access.check_attribute_return(session.entry.handle, code)?;
        return Err(Error::AttributeReadInvalid {
            call: AttributeBatchCall {
                code: code as u64,
                attribute_count: 1,
            },
            reason: crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::TemplateReadReturnedNoAttributeResult,
            ),
        });
    }
    if !body.data.valid_return(code) {
        returned.quarantine(&access.native);
        // Record scope changes without losing either the native code or anomaly.
        let _ = access.check_attribute_return(session.entry.handle, code);
        return Err(Error::AttributeReadInvalid {
            call: AttributeBatchCall {
                code: code as u64,
                attribute_count: 1,
            },
            reason: crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::TemplateDescriptorPointerOrCapacityChanged,
            ),
        });
    }
    returned.terminated();
    Ok(code)
}

pub(super) fn observe(
    session: &crate::Session,
    object: &crate::NativeObjectRef,
    attribute: AttributeType,
    plan: TemplateAttributeReadPlan<'_>,
    limits: AttributeTemplateLimits,
) -> Result<TemplateAttributeTree> {
    let progress = crate::session::AdmissionProgress::default();
    let epoch = session.snapshot.authentication_stamp();
    let (data, access) = session.prepare_with_native_roles_prepaid_at_epoch(
        [(Some(object), crate::session::activity::AccessMode::Read)],
        false,
        epoch,
        &progress,
        |overhead| {
            let (data, prepaid) = ReadCall::prepare(
                &session.inner.symmetric_budget,
                attribute,
                plan,
                limits,
                overhead,
                |bytes| {
                    crate::advanced::reserve_preparation_at_epoch(session, bytes, &progress, epoch)
                },
            )?;
            let scope = session.inner.attribute_extension_scope.get().copied();
            for node in &data.nodes {
                if let Some(attribute) = node.expected {
                    attribute.check_scope(scope)?;
                }
            }
            Ok((data, prepaid))
        },
    )?;
    let handle = session.managed_handle(&access, object)?;
    session.entry(&access)?;
    let mut frame = NativeFrame::session(access.clone(), data)?;
    let result = dispatch(&mut frame, session, handle);
    let code =
        session.metadata_result(&access, object.identity.access().authentication(), result)?;
    frame.into_inner()?.data.into_inner().finish(code)
}
