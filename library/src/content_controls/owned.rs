// SPDX-License-Identifier: Apache-2.0
//! Protected CKA_VALUE storage retained through uncertain native completion.
//!
//! This reader never stages a secret in the public attribute reader's `Vec<u8>`.
//! Its caller retains object activity in SessionAccess before entry. Both the
//! descriptor and any initialized secret allocation belong to the native frame.
use super::*;
use crate::bounds;
use crate::native::frame::{NativeFrame, SessionFrame};
use crate::session::SessionAccess;
use crate::symmetric::memory::Credit;

pub(crate) mod resident;

enum Phase {
    Sizing,
    Reading(SecretBytes),
}
struct ValueCall {
    descriptor: CK_ATTRIBUTE,
    phase: Phase,
    // Released after phase and its protected bytes, including native uncertainty.
    _credit: Credit,
}
// SAFETY: pValue is null or addresses the SecretBytes allocation owned by phase.
// The allocation is never resized while armed; no caller memory is referenced.
unsafe impl Send for ValueCall {}

impl ValueCall {
    fn descriptor_valid(&mut self, rv: CK_RV) -> bool {
        if self.descriptor.r#type != CKA_VALUE {
            return false;
        }
        match &mut self.phase {
            Phase::Sizing => self.descriptor.pValue.is_null(),
            Phase::Reading(bytes) => {
                if self.descriptor.pValue != bytes.as_mut_slice().as_mut_ptr().cast() {
                    return false;
                }
                // BUFFER_TOO_SMALL can report a larger required size. It grants
                // no access to output bytes and does not trigger a retry.
                !matches!(
                    rv,
                    CKR_OK | CKR_ATTRIBUTE_SENSITIVE | CKR_ATTRIBUTE_TYPE_INVALID
                ) || self.descriptor.ulValueLen == CK_UNAVAILABLE_INFORMATION
                    || self.descriptor.ulValueLen as u128 <= bytes.len() as u128
            }
        }
    }
}
fn dispatch(
    frame: &mut NativeFrame<SessionFrame<'_, ValueCall>>,
    session: &Session,
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
    attributes::record(access, session)?;
    returned.arm();
    // SAFETY: the stable frame owns the descriptor, secret buffer and access
    // protections. Neither allocation is freed or erased on uncertain return.
    let rv = returned.observe(
        unsafe { get(session.entry.handle, object, &mut data.descriptor, 1) },
        &access.native,
    );
    if crate::native_return::attribute_completion_known(rv) {
        if !data.descriptor_valid(rv) {
            returned.quarantine(&access.native);
            // Scope publication precedes the composed diagnostic; a native
            // refusal cannot erase the descriptor anomaly or expose the value.
            let _ = access.check_attribute_return(session.entry.handle, rv);
            return Err(Error::AttributeReadInvalid {
                call: crate::AttributeBatchCall {
                    code: rv as u64,
                    attribute_count: 1,
                },
                reason: crate::RejectionReason::ObjectContent(
                    crate::ObjectContentRejection::ContentNativeDescriptorOrCapacityChanged,
                ),
            });
        }
        returned.terminated();
    } else {
        returned.recoverable();
        session.poison(access);
    }
    if !matches!(rv, CKR_ATTRIBUTE_SENSITIVE | CKR_ATTRIBUTE_TYPE_INVALID) {
        access.check_attribute_return(session.entry.handle, rv)?;
    }
    Ok(rv)
}
fn absence(rv: CK_RV, length: CK_ULONG) -> Option<ProtectedContent> {
    let cause = match rv {
        CKR_ATTRIBUTE_SENSITIVE => AttributeUnavailableCause::Sensitive,
        CKR_ATTRIBUTE_TYPE_INVALID => AttributeUnavailableCause::Unsupported,
        _ if length == CK_UNAVAILABLE_INFORMATION => AttributeUnavailableCause::Unspecified,
        _ => return None,
    };
    Some(unavailable(CKA_VALUE, cause))
}
