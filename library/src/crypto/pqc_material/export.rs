// SPDX-License-Identifier: Apache-2.0
//! One exact private-attribute read, without sizing, retries or format fallback.
//! All native pointers remain backed by this owner until confirmed completion;
//! an uncertain return retains the secret allocations and their budget credits.
use super::*;
use crate::native::frame::NativeFrame;
use crate::session::SessionAccess;
use crate::symmetric::memory::Credit;

pub(super) struct ExportCall {
    output: PqcPrivateExport,
    descriptors: [CK_ATTRIBUTE; 2],
    expected: [CK_ATTRIBUTE; 2],
    count: usize,
    diagnostic: Option<crate::error::CompletionStorage>,
    _protection: crate::session::observation_protection::ObservationProtection,
    _credit: Credit,
}
// SAFETY: both descriptor arrays refer exclusively to output's owned stable
// buffers. Moving this structure does not move those allocations; no borrowed
// input, provider pointer or reference to the descriptor array is stored here.
unsafe impl Send for ExportCall {}

impl ExportCall {
    pub(super) const fn allocation_bytes() -> usize {
        std::mem::size_of::<Self>()
            + crate::native::frame::SessionFrame::<'_, Self>::allocation_bytes()
            + crate::error::CompletionStorage::allocation_bytes()
    }

    /// Validate a fully returned successful read before publishing any secret.
    /// Bounded shape disagreement does not mean the module still borrows memory.
    fn finish_representation(&mut self) -> Result<()> {
        let validation = validate_descriptors(
            &self.descriptors[..self.count],
            &self.expected[..self.count],
        );
        self.diagnostic
            .take()
            .expect("export diagnostic prepared before possession")
            .bind("C_GetAttributeValue")
            .finish_native(CKR_OK, validation)
    }

    fn inputs_valid(&self, rv: CK_RV) -> bool {
        self.descriptors[..self.count]
            .iter()
            .zip(&self.expected[..self.count])
            .all(|(actual, expected)| {
                actual.r#type == expected.r#type
                    && actual.pValue == expected.pValue
                    && (!matches!(
                        rv,
                        CKR_OK | CKR_ATTRIBUTE_SENSITIVE | CKR_ATTRIBUTE_TYPE_INVALID
                    ) || actual.ulValueLen == CK_UNAVAILABLE_INFORMATION
                        || actual.ulValueLen <= expected.ulValueLen)
            })
    }
}
pub(super) fn read_prepared(
    access: &SessionAccess<'_>,
    session: &Session,
    handle: CK_OBJECT_HANDLE,
    data: ExportCall,
) -> Result<PqcPrivateExport> {
    if !access.owns_session(session) {
        return Err(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
            crate::PostQuantumKeysRejection::PqcExportAccessOwner,
        )));
    }
    let mut frame = NativeFrame::session(access.clone(), data)?;
    let (returned, body) = frame.session_parts();
    let access = &body.access;
    let read = access
        .native
        .table
        .C_GetAttributeValue
        .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
            crate::AttributeValuesRejection::CGetAttributeValueUnavailable,
        )))?;
    let data = &mut *body.data;
    let count = bounds::ck_length(data.count)?;
    crate::attributes::record(access, session)?;

    returned.arm();
    // SAFETY: the stable frame owns the descriptors, exact initialized private
    // buffers, and the session/object protections for the entire native lifetime.
    let rv = returned.observe(
        unsafe {
            read(
                session.entry.handle,
                handle,
                data.descriptors.as_mut_ptr(),
                count,
            )
        },
        &access.native,
    );
    if crate::native_return::attribute_completion_known(rv) {
        if !data.inputs_valid(rv) {
            returned.quarantine(&access.native);
            // Retire the affected native scope, retaining both diagnostic causes.
            let _ = access.check_attribute_return(session.entry.handle, rv);
            return Err(data
                .diagnostic
                .take()
                .expect("export diagnostic prepared before possession")
                .bind("C_GetAttributeValue")
                .boundary_failure(
                    rv,
                    Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                        crate::PostQuantumKeysRejection::PqcPrivateDescriptorOrCapacityChanged,
                    )),
                ));
        }
        returned.terminated();
    } else {
        returned.recoverable();
        session.poison(access);
    }
    access.check_attribute_return(session.entry.handle, rv)?;
    // Only CKR_OK permits publishing the requested representation. Sensitive,
    // unsupported and partial reads remain native refusals, without fallback.
    data.finish_representation()?;
    Ok(frame.into_inner()?.data.into_inner().output)
}

mod preparation;
pub(super) use preparation::Storage;
