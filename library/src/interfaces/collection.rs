// SPDX-License-Identifier: Apache-2.0
//! Count/fill observations shared by inventory and explicit table selection.
use super::InterfaceListFrame;
use crate::native::frame::NativeFrame;
use crate::{
    Error, NativeInterfacesRejection as Reason, NativeOutputSize, RejectionReason, Result,
};
use fe11_sys::*;
fn rejected(reason: Reason) -> Error {
    Error::Rejected(RejectionReason::NativeInterfaces(reason))
}

pub(super) fn collect<T>(
    list: unsafe extern "C" fn(*mut CK_INTERFACE, *mut CK_ULONG) -> CK_RV,
    maximum: usize,
    attempts: usize,
    uncertain: &std::cell::Cell<bool>,
    mut before: impl FnMut() -> Result<()>,
    consume: impl FnOnce(&[CK_INTERFACE]) -> Result<T>,
) -> Result<T> {
    const FUNCTION: &str = "C_GetInterfaceList";
    if attempts == 0 {
        return Err(rejected(Reason::InterfaceDiscoveryAttemptsExhausted));
    }
    let diagnostic = crate::error::CompletionStorage::allocate()?.bind(FUNCTION);
    // Allocate once before any native observation; reuse only after established
    // return. No new frame allocation can erase an earlier capacity response.
    let mut frame = NativeFrame::new(InterfaceListFrame {
        count: 0,
        entries: Vec::new(),
    })?;
    let mut last: Option<NativeOutputSize> = None;
    for attempt in 0..attempts {
        frame.entries.clear();
        frame.count = 0;
        if let Err(cause) = before() {
            return Err(match last {
                Some(size) => {
                    diagnostic.output_failure(size.code as CK_RV, size.reported, size.limit, cause)
                }
                None => cause,
            });
        }
        // SAFETY: stable initialized count; null output is the explicit count query.
        let rv = unsafe { list(std::ptr::null_mut(), &mut frame.count) };
        let result = frame.loading_result(rv, FUNCTION, uncertain, false);
        if rv == CKR_BUFFER_TOO_SMALL {
            return Err(NativeOutputSize {
                function: FUNCTION,
                code: rv as u64,
                reported: frame.count as u64,
                limit: 0,
            }
            .buffer_too_small());
        }
        result?;
        let observed = frame.count;
        let count = crate::error::checked_native_size(FUNCTION, rv, observed, maximum);
        // CompletionDiagnostic is consumed only on the exclusive failure path.
        let count = match count {
            Ok(count) => count,
            Err(cause) => return Err(diagnostic.output_failure(rv, observed as u64, 0, cause)),
        };
        if count == 0 {
            return consume(&[])
                .map_err(|cause| diagnostic.output_failure(rv, observed as u64, 0, cause));
        }
        if frame.entries.try_reserve_exact(count).is_err() {
            return Err(diagnostic.output_failure(
                rv,
                observed as u64,
                0,
                rejected(Reason::InterfaceAllocation),
            ));
        }
        frame
            .entries
            .resize_with(count, crate::native::output::interface);
        if let Err(cause) = before() {
            return Err(diagnostic.output_failure(rv, observed as u64, 0, cause));
        }
        let body = &mut *frame;
        // SAFETY: initialized descriptor array and count share the stable frame.
        // A quarantined call cannot reach a retry or consume the descriptor slice.
        let rv = unsafe { list(body.entries.as_mut_ptr(), &mut body.count) };
        let result = frame.loading_result(rv, FUNCTION, uncertain, false);
        if rv == CKR_BUFFER_TOO_SMALL {
            let size = NativeOutputSize {
                function: FUNCTION,
                code: rv as u64,
                reported: frame.count as u64,
                limit: count,
            };
            if let Err(cause) =
                crate::error::checked_native_size(FUNCTION, rv, frame.count, maximum)
            {
                return Err(diagnostic.output_failure(rv, size.reported, count, cause));
            }
            if attempt + 1 == attempts {
                return Err(size.buffer_too_small());
            }
            last = Some(size);
            continue;
        }
        result?;
        let observed = frame.count;
        let filled = match crate::bounds::final_length(observed, count) {
            Ok(value) => value,
            Err(cause) => {
                frame.quarantine_loading(uncertain);
                return Err(diagnostic.output_failure(rv, observed as u64, count, cause));
            }
        };
        return consume(&frame.entries[..filled])
            .map_err(|cause| diagnostic.output_failure(rv, observed as u64, count, cause));
    }
    unreachable!("the final bounded attempt returns success or its observation")
}
