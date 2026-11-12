// SPDX-License-Identifier: Apache-2.0
//! Preserve ciphertext sizing observations without implying a failed creation.
use crate::{
    error::{CleanupStorage, CompletionDiagnostic},
    Error,
};
use fe11_sys::{CKR_BUFFER_TOO_SMALL, CK_ULONG};

// Both supported native ABIs represent CK_ULONG without loss in usize. Keep
// this invariant explicit if another ABI is added to the bindings later.
const _: () = assert!(std::mem::size_of::<CK_ULONG>() <= std::mem::size_of::<usize>());

/// Called only after C_EncapsulateKey returns CKR_BUFFER_TOO_SMALL and native
/// memory is returned. The reported length is an observation, not an allocation
/// request or proof that the module created no key. All error storage is prepaid.
pub(crate) fn capacity_failure(
    required: CK_ULONG,
    capacity: usize,
    local: Option<Error>,
    diagnostic: CompletionDiagnostic,
    cleanup: &mut CleanupStorage,
) -> Error {
    let failure = Error::OutputBufferTooSmall {
        function: "C_EncapsulateKey",
        code: CKR_BUFFER_TOO_SMALL as u64,
        required: required as usize,
        capacity,
    };
    let failure = match local {
        Some(cause) => {
            diagnostic.output_failure(CKR_BUFFER_TOO_SMALL, required as u64, capacity, cause)
        }
        None => failure,
    };
    // The enclosing mutation runner can still fail its cleanup preparation.
    // Do not consume that later stage's two independent failure leaves here.
    cleanup.mark_remaining(failure)
}
