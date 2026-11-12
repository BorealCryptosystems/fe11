// SPDX-License-Identifier: Apache-2.0
//! Function-specific completion of synchronous, traditional sequences.
//!
//! Authorities: PKCS#11 2.40 §§5.8–5.11, 5.13 and PKCS#11 3.2
//! §§5.8, 5.10, 5.12, 5.13, 5.15. Message encrypt/decrypt Final completion
//! and the already-inactive case follow §§5.9.5, 5.11.5, 5.14.5 and 5.16.5; a message's
//! own return never proves completion of its parent.
//! Dual-operation owners retain their separate contracts.
use super::call_memory_returned;
use fe11_sys::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutputRequest {
    Unspecified,
    LengthOnly,
    Buffer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Completion {
    Unproven,
    Terminated,
    Uncertain,
}

fn supported(version: (u8, u8), function: &str) -> bool {
    // The explicit historical selections retain the common sequence contract.
    // PKCS#11 2.20 sections 11.8-11.12 and 11.16 (archived pages 156-180,
    // 201-202) have the same probe/terminal distinction. Draft 2.30 is the
    // caller-selected historical compatibility view, not a published edition.
    let traditional = matches!(version, (2, 20 | 30 | 40..) | (3, _));
    traditional
        && (!function.starts_with("C_VerifySignature") || matches!(version, (3, 2..)))
        && (!function.starts_with("C_Message") || version.0 == 3)
}

/// Only for a non-NULL Init. Its caller owns this attempt's parameters even
/// when another operation is already active on the native session.
/// A refusal releases this attempt's parameters; it does not erase an older
/// sequence or grant permission to reuse an invalidated session.
pub(crate) fn init(version: (u8, u8), function: &str, rv: CK_RV) -> Completion {
    if !call_memory_returned(rv) {
        return Completion::Uncertain;
    }
    if !supported(version, function) || rv == CKR_OK {
        return Completion::Unproven;
    }
    // An uncertain effect is not proof of native inactivity. The separate
    // refused-attempt fact still permits returning this invocation's storage.
    if initialization_refused(version, function, rv) && !super::effect_uncertain(rv) {
        Completion::Terminated
    } else {
        Completion::Unproven
    }
}

/// Return of a refused non-NULL Init's own loan, after the caller verifies
/// its boundary. A refused attempt does not own a previously active sequence.
pub(crate) fn initialization_refused(version: (u8, u8), function: &str, rv: CK_RV) -> bool {
    supported(version, function)
        && rv != CKR_OK
        && call_memory_returned(rv)
        && matches!(
            function,
            "C_FindObjectsInit"
                | "C_EncryptInit"
                | "C_DecryptInit"
                | "C_DigestInit"
                | "C_SignInit"
                | "C_SignRecoverInit"
                | "C_VerifyInit"
                | "C_VerifyRecoverInit"
                | "C_VerifySignatureInit"
                | "C_MessageEncryptInit"
                | "C_MessageDecryptInit"
                | "C_MessageSignInit"
                | "C_MessageVerifyInit"
        )
}

/// Called after return, never as permission to retry. Successful size probes
/// and BUFFER_TOO_SMALL preserve exactly those operations whose clauses say so.
/// PENDING prevents release. Other returns follow the function's
/// clause, independently of the scope of context withdrawal and possible effects.
pub(crate) fn returned(
    version: (u8, u8),
    function: &str,
    output: OutputRequest,
    rv: CK_RV,
) -> Completion {
    if !call_memory_returned(rv) {
        return Completion::Uncertain;
    }
    if !supported(version, function) {
        return Completion::Unproven;
    }
    let terminated = match function {
        "C_Encrypt" | "C_EncryptFinal" | "C_Decrypt" | "C_DecryptFinal" | "C_Digest"
        | "C_DigestFinal" | "C_Sign" | "C_SignFinal" | "C_SignRecover" | "C_VerifyRecover" => {
            rv != CKR_BUFFER_TOO_SMALL && (rv != CKR_OK || output == OutputRequest::Buffer)
        }
        "C_EncryptUpdate" | "C_DecryptUpdate" => rv != CKR_OK && rv != CKR_BUFFER_TOO_SMALL,
        // DigestKey does not inherit DigestUpdate's termination-on-error rule.
        // An already-inactive digest is the only local terminal refusal here.
        "C_DigestKey" => rv == CKR_OPERATION_NOT_INITIALIZED,
        "C_DigestUpdate" | "C_SignUpdate" | "C_VerifyUpdate" | "C_VerifySignatureUpdate" => {
            rv != CKR_OK
        }
        "C_Verify" | "C_VerifyFinal" | "C_VerifySignature" | "C_VerifySignatureFinal" => true,
        // PKCS#11 3.2 §§5.7.8–5.7.9: a successful batch does not end
        // discovery; Final success or an already-inactive search does.
        "C_FindObjects" => rv == CKR_OPERATION_NOT_INITIALIZED,
        "C_FindObjectsFinal" => matches!(rv, CKR_OK | CKR_OPERATION_NOT_INITIALIZED),
        "C_MessageEncryptFinal"
        | "C_MessageDecryptFinal"
        | "C_MessageSignFinal"
        | "C_MessageVerifyFinal" => {
            matches!(rv, CKR_OK | CKR_OPERATION_NOT_INITIALIZED)
        }
        // These invocations have no sequence of their own. Their return ends
        // only their call storage loan, never a different active operation.
        "C_GenerateRandom"
        | "C_SeedRandom"
        | "C_GetObjectSize"
        | "C_GetFunctionStatus"
        | "C_CancelFunction" => true,
        // Other search/message calls, dual-operation, cancellation and mutation owners must
        // establish their own completion; their successful call is not enough.
        _ => false,
    };
    if terminated {
        Completion::Terminated
    } else {
        Completion::Unproven
    }
}

/// Whether a returned digest injection has released its input references.
/// This does not establish that the enclosing digest has terminated.
pub(crate) fn digest_input_returned(version: (u8, u8), function: &str, rv: CK_RV) -> bool {
    supported(version, function)
        && call_memory_returned(rv)
        && matches!(function, "C_DigestUpdate" | "C_DigestKey")
}
