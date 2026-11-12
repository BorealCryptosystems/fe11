// SPDX-License-Identifier: Apache-2.0
//! Native failure scope, separate from function-specific sequence termination.
//! Context validity and effect uncertainty are independent. Unknown returns
//! retain their exact error; function contracts decide termination independently.
use fe11_sys::*;

pub(crate) mod protocol;
pub(crate) mod sequence;

/// H-CALL-RETURN: an intact synchronous return ends this call's memory loan,
/// except PENDING. This is the trusted native-module boundary
/// documented in the threat model, not proof of termination of a parent
/// sequence, non-creation of an object, or permission to read refused outputs.
/// Callers must still quarantine a detected descriptor/input boundary anomaly.
pub(crate) fn call_memory_returned(rv: CK_RV) -> bool {
    diagnostic_memory_returned(rv as u64)
}

// Errors retain CK_RV as u64 on every target. Compare that complete diagnostic
// without narrowing it back to Windows' 32-bit CK_RV. This is the same
// H-CALL-RETURN classification as above, not a separate release policy.
pub(crate) fn diagnostic_memory_returned(code: u64) -> bool {
    code != CKR_PENDING as u64
}

/// A control return does not necessarily return the original asynchronous
/// operation's graph. Keep its stronger lifetime rule separate from a direct
/// invocation's temporary arguments, including foreign u64 diagnostics.
pub(crate) fn async_memory_returned(code: u64) -> bool {
    diagnostic_memory_returned(code) && code != CKR_GENERAL_ERROR as u64
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureScope {
    None,
    Session,
    Token,
    Module,
}

// Established invalidity withdraws its scope. An unexpected PENDING quarantines
// execution. GENERAL_ERROR alone establishes neither invalidity nor a live
// memory loan from a returned direct call. OPERATION_ACTIVE withdraws neither the session
// nor the pre-existing operation; each attempt owns its own completion proof.
pub(crate) fn native_context_scope(rv: CK_RV) -> FailureScope {
    diagnostic_context_scope(rv as u64)
}

// Shared by the native path and its retained diagnostic. Unknown values stay
// unknown; truncating high bits could alias an unrelated context-invalid code.
pub(crate) fn diagnostic_context_scope(code: u64) -> FailureScope {
    if [CKR_CRYPTOKI_NOT_INITIALIZED as u64, CKR_PENDING as u64].contains(&code) {
        FailureScope::Module
    } else if [
        CKR_DEVICE_REMOVED as u64,
        CKR_TOKEN_NOT_PRESENT as u64,
        CKR_TOKEN_NOT_RECOGNIZED as u64,
        CKR_SLOT_ID_INVALID as u64,
        CKR_FIPS_SELF_TEST_FAILED as u64,
    ]
    .contains(&code)
    {
        FailureScope::Token
    } else if [CKR_SESSION_CLOSED as u64, CKR_SESSION_HANDLE_INVALID as u64].contains(&code) {
        FailureScope::Session
    } else {
        FailureScope::None
    }
}
// An unknown return cannot prove absence of native effects, even though it
// does not establish that unrelated sessions or the module became invalid.
pub(crate) fn effect_uncertain(rv: CK_RV) -> bool {
    !standard_return(rv)
        || matches!(
            rv,
            CKR_GENERAL_ERROR
                | CKR_DEVICE_ERROR
                | CKR_DEVICE_REMOVED
                | CKR_CRYPTOKI_NOT_INITIALIZED
                | CKR_PENDING
                | CKR_FIPS_SELF_TEST_FAILED
                | CKR_LIBRARY_LOAD_FAILED
        )
}

pub(crate) fn failure_scope(rv: CK_RV) -> FailureScope {
    match native_context_scope(rv) {
        FailureScope::None if rv != CKR_OK && rv != CKR_OPERATION_ACTIVE => FailureScope::Session,
        scope => scope,
    }
}

// PKCS11 3.2 sections5.2/5.6.6: a refused state read does not terminate
// the cryptographic source. This never authorizes publication or retry.
// SetOperationState and all other native failures keep their existing scope.
pub(crate) fn state_read_scope(rv: CK_RV) -> FailureScope {
    native_context_scope(rv)
}

// The closed C_OpenSession table is independent of crypto sequence errors.
// Only the explicit ordinary refusal set establishes non-creation. Device,
// initialization and unknown failures retain ownership; never use error outputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpenFailure {
    pub non_creation: bool,
    pub scope: FailureScope,
}
pub(crate) fn open_failure(rv: CK_RV) -> OpenFailure {
    let non_creation = !effect_uncertain(rv)
        && matches!(
            rv,
            CKR_ARGUMENTS_BAD
                | CKR_HOST_MEMORY
                | CKR_FUNCTION_FAILED
                | CKR_FUNCTION_NOT_SUPPORTED
                | CKR_DEVICE_MEMORY
                | CKR_SESSION_COUNT
                | CKR_SESSION_PARALLEL_NOT_SUPPORTED
                | CKR_SESSION_READ_WRITE_SO_EXISTS
                | CKR_SLOT_ID_INVALID
                | CKR_TOKEN_NOT_PRESENT
                | CKR_TOKEN_NOT_RECOGNIZED
                | CKR_TOKEN_WRITE_PROTECTED
        );
    let scope = native_context_scope(rv);
    OpenFailure {
        non_creation,
        scope,
    }
}
// A non-OK close never establishes disappearance. The caller keeps ownership
// and revokes use independently of the wider failure scope returned here.
// Collective close is slot-scoped. Local failures retain all unproved credits.
pub(crate) fn recover_scope(rv: CK_RV) -> FailureScope {
    native_context_scope(rv)
}
pub(crate) fn close_scope(rv: CK_RV) -> FailureScope {
    native_context_scope(rv)
}

// Attribute reads do not start a sequence. Partial/ordinary read refusals
// cannot by themselves withdraw an otherwise usable session.
pub(crate) fn attribute_scope(rv: CK_RV) -> FailureScope {
    native_context_scope(rv)
}

// PKCS#11 3.2 section 5.7.5, plus the universal FUNCTION_NOT_SUPPORTED refusal.
// Partial attribute statuses complete the call; they do not prove that every
// value exists. Unknown/context/operation errors never authorize output reads.
pub(crate) fn attribute_completion_known(rv: CK_RV) -> bool {
    call_memory_returned(rv)
}

// Info and authentication do not create a cryptographic sequence. Keep their
// call storage separate from the existing cryptographic sequence owner.
#[derive(Clone, Copy, Debug)]
pub(crate) enum SessionCall {
    Info,
    Login,
    LoginUser,
    ContextLogin,
    ContextLoginUser,
    Logout,
}
impl SessionCall {
    // Authentication input lifetime does not determine the parent's lifetime.
    pub(crate) fn completion_known(self, rv: CK_RV) -> bool {
        call_memory_returned(rv)
    }

    pub fn function(self) -> &'static str {
        match self {
            Self::Info => "C_GetSessionInfo",
            Self::Login | Self::ContextLogin => "C_Login",
            Self::LoginUser | Self::ContextLoginUser => "C_LoginUser",
            Self::Logout => "C_Logout",
        }
    }
    pub fn scope(self, rv: CK_RV) -> FailureScope {
        // A login refusal does not dispose of a pre-existing operation,
        // whether Fe11 or another coordinated participant started it.
        native_context_scope(rv)
    }
}

#[derive(Clone, Copy)]
pub(crate) enum TokenCall {
    Info,
    Initialize,
}
impl TokenCall {
    // Neither call has a pre-existing multipart operation. A definite missing
    // slot/token refusal completes this call while retiring its context.
    pub(crate) fn completion_known(self, rv: CK_RV) -> bool {
        call_memory_returned(rv)
    }
}

// PIN mutations have no active sequence to abandon. Their possible effect is
// retained by the caller independently of session/token/module availability.
#[derive(Clone, Copy, Debug)]
pub(crate) enum PinCall {
    Initialize,
    Change,
}
impl PinCall {
    // PKCS#11 3.2 §§5.5.8–5.5.9: input lifetime follows H-CALL-RETURN;
    // possible credential mutation and role changes are classified separately.
    pub(crate) fn completion_known(self, rv: CK_RV) -> bool {
        call_memory_returned(rv)
    }

    pub fn function(self) -> &'static str {
        match self {
            Self::Initialize => "C_InitPIN",
            Self::Change => "C_SetPIN",
        }
    }
    pub fn scope(self, rv: CK_RV) -> FailureScope {
        native_context_scope(rv)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum MutationCall {
    Create,
    Copy,
    Set,
    Destroy,
    GeneratePair,
    GenerateKey,
    Derive,
    Unwrap,
    UnwrapAuthenticated,
    Encapsulate,
    Decapsulate,
}
impl MutationCall {
    // PKCS#11 3.2 §§5.7.1/5.7.2/5.7.6 and 5.18.4–9. Storage completion is separate
    // from effect/non-creation and failure scope, especially for partial Set.
    // Every listed mutation has a call-scoped template, not an Init sequence.
    pub(crate) fn template_completion_known(self, rv: CK_RV) -> bool {
        call_memory_returned(rv)
    }
    // PKCS#11 v3.2, return-value definitions and §§5.7.3/5.7.6:
    // these refusals say that the requested action was not performed.
    // This is an effect classification, not an error-to-success conversion.
    // Do not extend it to other functions or ambiguous errors by analogy.
    pub(crate) fn definite_object_refusal(self, rv: CK_RV) -> bool {
        // §5.7.2 explicitly forbids Copy when CKA_COPYABLE is false.
        // Do not extend the other Set/Destroy guarantees to Copy by analogy.
        matches!(self, Self::Copy) && rv == CKR_ACTION_PROHIBITED
            || matches!(self, Self::Set | Self::Destroy)
                && matches!(
                    rv,
                    CKR_ACTION_PROHIBITED | CKR_SESSION_READ_ONLY | CKR_TOKEN_WRITE_PROTECTED
                )
    }

    pub fn function(self) -> &'static str {
        match self {
            Self::Create => "C_CreateObject",
            Self::Copy => "C_CopyObject",
            Self::Set => "C_SetAttributeValue",
            Self::Destroy => "C_DestroyObject",
            Self::GeneratePair => "C_GenerateKeyPair",
            Self::GenerateKey => "C_GenerateKey",
            Self::Derive => "C_DeriveKey",
            Self::Unwrap => "C_UnwrapKey",
            Self::UnwrapAuthenticated => "C_UnwrapKeyAuthenticated",
            Self::Encapsulate => "C_EncapsulateKey",
            Self::Decapsulate => "C_DecapsulateKey",
        }
    }
    pub fn scope(self, rv: CK_RV) -> FailureScope {
        native_context_scope(rv)
    }
    // Closed effect classification, not an application retirement decision.
    fn effect_scope(self, rv: CK_RV) -> FailureScope {
        if matches!(self, Self::Encapsulate | Self::Decapsulate) {
            return kem_scope(matches!(self, Self::Decapsulate), rv);
        }
        if matches!(self, Self::Derive) {
            return derive_scope(rv);
        }
        if matches!(self, Self::Unwrap | Self::UnwrapAuthenticated) {
            return effect_unwrap_scope(rv);
        }
        match rv {
            CKR_OK
            | CKR_HOST_MEMORY
            | CKR_DEVICE_MEMORY
            | CKR_FUNCTION_FAILED
            | CKR_FUNCTION_NOT_SUPPORTED
            | CKR_SESSION_READ_ONLY
            | CKR_TOKEN_WRITE_PROTECTED
            | CKR_USER_NOT_LOGGED_IN
            | CKR_PIN_EXPIRED => FailureScope::None,
            CKR_SESSION_CLOSED | CKR_SESSION_HANDLE_INVALID | CKR_OPERATION_ACTIVE => {
                FailureScope::Session
            }
            CKR_DEVICE_ERROR
            | CKR_DEVICE_REMOVED
            | CKR_TOKEN_NOT_PRESENT
            | CKR_FIPS_SELF_TEST_FAILED => FailureScope::Token,
            CKR_ARGUMENTS_BAD
            | CKR_ATTRIBUTE_READ_ONLY
            | CKR_ATTRIBUTE_TYPE_INVALID
            | CKR_ATTRIBUTE_VALUE_INVALID
            | CKR_TEMPLATE_INCONSISTENT
                if !matches!(self, Self::Destroy) =>
            {
                FailureScope::None
            }
            CKR_TEMPLATE_INCOMPLETE
            | CKR_CURVE_NOT_SUPPORTED
            | CKR_DOMAIN_PARAMS_INVALID
            | CKR_PARAMETER_SET_NOT_SUPPORTED
                if matches!(self, Self::Create | Self::GeneratePair) =>
            {
                FailureScope::None
            }
            CKR_TEMPLATE_INCOMPLETE | CKR_CURVE_NOT_SUPPORTED
                if matches!(self, Self::GenerateKey) =>
            {
                FailureScope::None
            }
            CKR_ACTION_PROHIBITED | CKR_OBJECT_HANDLE_INVALID
                if matches!(self, Self::Copy | Self::Set | Self::Destroy) =>
            {
                FailureScope::None
            }
            CKR_FUNCTION_CANCELED | CKR_MECHANISM_INVALID | CKR_MECHANISM_PARAM_INVALID
                if matches!(self, Self::GeneratePair | Self::GenerateKey) =>
            {
                FailureScope::None
            }
            _ => FailureScope::Module,
        }
    }
    // No error output handle is used. Only a function-specific non-creation
    // guarantee may release the local destination ticket, never an unknown effect.
    pub fn non_creation(self, rv: CK_RV) -> bool {
        if effect_uncertain(rv) {
            return false;
        }
        if matches!(self, Self::Encapsulate | Self::Decapsulate) {
            // §5.18.8/9 explicitly guarantee no new object when the exact
            // supplied template is refused. Do not infer this for unknown errors.
            return matches!(
                rv,
                CKR_ATTRIBUTE_READ_ONLY
                    | CKR_ATTRIBUTE_TYPE_INVALID
                    | CKR_ATTRIBUTE_VALUE_INVALID
                    | CKR_TEMPLATE_INCOMPLETE
                    | CKR_TEMPLATE_INCONSISTENT
            );
        }
        if matches!(self, Self::Unwrap | Self::UnwrapAuthenticated) {
            // PKCS11 3.2 section5 and5.18: scope and non-creation are independent.
            // The CKR_FIPS_SELF_TEST_FAILED exception withdraws the token without proving absence.
            return rv != CKR_OK
                && matches!(
                    effect_unwrap_scope(rv),
                    FailureScope::None | FailureScope::Session
                );
        }
        if rv == CKR_OK || self.effect_scope(rv) != FailureScope::None {
            return false;
        }
        match self {
            Self::GeneratePair | Self::GenerateKey => true,
            // §5.7.2: CKA_COPYABLE=false forbids the action itself. There is
            // no new copy to retain; this says nothing about mutable aliases.
            Self::Copy if rv == CKR_ACTION_PROHIBITED => true,
            Self::Create | Self::Copy | Self::Derive => matches!(
                rv,
                CKR_ATTRIBUTE_READ_ONLY
                    | CKR_ATTRIBUTE_TYPE_INVALID
                    | CKR_ATTRIBUTE_VALUE_INVALID
                    | CKR_TEMPLATE_INCOMPLETE
                    | CKR_TEMPLATE_INCONSISTENT
            ),
            Self::Set | Self::Destroy => false,
            Self::Unwrap | Self::UnwrapAuthenticated | Self::Encapsulate | Self::Decapsulate => {
                unreachable!()
            }
        }
    }
}

// §5.18.8/9: KEM creates an object without an Init/Final sequence. Keep native
// cryptographic refusals distinct from operational failure and unknown effects.
fn kem_scope(decapsulate: bool, rv: CK_RV) -> FailureScope {
    match rv {
        CKR_OK
        | CKR_ARGUMENTS_BAD
        | CKR_ATTRIBUTE_READ_ONLY
        | CKR_ATTRIBUTE_TYPE_INVALID
        | CKR_ATTRIBUTE_VALUE_INVALID
        | CKR_BUFFER_TOO_SMALL
        | CKR_CURVE_NOT_SUPPORTED
        | CKR_DEVICE_MEMORY
        | CKR_DOMAIN_PARAMS_INVALID
        | CKR_FUNCTION_CANCELED
        | CKR_FUNCTION_FAILED
        | CKR_FUNCTION_NOT_SUPPORTED
        | CKR_HOST_MEMORY
        | CKR_MECHANISM_INVALID
        | CKR_MECHANISM_PARAM_INVALID
        | CKR_PARAMETER_SET_NOT_SUPPORTED
        | CKR_PIN_EXPIRED
        | CKR_SESSION_READ_ONLY
        | CKR_TEMPLATE_INCOMPLETE
        | CKR_TEMPLATE_INCONSISTENT
        | CKR_TOKEN_WRITE_PROTECTED
        | CKR_USER_NOT_LOGGED_IN => FailureScope::None,
        CKR_KEY_HANDLE_INVALID | CKR_KEY_SIZE_RANGE | CKR_KEY_TYPE_INCONSISTENT if !decapsulate => {
            FailureScope::None
        }
        CKR_UNWRAPPING_KEY_HANDLE_INVALID
        | CKR_UNWRAPPING_KEY_SIZE_RANGE
        | CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT
        | CKR_WRAPPED_KEY_INVALID
        | CKR_WRAPPED_KEY_LEN_RANGE
            if decapsulate =>
        {
            FailureScope::None
        }
        CKR_SESSION_CLOSED | CKR_SESSION_HANDLE_INVALID | CKR_OPERATION_ACTIVE => {
            FailureScope::Session
        }
        CKR_DEVICE_ERROR
        | CKR_DEVICE_REMOVED
        | CKR_TOKEN_NOT_PRESENT
        | CKR_FIPS_SELF_TEST_FAILED => FailureScope::Token,
        _ => FailureScope::Module,
    }
}

// Slot discovery and initialization have no session sequence. Function names
// are the standard ABI owners, never provider selectors.
pub(crate) fn slot_scope(function: &str, rv: CK_RV) -> FailureScope {
    let _ = function;
    native_context_scope(rv)
}

fn standard_return(rv: CK_RV) -> bool {
    matches!(
        rv,
        CKR_OK
            | CKR_CANCEL
            | CKR_HOST_MEMORY
            | CKR_SLOT_ID_INVALID
            | CKR_GENERAL_ERROR
            | CKR_FUNCTION_FAILED
            | CKR_ARGUMENTS_BAD
            | CKR_NO_EVENT
            | CKR_NEED_TO_CREATE_THREADS
            | CKR_CANT_LOCK
            | CKR_ATTRIBUTE_READ_ONLY
            | CKR_ATTRIBUTE_SENSITIVE
            | CKR_ATTRIBUTE_TYPE_INVALID
            | CKR_ATTRIBUTE_VALUE_INVALID
            | CKR_ACTION_PROHIBITED
            | CKR_DATA_INVALID
            | CKR_DATA_LEN_RANGE
            | CKR_DEVICE_ERROR
            | CKR_DEVICE_MEMORY
            | CKR_DEVICE_REMOVED
            | CKR_ENCRYPTED_DATA_INVALID
            | CKR_ENCRYPTED_DATA_LEN_RANGE
            | CKR_AEAD_DECRYPT_FAILED
            | CKR_FUNCTION_CANCELED
            | CKR_FUNCTION_NOT_PARALLEL
            | CKR_FUNCTION_NOT_SUPPORTED
            | CKR_KEY_HANDLE_INVALID
            | CKR_KEY_SIZE_RANGE
            | CKR_KEY_TYPE_INCONSISTENT
            | CKR_KEY_NOT_NEEDED
            | CKR_KEY_CHANGED
            | CKR_KEY_NEEDED
            | CKR_KEY_INDIGESTIBLE
            | CKR_KEY_FUNCTION_NOT_PERMITTED
            | CKR_KEY_NOT_WRAPPABLE
            | CKR_KEY_UNEXTRACTABLE
            | CKR_MECHANISM_INVALID
            | CKR_MECHANISM_PARAM_INVALID
            | CKR_OBJECT_HANDLE_INVALID
            | CKR_OPERATION_ACTIVE
            | CKR_OPERATION_NOT_INITIALIZED
            | CKR_PIN_INCORRECT
            | CKR_PIN_INVALID
            | CKR_PIN_LEN_RANGE
            | CKR_PIN_EXPIRED
            | CKR_PIN_LOCKED
            | CKR_SESSION_CLOSED
            | CKR_SESSION_COUNT
            | CKR_SESSION_HANDLE_INVALID
            | CKR_SESSION_PARALLEL_NOT_SUPPORTED
            | CKR_SESSION_READ_ONLY
            | CKR_SESSION_EXISTS
            | CKR_SESSION_READ_ONLY_EXISTS
            | CKR_SESSION_READ_WRITE_SO_EXISTS
            | CKR_SIGNATURE_INVALID
            | CKR_SIGNATURE_LEN_RANGE
            | CKR_TEMPLATE_INCOMPLETE
            | CKR_TEMPLATE_INCONSISTENT
            | CKR_TOKEN_NOT_PRESENT
            | CKR_TOKEN_NOT_RECOGNIZED
            | CKR_TOKEN_WRITE_PROTECTED
            | CKR_UNWRAPPING_KEY_HANDLE_INVALID
            | CKR_UNWRAPPING_KEY_SIZE_RANGE
            | CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT
            | CKR_USER_ALREADY_LOGGED_IN
            | CKR_USER_NOT_LOGGED_IN
            | CKR_USER_PIN_NOT_INITIALIZED
            | CKR_USER_TYPE_INVALID
            | CKR_USER_ANOTHER_ALREADY_LOGGED_IN
            | CKR_USER_TOO_MANY_TYPES
            | CKR_WRAPPED_KEY_INVALID
            | CKR_WRAPPED_KEY_LEN_RANGE
            | CKR_WRAPPING_KEY_HANDLE_INVALID
            | CKR_WRAPPING_KEY_SIZE_RANGE
            | CKR_WRAPPING_KEY_TYPE_INCONSISTENT
            | CKR_RANDOM_SEED_NOT_SUPPORTED
            | CKR_RANDOM_NO_RNG
            | CKR_DOMAIN_PARAMS_INVALID
            | CKR_CURVE_NOT_SUPPORTED
            | CKR_BUFFER_TOO_SMALL
            | CKR_SAVED_STATE_INVALID
            | CKR_INFORMATION_SENSITIVE
            | CKR_STATE_UNSAVEABLE
            | CKR_CRYPTOKI_NOT_INITIALIZED
            | CKR_CRYPTOKI_ALREADY_INITIALIZED
            | CKR_MUTEX_BAD
            | CKR_MUTEX_NOT_LOCKED
            | CKR_NEW_PIN_MODE
            | CKR_NEXT_OTP
            | CKR_EXCEEDED_MAX_ITERATIONS
            | CKR_FIPS_SELF_TEST_FAILED
            | CKR_LIBRARY_LOAD_FAILED
            | CKR_PIN_TOO_WEAK
            | CKR_PUBLIC_KEY_INVALID
            | CKR_FUNCTION_REJECTED
            | CKR_TOKEN_RESOURCE_EXCEEDED
            | CKR_OPERATION_CANCEL_FAILED
            | CKR_KEY_EXHAUSTED
            | CKR_PENDING
            | CKR_SESSION_ASYNC_NOT_SUPPORTED
            | CKR_SEED_RANDOM_REQUIRED
            | CKR_OPERATION_NOT_VALIDATED
            | CKR_TOKEN_NOT_INITIALIZED
            | CKR_PARAMETER_SET_NOT_SUPPORTED
    )
}

// PKCS#11 unwrap return classification. PENDING remains uncertain for both routes, even
// though only the classical function lists it. No off-list cryptographic code
// is normalized into a benign wrapped-key error.
fn effect_unwrap_scope(rv: CK_RV) -> FailureScope {
    match rv {
        CKR_OK
        | CKR_ARGUMENTS_BAD
        | CKR_ATTRIBUTE_READ_ONLY
        | CKR_ATTRIBUTE_TYPE_INVALID
        | CKR_ATTRIBUTE_VALUE_INVALID
        | CKR_BUFFER_TOO_SMALL
        | CKR_CURVE_NOT_SUPPORTED
        | CKR_DEVICE_MEMORY
        | CKR_DOMAIN_PARAMS_INVALID
        | CKR_FUNCTION_CANCELED
        | CKR_FUNCTION_FAILED
        | CKR_FUNCTION_NOT_SUPPORTED
        | CKR_HOST_MEMORY
        | CKR_MECHANISM_INVALID
        | CKR_MECHANISM_PARAM_INVALID
        | CKR_PARAMETER_SET_NOT_SUPPORTED
        | CKR_PIN_EXPIRED
        | CKR_SESSION_READ_ONLY
        | CKR_TEMPLATE_INCOMPLETE
        | CKR_TEMPLATE_INCONSISTENT
        | CKR_TOKEN_WRITE_PROTECTED
        | CKR_UNWRAPPING_KEY_HANDLE_INVALID
        | CKR_UNWRAPPING_KEY_SIZE_RANGE
        | CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT
        | CKR_USER_NOT_LOGGED_IN
        | CKR_WRAPPED_KEY_INVALID
        | CKR_WRAPPED_KEY_LEN_RANGE
        | CKR_OPERATION_NOT_VALIDATED => FailureScope::None,
        CKR_OPERATION_ACTIVE | CKR_SESSION_CLOSED | CKR_SESSION_HANDLE_INVALID => {
            FailureScope::Session
        }
        CKR_DEVICE_ERROR | CKR_DEVICE_REMOVED | CKR_FIPS_SELF_TEST_FAILED => FailureScope::Token,
        _ => FailureScope::Module,
    }
}

fn derive_scope(rv: CK_RV) -> FailureScope {
    match rv {
        CKR_OK
        | CKR_ATTRIBUTE_READ_ONLY
        | CKR_ATTRIBUTE_TYPE_INVALID
        | CKR_ATTRIBUTE_VALUE_INVALID
        | CKR_TEMPLATE_INCOMPLETE
        | CKR_TEMPLATE_INCONSISTENT
        | CKR_ARGUMENTS_BAD
        | CKR_CURVE_NOT_SUPPORTED
        | CKR_DOMAIN_PARAMS_INVALID
        | CKR_FUNCTION_CANCELED
        | CKR_FUNCTION_FAILED
        | CKR_FUNCTION_NOT_SUPPORTED
        | CKR_HOST_MEMORY
        | CKR_DEVICE_MEMORY
        | CKR_KEY_HANDLE_INVALID
        | CKR_KEY_SIZE_RANGE
        | CKR_KEY_TYPE_INCONSISTENT
        | CKR_MECHANISM_INVALID
        | CKR_MECHANISM_PARAM_INVALID
        | CKR_PIN_EXPIRED
        | CKR_SESSION_READ_ONLY
        | CKR_TOKEN_WRITE_PROTECTED
        | CKR_USER_NOT_LOGGED_IN => FailureScope::None,
        CKR_OPERATION_ACTIVE | CKR_SESSION_CLOSED | CKR_SESSION_HANDLE_INVALID => {
            FailureScope::Session
        }
        CKR_DEVICE_ERROR
        | CKR_DEVICE_REMOVED
        | CKR_TOKEN_NOT_PRESENT
        | CKR_FIPS_SELF_TEST_FAILED => FailureScope::Token,
        _ => FailureScope::Module,
    }
}
