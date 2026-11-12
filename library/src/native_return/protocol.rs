// SPDX-License-Identifier: Apache-2.0
//! Order native context observation, borrowed-memory inspection and projection.
//!
//! This module never owns a native operand or releases one. The dispatch owner
//! keeps its guards and storage while supplying the inspection closure. A return
//! of memory permits that inspection; it does not prove sequence termination.
use super::sequence::{self, Completion, OutputRequest};
use super::{native_context_scope, FailureScope};
use crate::{Error, Result};
use fe11_sys::CK_RV;

/// The physical control and the operation whose result it reports are distinct.
/// For ordinary calls both names are identical. AsyncComplete reports its target's
/// code, while accounting still belongs to the physical C_AsyncComplete call.
#[derive(Clone, Copy)]
pub(crate) struct ReturnCode {
    function: Function,
    code: CK_RV,
}

#[derive(Clone, Copy)]
enum Function {
    Direct(&'static str),
    // The physical call is C_AsyncComplete, recorded by its dispatch owner.
    // Its return code is classified and diagnosed against this target.
    AsyncCompletion { target: &'static str },
}

impl ReturnCode {
    pub(crate) fn function(self) -> &'static str {
        match self.function {
            Function::Direct(function) => function,
            Function::AsyncCompletion { target } => target,
        }
    }

    pub(crate) fn code(self) -> CK_RV {
        self.code
    }

    pub(crate) fn memory_returned(self) -> bool {
        match self.function {
            Function::Direct(_) => super::call_memory_returned(self.code),
            Function::AsyncCompletion { .. } => super::async_memory_returned(self.code as u64),
        }
    }

    fn context_scope(self) -> FailureScope {
        if !self.memory_returned() {
            FailureScope::Module
        } else {
            native_context_scope(self.code)
        }
    }

    /// The length slot of a direct output call is defined on BUFFER_TOO_SMALL.
    /// AsyncComplete has a different result descriptor; do not reuse the old
    /// direct-call slot as evidence of a newly requested capacity.
    pub(crate) fn direct_output_size(
        self,
        capacity: usize,
        read: impl FnOnce() -> fe11_sys::CK_ULONG,
    ) -> Option<crate::NativeOutputSize> {
        match self.function {
            Function::Direct(function) => {
                crate::NativeOutputSize::buffer_refusal(function, self.code, capacity, read)
            }
            Function::AsyncCompletion { .. } => None,
        }
    }

    pub(crate) fn check(self, may_have_effect: bool) -> Result<()> {
        crate::error::check(
            self.code,
            self.function(),
            may_have_effect || super::effect_uncertain(self.code),
        )
    }
}

/// Context has been notified, but native-addressable fields cannot yet be read
/// by a projection. Inspection is invoked only through this consumed value.
pub(crate) struct PendingInspection(ReturnCode);

impl PendingInspection {
    /// Continue inspecting the target's own graph after its control frame has
    /// been inspected. The token carries the already observed native return;
    /// forwarding it must not withdraw the same context a second time.
    pub(crate) fn forwarded(result: ReturnCode) -> Self {
        Self(result)
    }

    pub(crate) fn code(&self) -> CK_RV {
        self.0.code()
    }

    pub(crate) fn function(&self) -> &'static str {
        self.0.function()
    }

    pub(crate) fn direct_output_size(
        &self,
        capacity: usize,
        read: impl FnOnce() -> fe11_sys::CK_ULONG,
    ) -> Option<crate::NativeOutputSize> {
        self.0.direct_output_size(capacity, read)
    }

    pub(crate) fn returned(
        function: &'static str,
        code: CK_RV,
        observe: impl FnOnce(FailureScope),
    ) -> Self {
        Self::observe(Function::Direct(function), code, observe)
    }

    pub(crate) fn completed(
        target: &'static str,
        code: CK_RV,
        observe: impl FnOnce(FailureScope),
    ) -> Self {
        Self::observe(Function::AsyncCompletion { target }, code, observe)
    }

    fn observe(function: Function, code: CK_RV, observe: impl FnOnce(FailureScope)) -> Self {
        let result = ReturnCode { function, code };
        observe(result.context_scope());
        Self(result)
    }

    /// Inspect a mutation's immutable inputs after context observation. Outputs
    /// remain the owner's responsibility and must only be read on defined codes.
    pub(crate) fn inspect_inputs(self, inspect: impl FnOnce() -> bool) -> InputInspection {
        let boundary = if self.0.memory_returned() {
            if inspect() {
                InputBoundary::Verified
            } else {
                InputBoundary::Violated
            }
        } else {
            InputBoundary::Unavailable
        };
        InputInspection {
            result: self.0,
            boundary,
        }
    }

    /// Inspect immutable descriptors and witnesses, plus only those output fields
    /// the exact function permits on this code. Do not call native code here.
    pub(crate) fn inspect(self, inspect: impl FnOnce() -> Result<()>) -> InspectedReturn {
        let boundary = if self.0.memory_returned() {
            match inspect() {
                Ok(()) => Boundary::Verified,
                Err(cause) => Boundary::Invalid(cause),
            }
        } else {
            Boundary::Unavailable
        };
        InspectedReturn {
            result: self.0,
            boundary,
        }
    }
}

/// Input integrity and return of memory do not establish absence of objects.
/// A violated boundary overrides even a function-specific non-creation code.
pub(crate) struct InputInspection {
    result: ReturnCode,
    boundary: InputBoundary,
}

enum InputBoundary {
    Unavailable,
    Verified,
    Violated,
}

/// Mechanism contracts which differ from ordinary one-object creation.
pub(crate) enum CreationContract {
    Function(super::MutationCall),
    /// Ordinary SSL/TLS/WTLS key-material failure creates no keys, with intact inputs.
    KeyMaterial,
    /// PRF or KEA random output: no object output exists in this invocation.
    NoObjects,
}

impl InputInspection {
    pub(crate) fn memory_returned(&self) -> bool {
        !matches!(self.boundary, InputBoundary::Unavailable)
    }

    /// False also covers unavailable memory; it is not an integrity proof.
    pub(crate) fn violated(&self) -> bool {
        matches!(self.boundary, InputBoundary::Violated)
    }

    pub(crate) fn no_objects(&self, contract: CreationContract) -> bool {
        if !matches!(self.boundary, InputBoundary::Verified) {
            return false;
        }
        match contract {
            CreationContract::Function(call) => call.non_creation(self.result.code()),
            CreationContract::KeyMaterial => {
                // Returned memory does not prove absence of native effects.
                // Preserve the shared uncertainty classification, including
                // GENERAL_ERROR and errors which can take precedence over it.
                // SSL/TLS/WTLS explicitly create no keys on ordinary failure:
                // DEVICE_ERROR retains that guarantee, not context validity.
                let code = self.result.code();
                code != fe11_sys::CKR_OK
                    && (!super::effect_uncertain(code) || code == fe11_sys::CKR_DEVICE_ERROR)
            }
            CreationContract::NoObjects => true,
        }
    }

    /// Preserve the family's effect flag; no-object operations are not creation.
    pub(crate) fn check(&self, may_have_effect: bool) -> Result<()> {
        crate::error::check(self.result.code(), self.result.function(), may_have_effect)
    }
}

enum Boundary {
    Unavailable,
    Verified,
    Invalid(Error),
}

#[derive(Clone, Copy)]
pub(crate) enum SequencePhase {
    Initialize,
    Continue(OutputRequest),
}

pub(crate) struct InspectedReturn {
    result: ReturnCode,
    boundary: Boundary,
}

impl InspectedReturn {
    /// The caller supplied a non-NULL Init. This retires only its refused
    /// attempt, never a pre-existing native sequence or another owner's loan.
    pub(crate) fn initialization_refused(&self, version: (u8, u8), phase: SequencePhase) -> bool {
        matches!(phase, SequencePhase::Initialize)
            && matches!(self.boundary, Boundary::Verified)
            && matches!(self.result.function, Function::Direct(_))
            && sequence::initialization_refused(version, self.result.function(), self.result.code())
    }

    /// A violated or unavailable boundary overrides any ordinary termination
    /// rule. The owner applies this fact without releasing other outstanding loans.
    pub(crate) fn completion(&self, version: (u8, u8), phase: SequencePhase) -> Completion {
        if !matches!(self.boundary, Boundary::Verified) {
            return Completion::Uncertain;
        }
        match phase {
            SequencePhase::Initialize => {
                sequence::init(version, self.result.function(), self.result.code())
            }
            SequencePhase::Continue(output) => {
                sequence::returned(version, self.result.function(), output, self.result.code())
            }
        }
    }

    /// Supply the owner's prepaid native/local diagnostic only on a violation.
    /// The unavailable case preserves its raw error and must remain retained by
    /// the owner. It is not converted into a verified memory return.
    pub(crate) fn resolve(
        self,
        invalid: impl FnOnce(ReturnCode, Error) -> Error,
    ) -> Result<ReturnCode> {
        match self.boundary {
            Boundary::Invalid(cause) => Err(invalid(self.result, cause)),
            Boundary::Verified | Boundary::Unavailable => Ok(self.result),
        }
    }
}
