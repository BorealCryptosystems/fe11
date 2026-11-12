// SPDX-License-Identifier: Apache-2.0
//! Composition using storage reserved before native dispatch.
use super::{CompletionDiagnostic, Error, FailurePair, NativeOutputSize, Result};

impl CompletionDiagnostic {
    /// Retain an output observation and its independent local failure in the
    /// completion leaf. The later cleanup stage keeps both of its own leaves.
    pub(crate) fn output_failure(
        mut self,
        code: fe11_sys::CK_RV,
        reported: u64,
        limit: usize,
        cause: Error,
    ) -> Error {
        *self.cause = cause;
        Error::NativeOutputAndLocalFailure {
            size: NativeOutputSize {
                function: self.function,
                code: code as u64,
                reported,
                limit,
            },
            cause: self.cause,
        }
    }

    /// Output-bearing failures retain the defined scalar as well as the
    /// independent local cause. An absent observation never fabricates a size.
    pub(crate) fn boundary_with_output(
        self,
        code: fe11_sys::CK_RV,
        size: Option<NativeOutputSize>,
        cause: Error,
    ) -> Error {
        match size {
            Some(size) => self.output_failure(code, size.reported, size.limit, cause),
            None => self.boundary_failure(code, cause),
        }
    }

    /// Report a violated memory boundary without claiming a completed operation.
    /// The leaf was reserved before dispatch; a simultaneous native refusal is
    /// preserved without allocating in the return path.
    pub(crate) fn boundary_failure(mut self, code: fe11_sys::CK_RV, cause: Error) -> Error {
        if code == fe11_sys::CKR_OK {
            return cause;
        }
        *self.cause = cause;
        Error::NativeAndLocalFailure {
            function: self.function,
            code: code as u64,
            cause: self.cause,
        }
    }

    /// Reuse two unconsumed completion leaves for a local abort that prevents
    /// both native completion and publication. The enclosing owner retains
    /// their credits; this conversion neither allocates nor changes a cause.
    pub(crate) fn pair_with(self, secondary: Self) -> FailurePair {
        FailurePair {
            operation: self.cause,
            cleanup: secondary.cause,
        }
    }

    pub(crate) fn finish<T>(mut self, result: Result<T>) -> Result<T> {
        result.map_err(|cause| {
            *self.cause = cause;
            Error::OperationCompleted {
                function: self.function,
                cause: self.cause,
            }
        })
    }
    // Reuse storage reserved before dispatch for two simultaneous failures.
    // CKR_OK retains the existing, explicit OperationCompleted contract.
    pub(crate) fn finish_native<T>(
        mut self,
        code: fe11_sys::CK_RV,
        result: Result<T>,
    ) -> Result<T> {
        if code == fe11_sys::CKR_OK {
            return self.finish(result);
        }
        result.map_err(|cause| {
            *self.cause = cause;
            Error::NativeAndLocalFailure {
                function: self.function,
                code: code as u64,
                cause: self.cause,
            }
        })
    }
}
