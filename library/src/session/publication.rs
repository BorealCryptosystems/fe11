// SPDX-License-Identifier: Apache-2.0
//! Publish native failure scopes before projecting session results.
//! Mutation, metadata and private-result paths preserve their distinct return contracts.

use super::*;

impl Session {
    /// Observe context once, before inspecting a returned input graph. The
    /// owner keeps its frame, creation ticket and diagnostics through projection.
    pub(crate) fn inspect_native_inputs(
        &self,
        state: &State,
        function: &'static str,
        rv: CK_RV,
        inspect: impl FnOnce() -> bool,
    ) -> crate::native_return::protocol::InputInspection {
        crate::native_return::protocol::PendingInspection::returned(function, rv, |scope| {
            if scope == crate::native_return::FailureScope::Session {
                self.poison(state);
            }
            state.apply_session_failure(&self.entry, rv, scope);
        })
        .inspect_inputs(inspect)
    }

    pub(crate) fn mutation_result(
        &self,
        s: &State,
        call: crate::native_return::MutationCall,
        rv: CK_RV,
    ) -> Result<()> {
        let scope = call.scope(rv);
        if scope == crate::native_return::FailureScope::Session {
            self.poison(s);
        }
        s.apply_session_failure(&self.entry, rv, scope);
        check(rv, call.function(), !call.definite_object_refusal(rv))
    }

    // A completed output is a historical result, not a promise that the context
    // remains usable. Subsequent calls validate their own native owners.
    pub(crate) fn public_result<T>(&self, s: &State, result: Result<T>) -> Result<T> {
        self.metadata_result(s, None, result)
    }

    // Do not erase an already completed result when a peer withdraws the local
    // context. Observation owners check their selected consistency requirements
    // while collecting values; mutation owners retain their separate receipts.
    pub(crate) fn metadata_result<T>(
        &self,
        _s: &State,
        _stamp: Option<u64>,
        result: Result<T>,
    ) -> Result<T> {
        match result {
            Err(error) => {
                self.observe_authentication_error(&error);
                Err(error)
            }
            Ok(value) => Ok(value),
        }
    }

    // The sequence already returned: a later login change neither revokes its
    // completed output nor supplies proof about the next native operation.
    pub(crate) fn private_result<T>(
        &self,
        _s: &State,
        _stamp: u64,
        result: Result<T>,
    ) -> Result<T> {
        match result {
            Err(error) => {
                self.observe_authentication_error(&error);
                Err(error)
            }
            Ok(value) => Ok(value),
        }
    }
}
