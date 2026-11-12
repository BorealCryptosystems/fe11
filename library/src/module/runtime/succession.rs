// SPDX-License-Identifier: Apache-2.0
//! Explicit generation replacement; withdrawal never fabricates native cleanup.
use super::{Module, RuntimeOwner};
use crate::Result;
use std::sync::Arc;

pub(crate) struct SuccessorContext {
    pub(crate) image: crate::native::image_reservation::Successor,
    pub(crate) budget: Arc<crate::symmetric::memory::Budget>,
    pub(crate) sessions: Arc<crate::session_budget::SessionLedger>,
    pub(crate) generation: u64,
}

impl Module {
    /// Explicitly initialize the next generation of this same native image.
    /// Requires this owner to have recorded successful Finalize, a native
    /// NOT_INITIALIZED return, or a reset notification with the unsafe contract
    /// below. Pending execution/callbacks/waiters prevent replacement.
    ///
    /// Old references stay retired, with their retained credits. The byte limit
    /// must remain the same; session ceilings include retained predecessors.
    /// No Login, object rebinding, checkpoint import or operation replay occurs.
    pub fn successor(&self, builder: crate::ModuleBuilder) -> Result<Module> {
        self.successor_with(builder, None)
    }

    /// Attach the next generation already initialized by the application.
    /// This method issues no C_Initialize and adopts no old sessions.
    ///
    /// # Safety
    /// ExternalInitialization's contract must hold for the new generation at
    /// attachment and throughout its use. It must be quiescent, every foreign
    /// user must enroll, and existing foreign sessions must be registered before
    /// distributing clients. The retired generation's contract is not renewed.
    pub unsafe fn attach_successor(
        &self,
        builder: crate::ModuleBuilder,
        initialization: crate::ExternalInitialization,
    ) -> Result<Module> {
        self.successor_with(builder, Some(initialization))
    }

    fn successor_with(
        &self,
        builder: crate::ModuleBuilder,
        external: Option<crate::ExternalInitialization>,
    ) -> Result<Module> {
        self.require_lifecycle_owner()?;
        self.inner.check_lifecycle_reentry()?;
        let context = self.prepare_successor()?;
        let result = builder.open_successor(external, &context)?;
        self.inner.slot_events.commit_successor();
        Ok(result)
    }

    /// Notify this owner that its native initialization has been reset elsewhere.
    /// This only withdraws authority; it frees no buffers or credits and does
    /// not assert that Finalize was called by Fe11.
    ///
    /// # Safety
    /// The reset must concern this exact image and initialization, with its old
    /// state definitively lost. All in-process users must participate in the
    /// shared admission/ownership protocol. No unregistered execution, callback
    /// or hidden reinitialization may overlap subsequent successor creation.
    /// Retain all old referents; notification alone is not a release proof.
    pub unsafe fn notify_runtime_reset(&self) -> Result<()> {
        self.require_lifecycle_owner()?;
        self.inner.availability.retire_initialization();
        Ok(())
    }

    fn prepare_successor(&self) -> Result<SuccessorContext> {
        self.inner.state.begin_drain()?;
        // The existing drain destructor wakes waiters on every exit. Loss of
        // initialization remains permanent even when drain admission reopens.
        let _drain = super::super::ModuleDrain {
            inner: self.inner.clone(),
        };
        let closing = self.inner.state.reserve_close()?;
        let mut state = self.inner.state.write_closing(true, closing.as_ref())?;
        state.native.successor_ready()?;
        let mut callbacks = self.inner.foreign.seal_successor_callbacks()?;
        self.inner.foreign.successor_ready()?;
        let entries = state.session_ledger.finalization_candidates()?;
        for entry in &entries {
            super::super::validate_finalization_entry(&state, entry)?;
        }
        state.operations.finalization_ready(&entries)?;
        let generation = state.token_registry()?.next_generation;
        let mut sessions = state.session_ledger.seal_recovery(&entries)?;
        // Reserve B atomically before removing A's registration. The old image
        // and graphs remain strongly held; this is not a memory reclamation.
        let image = self.inner.slot_events.reserve_successor()?;
        sessions.commit();
        if let Some(callbacks) = &mut callbacks {
            callbacks.commit();
        }
        self.inner.availability.retire_initialization();
        for entry in &entries {
            entry.credit.retire_runtime()?;
        }
        // Drop the ledger seal before mutating State: it borrows the ledger in
        // State, but its committed admission remains permanently closed.
        drop(sessions);
        state.close_local();
        self.inner.context_wakes.notify();
        Ok(SuccessorContext {
            image,
            budget: self.inner.symmetric_budget.clone(),
            sessions: self.inner.session_ledger.clone(),
            generation,
        })
    }
}

impl RuntimeOwner {
    /// Replace this retired generation and split its successor into one owner
    /// and one ordinary client. This owner retains only the old generation.
    pub fn successor(&self, builder: crate::ModuleBuilder) -> Result<(RuntimeOwner, Module)> {
        RuntimeOwner::from_opened(self.module.successor(builder)?)
    }
    /// Attach and split the application's next initialization.
    ///
    /// # Safety
    /// The caller must satisfy [`Module::attach_successor`]'s contract for the
    /// new generation, including enrollment before distributing its client.
    pub unsafe fn attach_successor(
        &self,
        builder: crate::ModuleBuilder,
        initialization: crate::ExternalInitialization,
    ) -> Result<(RuntimeOwner, Module)> {
        // SAFETY: the caller supplies the same generation-specific contract.
        RuntimeOwner::from_opened(unsafe { self.module.attach_successor(builder, initialization)? })
    }
}
