// SPDX-License-Identifier: Apache-2.0
//! Reconcile concluded observations without lending them to newer snapshots.

use super::*;

pub(crate) fn withdraw(
    registry: &mut crate::module::TokenRegistry,
    revision: &mut u64,
    observed: &[Arc<TokenSnapshot>],
    epochs: &[u64],
    contradicted: impl Fn(&TokenSnapshot) -> bool,
) -> Result<()> {
    let changed = registry.revision != *revision
        || registry.tokens.len() != observed.len()
        || !registry
            .tokens
            .iter()
            .zip(observed)
            .all(|(a, b)| Arc::ptr_eq(a, b));
    if observed.len() != epochs.len() {
        return Err(stale_observation());
    }
    let exact = |old: &Arc<TokenSnapshot>| registry.tokens.iter().any(|t| Arc::ptr_eq(t, old));
    let withdrawing = observed
        .iter()
        .any(|old| exact(old) && old.admission_available() && contradicted(old));
    if withdrawing {
        // Another slot's discovery failure may have advanced the registry.
        // Withdraw only the still-published captured objects, never replacements.
        // Even exhausted revision capacity cannot keep a contradiction usable.
        for (old, epoch) in observed.iter().zip(epochs) {
            if exact(old) && contradicted(old) {
                old.withdraw_admission(*epoch);
            }
        }
        registry.advance()?;
    }
    if changed {
        // The exact contradictions remain withdrawn, but the old report is
        // insufficient authority to publish any successor into this registry.
        return Err(stale_observation());
    }
    *revision = registry.revision;
    Ok(())
}

fn stale_observation() -> Error {
    Error::Rejected(crate::RejectionReason::TokenAdministration(
        crate::TokenAdministrationRejection::TokenRegistryChangedAfterDiscovery,
    ))
}
