// SPDX-License-Identifier: Apache-2.0
//! Fallible counter updates using the CAS API available on the minimum Rust version.
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// The decision may be evaluated again after contention or a spurious failure.
/// Keep it free of side effects: returning None refuses the observed value
/// without writing; success returns the previous value, not the replacement.
pub(crate) trait AtomicUpdate {
    type Value;

    fn update_checked(
        &self,
        set_order: Ordering,
        fetch_order: Ordering,
        decide: impl FnMut(Self::Value) -> Option<Self::Value>,
    ) -> Result<Self::Value, Self::Value>;
}

impl AtomicUpdate for AtomicU64 {
    type Value = u64;

    fn update_checked(
        &self,
        set_order: Ordering,
        fetch_order: Ordering,
        decide: impl FnMut(u64) -> Option<u64>,
    ) -> Result<u64, u64> {
        update(
            self.load(fetch_order),
            |current, next| self.compare_exchange_weak(current, next, set_order, fetch_order),
            decide,
        )
    }
}

impl AtomicUpdate for AtomicUsize {
    type Value = usize;

    fn update_checked(
        &self,
        set_order: Ordering,
        fetch_order: Ordering,
        decide: impl FnMut(usize) -> Option<usize>,
    ) -> Result<usize, usize> {
        update(
            self.load(fetch_order),
            |current, next| self.compare_exchange_weak(current, next, set_order, fetch_order),
            decide,
        )
    }
}

fn update<T: Copy>(
    mut current: T,
    mut compare: impl FnMut(T, T) -> Result<T, T>,
    mut decide: impl FnMut(T) -> Option<T>,
) -> Result<T, T> {
    loop {
        let Some(next) = decide(current) else {
            return Err(current);
        };
        match compare(current, next) {
            Ok(previous) => return Ok(previous),
            Err(observed) => current = observed,
        }
    }
}
