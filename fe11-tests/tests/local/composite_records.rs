// SPDX-License-Identifier: Apache-2.0
//! Public value contracts; each case varies one field and keeps its siblings fixed.

macro_rules! check_field {
    ($base:expr, $field:ident, $ty:ty, [$($value:expr),+ $(,)?]) => {{
        let inputs: &[$ty] = &[$($value),+];
        for expected in inputs {
            let mut record = $base;
            record.$field = expected.clone();
            assert_eq!(&record.$field, expected);
        }
    }};
}

#[path = "composite_records/attribute_read_plan_through_native_skipjack_private.rs"]
mod attribute_read_plan_through_native_skipjack_private;
#[path = "composite_records/native_skipjack_relay_through_windows_loader_requests.rs"]
mod native_skipjack_relay_through_windows_loader_requests;
