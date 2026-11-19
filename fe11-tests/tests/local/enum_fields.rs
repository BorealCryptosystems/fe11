// SPDX-License-Identifier: Apache-2.0
//! Typed pattern contracts grouped by the public enum they describe.

// Each field keeps its distinct expected value across construction and matching.
macro_rules! roundtrip_fields {
    ($owner:ident :: $variant:ident { $($field:ident),+ }) => {{
        let input = $owner::$variant { $($field: $field.clone()),+ };
        let returned = match input {
            $owner::$variant { $($field),+ } => ($($field,)+),
            _ => panic!(concat!("expected ", stringify!($owner), "::", stringify!($variant))),
        };
        assert_eq!(returned, ($($field,)+));
    }};
}

#[path = "enum_fields/aead_nonce_through_generation_invocation.rs"]
mod aead_nonce_through_generation_invocation;
#[path = "enum_fields/hash_provenance_through_state_capture_progress.rs"]
mod hash_provenance_through_state_capture_progress;
#[path = "enum_fields/state_key_encoding_through_wrap_parameters.rs"]
mod state_key_encoding_through_wrap_parameters;
