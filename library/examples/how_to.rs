// SPDX-License-Identifier: Apache-2.0
//! Documentation examples: compile with cargo check --example how_to.
//! Functions execute native operations only when called by an application.
#[path = "how_to/setup.rs"]
pub mod setup;
#[path = "how_to/operations.rs"]
pub mod operations;
#[path = "how_to/keys.rs"]
pub mod keys;
#[path = "how_to/lifecycle.rs"]
pub mod lifecycle;
#[path = "how_to/pqc.rs"]
pub mod pqc;
