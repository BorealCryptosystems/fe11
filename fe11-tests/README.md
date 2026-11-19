# Fe11 public test suite

This package exercises the public Rust API of Fe11 0.1.1 and its interoperability
with SoftHSM. From the workspace, run the local contracts with `cargo test --locked -p fe11-tests --test local`. Rust 1.81 is the
minimum supported toolchain. In an extracted test package, first run
`cargo generate-lockfile` to resolve the matching released library, then use the
same locked command. Native cases use a Linux worker and disposable tokens.

The [suite guide](tests/README.md) describes native prerequisites, offline fixture
extraction, the scenario catalogue, public reference vectors and result records.
