A Rust PKCS#11 interface with owned native resources.

Fe11 loads an application-selected native module and exposes sessions, objects,
cryptographic operations and their retained memory through Rust owners.
The application chooses mechanisms, keys, parameters and policy. Fe11 manages
their interface representation and preserves native results.

This is an initial community release.

# Runtime and ownership

The application establishes trust in the native implementation and loader
configuration. Other processes can use the same token. In-process clients share
an initialization through [`ModuleBuilder::open_shared`] and [`RuntimeOwner`],
using distinct sessions. Foreign native libraries participate through the
documented unsafe coordination contract.

Object references retain their native identity behind the Rust API. A single
module owner carries lifecycle authority. [`Module::close`] and
[`Session::close`] expose teardown results. Uncertain native execution keeps its
memory owners retained until completion is established.

Observations describe state at the time of their native read. Recovery explicitly
selects a new session or runtime generation. A reference remains bound to its
original generation throughout that process.

# Cryptographic operations and private material

Typed session methods select mechanisms and parameters for digest, signature,
verification, encryption, decryption, generation, derivation and key transport.
Advanced owners supply caller-driven streams, native messages and continuation.

[`Session::export_pqc_private_key`] reads the selected ML-DSA/ML-KEM private
representation when native policy permits it. The caller supplies a managed
reference, [`PqcPrivateEncoding`] and [`ObjectAdmission`]. Complete successful
reads publish a [`PqcPrivateExport`] owning erasable storage. Refused or partial
reads preserve the failure without publishing private output.

Secret PIN storage and private exports have restricted formatting and duplication
interfaces. The ownership guide specifies those guarantees. Applications manage
any copies they create outside these owners.

# Software verification

[`VerifyEngine`] selects an optional software component for public-key signature
verification and hashing. [`VerifyEngineInfo`] describes its image, version and
service observations. Native PKCS#11 operations use the selected native module;
explicit software-verification operations use the selected component.
