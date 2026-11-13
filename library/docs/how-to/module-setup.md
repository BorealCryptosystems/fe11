# Load a module and select a token

Use an absolute path to a PKCS#11 module trusted by the application. Its bitness,
calling convention and PKCS#11 layout must match the selected target. Keep the
module's dependent libraries under the same loader trust policy.

The complete setup below takes application resource budgets. `ModuleIntegrity`
can request a SHA-256 comparison with `ModuleDigestMismatch::Refuse`; obtain the
expected digest from your authenticated deployment manifest. The integrity choice
describes the file check; native loading remains a trust boundary.

`ProviderDefault` selects the module's default interface. Applications requiring
PKCS#11 3.2, including ML-KEM, can select
`InterfaceSelection::Standard { version: (3, 2), required_flags: 0 }` explicitly
before opening. `Concurrent` requests native OS locking. Select the appropriate
initialization contract for the provider and other participants in the process.

The Edwards OID/raw-point/field-bit and ChaCha bit-length choices below are
explicit representation settings. If your deployment requires another supported
representation, select it before opening the module.

```rust,no_run
// SPDX-License-Identifier: Apache-2.0
use fe11::*;
use std::path::PathBuf;

/// Application-selected resource budgets for the example configuration.
pub struct Budgets {
    pub slots: usize,
    pub mechanisms: usize,
    pub discovery_attempts: usize,
    pub interfaces: usize,
    pub sessions: usize,
    pub read_write_sessions: usize,
    pub input_parts: usize,
    pub input_bytes: usize,
    pub owned_buffer_bytes: usize,
}

/// Configure explicit native loading, resource and representation choices.
pub fn open_module(path: PathBuf, integrity: ModuleIntegrity, b: Budgets) -> Result<Module> {
    let config = ModuleConfig {
        path,
        integrity,
        limits: Limits {
            slots: b.slots,
            mechanisms: b.mechanisms,
            discovery_attempts: b.discovery_attempts,
            sessions: b.sessions,
        },
    };
    let options = ModuleOptions {
        discovery: DiscoverySelection::AllPresentSlots,
        initialization: InitializationOptions {
            cannot_create_os_threads: false,
            concurrency: NativeConcurrency::Concurrent,
        },
        interface_discovery: InterfaceDiscoveryLimits {
            interfaces: b.interfaces,
            attempts: b.discovery_attempts,
        },
        object_limits: ObjectLimits {
            object_references: None,
            managed_references: None,
            destination_reservations: None,
        },
        interface: InterfaceSelection::ProviderDefault,
        crypto_options: CryptoOptions {
            limits: CryptoLimits {
                maximum_parts: b.input_parts,
                maximum_total_bytes: b.input_bytes,
            },
            edwards: EdwardsOptions {
                parameter_encoding: EdwardsParameterEncoding::Oid,
                point_encoding: EdwardsPointEncoding::Raw,
                key_size_units: EdwardsKeySizeUnits::FieldBits,
            },
        },
        session_policy: SessionPolicy {
            module_read_write: b.read_write_sessions,
            default_token: SessionLimit {
                total: b.sessions,
                read_write: b.read_write_sessions,
            },
            tokens: Vec::new(),
            announced_limits: AnnouncedSessionLimits::Ignore,
        },
        symmetric_limits: SymmetricLimits {
            maximum_buffer_bytes: b.owned_buffer_bytes,
        },
        chacha_nonce_length_encoding: ChaChaNonceLengthEncoding::Bits,
    };
    Module::builder(config, options).open()
}

/// Enumerate the completed opening snapshot's full token identities.
pub fn token_identities(module: &Module) -> Vec<TokenIdentity> {
    module.tokens().iter().map(|token| token.identity.clone()).collect()
}

/// Use an exact identity selected by the application from discovery.
pub fn open_selected_session(
    module: &Module,
    identity: &TokenIdentity,
    read_write: bool,
) -> Result<Session> {
    module.select(identity)?.open_session(read_write)
}
```

## Select deliberately

Call `token_identities(&module)`, display or compare the complete identities, then
pass the chosen identity to `open_selected_session`. Match manufacturer, model,
serial and slot according to application configuration; vector position alone is
not a persistent token identity. Request a read/write session for token-object
creation or administrative changes that require it.

`module.tokens()` is the completed opening snapshot. Fresh information queries
such as `slot_ids` and `token_info` return observations; they do not rewrite that
snapshot. Follow the [recovery contract](../error-recovery.md) if the token or
runtime changes. Finish operations and close sessions before `module.close()`.

Reference: [ModuleBuilder](https://borealcryptosystems.github.io/fe11/0.1.1/api/fe11/struct.ModuleBuilder.html),
[ModuleOptions](https://borealcryptosystems.github.io/fe11/0.1.1/api/fe11/struct.ModuleOptions.html),
[SessionPolicy](https://borealcryptosystems.github.io/fe11/0.1.1/api/fe11/struct.SessionPolicy.html).

[All How To guides](index.md)
