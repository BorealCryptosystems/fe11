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
