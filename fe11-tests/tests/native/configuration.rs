// SPDX-License-Identifier: Apache-2.0
//! Explicit test budgets and interface selection, independent of module identity.
use fe11::*;
use std::path::PathBuf;

pub struct Configuration {
    pub module: PathBuf,
    pub module_sha256: [u8; 32],
    pub interface: InterfaceSelection,
    pub label: String,
}

/// Ordinary-case allowances. Boundary cases supply their own smaller budgets.
/// These are test inputs, not defaults or policy imposed by the library.
pub struct Budgets {
    pub slots: usize,
    pub mechanisms: usize,
    pub interfaces: usize,
    pub discovery_attempts: usize,
    pub sessions: usize,
    pub parts: usize,
    pub input_bytes: usize,
    pub buffer_bytes: usize,
}

impl Budgets {
    pub fn ordinary() -> Self {
        Self {
            slots: 64,
            mechanisms: 512,
            interfaces: 16,
            discovery_attempts: 4,
            sessions: 16,
            parts: 131072,
            // Largest published streaming digest fixture. This is a numeric
            // allowance; the streaming worker never allocates the full message.
            input_bytes: usize::try_from(8_589_934_592_u64)
                .expect("the native suite requires a 64-bit target"),
            buffer_bytes: 64 * 1024 * 1024,
        }
    }
}

impl Configuration {
    pub fn open(&self, budgets: &Budgets) -> Result<Module> {
        self.builder(budgets).open()
    }

    /// The same explicit options serve owned and shared-runtime scenarios.
    pub fn builder(&self, budgets: &Budgets) -> ModuleBuilder {
        let config = ModuleConfig {
            path: self.module.clone(),
            integrity: ModuleIntegrity::Sha256 {
                expected: self.module_sha256,
                on_mismatch: ModuleDigestMismatch::Refuse,
            },
            limits: Limits {
                slots: budgets.slots,
                mechanisms: budgets.mechanisms,
                discovery_attempts: budgets.discovery_attempts,
                sessions: budgets.sessions,
            },
        };
        Module::builder(config, self.options(budgets))
    }

    /// Common options also support explicit current-process source boundaries.
    pub fn options(&self, budgets: &Budgets) -> ModuleOptions {
        ModuleOptions {
            discovery: DiscoverySelection::AllPresentSlots,
            initialization: InitializationOptions {
                cannot_create_os_threads: false,
                concurrency: NativeConcurrency::Concurrent,
            },
            interface_discovery: InterfaceDiscoveryLimits {
                interfaces: budgets.interfaces,
                attempts: budgets.discovery_attempts,
            },
            object_limits: ObjectLimits {
                object_references: None,
                managed_references: None,
                destination_reservations: None,
            },
            interface: self.interface,
            crypto_options: CryptoOptions {
                limits: CryptoLimits {
                    maximum_parts: budgets.parts,
                    maximum_total_bytes: budgets.input_bytes,
                },
                edwards: EdwardsOptions {
                    parameter_encoding: EdwardsParameterEncoding::Oid,
                    point_encoding: EdwardsPointEncoding::Raw,
                    key_size_units: EdwardsKeySizeUnits::FieldBits,
                },
            },
            session_policy: SessionPolicy {
                module_read_write: budgets.sessions,
                default_token: SessionLimit {
                    total: budgets.sessions,
                    read_write: budgets.sessions,
                },
                tokens: Vec::new(),
                announced_limits: AnnouncedSessionLimits::Ignore,
            },
            symmetric_limits: SymmetricLimits {
                maximum_buffer_bytes: budgets.buffer_bytes,
            },
            chacha_nonce_length_encoding: ChaChaNonceLengthEncoding::Bits,
        }
    }
}

/// A test namespace is an exact label, not a prefix or a convenient first slot.
pub fn select_token(module: &Module, label: &str) -> Option<TokenIdentity> {
    let mut selected = None;
    for token in module.tokens() {
        let length = token
            .label
            .iter()
            .rposition(|byte| *byte != b' ')
            .map_or(0, |last| last + 1);
        if &token.label[..length] == label.as_bytes() {
            if selected.is_some() {
                return None;
            }
            selected = Some(token.identity.clone());
        }
    }
    selected
}
