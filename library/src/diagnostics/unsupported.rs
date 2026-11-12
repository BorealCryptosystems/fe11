// SPDX-License-Identifier: Apache-2.0
//! Unsupported reasons grouped by technical responsibility.

mod aead_messages;
pub use aead_messages::AeadMessagesUnsupported;
mod cipher_continuation;
pub use cipher_continuation::CipherContinuationUnsupported;
mod mechanism_extensions;
pub use mechanism_extensions::MechanismExtensionsUnsupported;
mod mechanisms;
pub use mechanisms::MechanismsUnsupported;
mod module_configuration;
pub use module_configuration::ModuleConfigurationUnsupported;
mod module_lifecycle;
pub use module_lifecycle::ModuleLifecycleUnsupported;
mod native_interfaces;
pub use native_interfaces::NativeInterfacesUnsupported;
mod native_loading;
pub use native_loading::NativeLoadingUnsupported;
mod native_mac;
pub use native_mac::NativeMacUnsupported;
mod native_messages;
pub use native_messages::NativeMessagesUnsupported;
mod object_creation;
pub use object_creation::ObjectCreationUnsupported;
mod post_quantum_keys;
pub use post_quantum_keys::PostQuantumKeysUnsupported;
mod signature_continuation;
pub use signature_continuation::SignatureContinuationUnsupported;

/// Typed unsupported cause; its enclosing error retains effect information.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnsupportedReason {
    /// Aead Messages diagnostic.
    AeadMessages(AeadMessagesUnsupported),
    /// Cipher Continuation diagnostic.
    CipherContinuation(CipherContinuationUnsupported),
    /// Mechanism Extensions diagnostic.
    MechanismExtensions(MechanismExtensionsUnsupported),
    /// Mechanisms diagnostic.
    Mechanisms(MechanismsUnsupported),
    /// Module Configuration diagnostic.
    ModuleConfiguration(ModuleConfigurationUnsupported),
    /// Module Lifecycle diagnostic.
    ModuleLifecycle(ModuleLifecycleUnsupported),
    /// Native Interfaces diagnostic.
    NativeInterfaces(NativeInterfacesUnsupported),
    /// Native Loading diagnostic.
    NativeLoading(NativeLoadingUnsupported),
    /// Native Mac diagnostic.
    NativeMac(NativeMacUnsupported),
    /// Native Messages diagnostic.
    NativeMessages(NativeMessagesUnsupported),
    /// Object Creation diagnostic.
    ObjectCreation(ObjectCreationUnsupported),
    /// Post Quantum Keys diagnostic.
    PostQuantumKeys(PostQuantumKeysUnsupported),
    /// Signature Continuation diagnostic.
    SignatureContinuation(SignatureContinuationUnsupported),
    /// An explicitly requested native function is absent.
    NativeFunction {
        /// Exact PKCS#11 function name.
        function: &'static str,
    },
}

impl std::fmt::Display for UnsupportedReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AeadMessages(reason) => std::fmt::Display::fmt(reason, f),
            Self::CipherContinuation(reason) => std::fmt::Display::fmt(reason, f),
            Self::MechanismExtensions(reason) => std::fmt::Display::fmt(reason, f),
            Self::Mechanisms(reason) => std::fmt::Display::fmt(reason, f),
            Self::ModuleConfiguration(reason) => std::fmt::Display::fmt(reason, f),
            Self::ModuleLifecycle(reason) => std::fmt::Display::fmt(reason, f),
            Self::NativeInterfaces(reason) => std::fmt::Display::fmt(reason, f),
            Self::NativeLoading(reason) => std::fmt::Display::fmt(reason, f),
            Self::NativeMac(reason) => std::fmt::Display::fmt(reason, f),
            Self::NativeMessages(reason) => std::fmt::Display::fmt(reason, f),
            Self::ObjectCreation(reason) => std::fmt::Display::fmt(reason, f),
            Self::PostQuantumKeys(reason) => std::fmt::Display::fmt(reason, f),
            Self::SignatureContinuation(reason) => std::fmt::Display::fmt(reason, f),
            Self::NativeFunction { function } => {
                write!(f, "native function {function} is unavailable")
            }
        }
    }
}

impl From<AeadMessagesUnsupported> for UnsupportedReason {
    fn from(reason: AeadMessagesUnsupported) -> Self {
        Self::AeadMessages(reason)
    }
}

impl From<CipherContinuationUnsupported> for UnsupportedReason {
    fn from(reason: CipherContinuationUnsupported) -> Self {
        Self::CipherContinuation(reason)
    }
}

impl From<MechanismExtensionsUnsupported> for UnsupportedReason {
    fn from(reason: MechanismExtensionsUnsupported) -> Self {
        Self::MechanismExtensions(reason)
    }
}

impl From<MechanismsUnsupported> for UnsupportedReason {
    fn from(reason: MechanismsUnsupported) -> Self {
        Self::Mechanisms(reason)
    }
}

impl From<ModuleConfigurationUnsupported> for UnsupportedReason {
    fn from(reason: ModuleConfigurationUnsupported) -> Self {
        Self::ModuleConfiguration(reason)
    }
}

impl From<ModuleLifecycleUnsupported> for UnsupportedReason {
    fn from(reason: ModuleLifecycleUnsupported) -> Self {
        Self::ModuleLifecycle(reason)
    }
}

impl From<NativeInterfacesUnsupported> for UnsupportedReason {
    fn from(reason: NativeInterfacesUnsupported) -> Self {
        Self::NativeInterfaces(reason)
    }
}

impl From<NativeLoadingUnsupported> for UnsupportedReason {
    fn from(reason: NativeLoadingUnsupported) -> Self {
        Self::NativeLoading(reason)
    }
}

impl From<NativeMacUnsupported> for UnsupportedReason {
    fn from(reason: NativeMacUnsupported) -> Self {
        Self::NativeMac(reason)
    }
}

impl From<NativeMessagesUnsupported> for UnsupportedReason {
    fn from(reason: NativeMessagesUnsupported) -> Self {
        Self::NativeMessages(reason)
    }
}

impl From<ObjectCreationUnsupported> for UnsupportedReason {
    fn from(reason: ObjectCreationUnsupported) -> Self {
        Self::ObjectCreation(reason)
    }
}

impl From<PostQuantumKeysUnsupported> for UnsupportedReason {
    fn from(reason: PostQuantumKeysUnsupported) -> Self {
        Self::PostQuantumKeys(reason)
    }
}

impl From<SignatureContinuationUnsupported> for UnsupportedReason {
    fn from(reason: SignatureContinuationUnsupported) -> Self {
        Self::SignatureContinuation(reason)
    }
}
