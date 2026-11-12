// SPDX-License-Identifier: Apache-2.0
//! NativeInterfaces causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to native interfaces.
#[doc = include_str!("../../../docs/diagnostics/rejection-native_interfaces.md")]
pub enum NativeInterfacesRejection {
    /// Counter exhausted. [Detection, owner and recovery](#cause-CounterExhausted).
    CounterExhausted,
    /// No name terminator within the caller's readable-byte limit.
    InterfaceNameLimit {
        /// Zero-based index in the native interface list.
        index: usize,
        /// Caller-selected readable bytes, including the terminating NUL.
        limit: usize,
    },
    /// Copying this name would exceed the caller's aggregate name-byte limit.
    InterfaceNamesTotalLimit {
        /// Zero-based index whose name would exceed the aggregate bound.
        index: usize,
        /// Caller-selected total copied name bytes, excluding NUL terminators.
        limit: usize,
    },
    /// Incoherent selected interface. [Detection, owner and recovery](#cause-IncoherentSelectedInterface).
    IncoherentSelectedInterface,
    /// Interface allocation. [Detection, owner and recovery](#cause-InterfaceAllocation).
    InterfaceAllocation,
    /// Interface discovery attempts exhausted. [Detection, owner and recovery](#cause-InterfaceDiscoveryAttemptsExhausted).
    InterfaceDiscoveryAttemptsExhausted,
    /// Interface list export. [Detection, owner and recovery](#cause-InterfaceListExport).
    InterfaceListExport,
    /// Interface selection export. [Detection, owner and recovery](#cause-InterfaceSelectionExport).
    InterfaceSelectionExport,
    /// Null interface name. [Detection, owner and recovery](#cause-NullInterfaceName).
    NullInterfaceName,
    /// Null interface table. [Detection, owner and recovery](#cause-NullInterfaceTable).
    NullInterfaceTable,
    /// Null selected interface. [Detection, owner and recovery](#cause-NullSelectedInterface).
    NullSelectedInterface,
    /// Requested interface absent. [Detection, owner and recovery](#cause-RequestedInterfaceAbsent).
    RequestedInterfaceAbsent,
    /// Unsupported interface selection. [Detection, owner and recovery](#cause-UnsupportedInterfaceSelection).
    UnsupportedInterfaceSelection,
}

impl std::fmt::Display for NativeInterfacesRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InterfaceNameLimit { index, limit } => {
                write!(f, "interface {index} name exceeds {limit} readable bytes")
            }
            Self::InterfaceNamesTotalLimit { index, limit } => {
                write!(f, "interface {index} exceeds total name bound {limit}")
            }
            Self::CounterExhausted => f.write_str("counter exhausted"),
            Self::IncoherentSelectedInterface => f.write_str("incoherent selected interface"),
            Self::InterfaceAllocation => f.write_str("interface allocation"),
            Self::InterfaceDiscoveryAttemptsExhausted => {
                f.write_str("interface discovery attempts exhausted")
            }
            Self::InterfaceListExport => f.write_str("interface list export"),
            Self::InterfaceSelectionExport => f.write_str("interface selection export"),
            Self::NullInterfaceName => f.write_str("null interface name"),
            Self::NullInterfaceTable => f.write_str("null interface table"),
            Self::NullSelectedInterface => f.write_str("null selected interface"),
            Self::RequestedInterfaceAbsent => f.write_str("requested interface absent"),
            Self::UnsupportedInterfaceSelection => f.write_str("unsupported interface selection"),
        }
    }
}
