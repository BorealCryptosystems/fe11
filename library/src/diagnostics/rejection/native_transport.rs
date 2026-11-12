// SPDX-License-Identifier: Apache-2.0
//! NativeTransport causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to native transport.
#[doc = include_str!("../../../docs/diagnostics/rejection-native_transport.md")]
pub enum NativeTransportRejection {
    /// SKIPJACK shared P/G extent. [Detection, owner and recovery](#cause-SkipjackSharedPGExtent).
    SkipjackSharedPGExtent,
    /// Historical transport mechanism/layout mismatch. [Detection, owner and recovery](#cause-HistoricalTransportMechanismLayoutMismatch).
    HistoricalTransportMechanismLayoutMismatch,
    /// Transport fixed parameter extent. [Detection, owner and recovery](#cause-TransportFixedParameterExtent).
    TransportFixedParameterExtent,
    /// Transport scalar ABI width. [Detection, owner and recovery](#cause-TransportScalarAbiWidth).
    TransportScalarAbiWidth,
}

impl std::fmt::Display for NativeTransportRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SkipjackSharedPGExtent => f.write_str("SKIPJACK shared P/G extent"),
            Self::HistoricalTransportMechanismLayoutMismatch => {
                f.write_str("historical transport mechanism/layout mismatch")
            }
            Self::TransportFixedParameterExtent => f.write_str("transport fixed parameter extent"),
            Self::TransportScalarAbiWidth => f.write_str("transport scalar ABI width"),
        }
    }
}
