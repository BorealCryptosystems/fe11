// SPDX-License-Identifier: Apache-2.0
//! TLS key-material derivation keeps its multi-object result explicit.
use crate::{
    AttributeInput, AttributeTemplateLimits, DestinationPlan, NativeObjectView, TlsRandoms,
};

/// Exact native key-material mechanism. Hashes and protocol policy are caller choices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsKeyMaterialMechanism {
    /// CKM_SSL3_KEY_AND_MAC_DERIVE.
    Ssl3,
    /// CKM_TLS_KEY_AND_MAC_DERIVE.
    Tls,
    /// CKM_TLS12_KEY_AND_MAC_DERIVE.
    Tls12 {
        /// Caller-selected native hash mechanism identifier (CKM); no implicit hashing substitution.
        hash: u64,
    },
    /// CKM_TLS12_KEY_SAFE_DERIVE. Native IV length is preserved but ignored by
    /// the mechanism; this result never claims an IV was generated.
    Tls12Safe {
        /// Caller-selected native hash mechanism identifier (CKM); no implicit hashing substitution.
        hash: u64,
    },
    /// CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE.
    WtlsServer {
        /// Native digest mechanism identifier (CKM), passed unchanged.
        digest: u64,
        /// Native WTLS sequence number; the caller selects the protocol value.
        sequence: u64,
    },
    /// CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE.
    WtlsClient {
        /// Native digest mechanism identifier (CKM), passed unchanged.
        digest: u64,
        /// Native WTLS sequence number; the caller selects the protocol value.
        sequence: u64,
    },
}
impl TlsKeyMaterialMechanism {
    pub(crate) fn native(self) -> fe11_sys::CK_MECHANISM_TYPE {
        use fe11_sys::*;
        match self {
            Self::Ssl3 => CKM_SSL3_KEY_AND_MAC_DERIVE,
            Self::Tls => CKM_TLS_KEY_AND_MAC_DERIVE,
            Self::Tls12 { .. } => CKM_TLS12_KEY_AND_MAC_DERIVE,
            Self::Tls12Safe { .. } => CKM_TLS12_KEY_SAFE_DERIVE,
            Self::WtlsServer { .. } => CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE,
            Self::WtlsClient { .. } => CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE,
        }
    }
    pub(crate) fn count(self) -> usize {
        match self {
            Self::WtlsServer { .. } | Self::WtlsClient { .. } => 2,
            _ => 4,
        }
    }
}
/// One exact template, shared by the native key-material operation. The module
/// derives MAC-key attributes as specified by PKCS#11; Fe11 adds no attributes.
pub struct TlsKeyMaterialRequest<'a> {
    /// Native mechanism and its algorithm-specific scalars.
    pub mechanism: TlsKeyMaterialMechanism,
    /// Client and server randoms, copied before dispatch.
    pub randoms: TlsRandoms<'a>,
    /// Requested MAC-key length in bits.
    pub mac_bits: u64,
    /// Requested encryption-key length in bits, before native export expansion.
    pub key_bits: u64,
    /// Requested IV length in bits; storage rounds up to whole bytes.
    pub iv_bits: u64,
    /// Native export-suite flag, without local protocol policy.
    pub export: bool,
    /// Exact C_DeriveKey template.
    pub attributes: &'a [AttributeInput<'a>],
    /// Caller bounds on this template.
    pub limits: AttributeTemplateLimits,
}
/// Independent observations for an output. These do not alter the shared template.
pub struct DerivedKeyObservation {
    /// None returns the native object without attribute reads.
    pub observation: Option<crate::CreationObservation>,
    /// Optional destination observation/requirement before dispatch.
    pub destination: DestinationPlan,
}
/// Ordered observations matching native output fields.
pub enum TlsKeyMaterialObservations {
    /// Client MAC, server MAC, client key, server key, in that order.
    Tls([DerivedKeyObservation; 4]),
    /// MAC and encryption key for the selected WTLS endpoint.
    Wtls([DerivedKeyObservation; 2]),
}
impl TlsKeyMaterialObservations {
    // Move content observations exactly once; never duplicate secret expectations.
    pub(crate) fn into_iter(self) -> impl Iterator<Item = DerivedKeyObservation> {
        let slots = match self {
            Self::Tls(values) => values.map(Some),
            Self::Wtls([mac, key]) => [Some(mac), Some(key), None, None],
        };
        slots.into_iter().flatten()
    }

    pub(crate) fn as_slice(&self) -> &[DerivedKeyObservation] {
        match self {
            Self::Tls(v) => v,
            Self::Wtls(v) => v,
        }
    }
}
/// Role of a returned object, independent of its native handle or CKA_ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsKeyMaterialPart {
    /// TLS client MAC key.
    ClientMac,
    /// TLS server MAC key.
    ServerMac,
    /// TLS client encryption key.
    ClientKey,
    /// TLS server encryption key.
    ServerKey,
    /// WTLS MAC key for the endpoint selected by the mechanism.
    WtlsMac,
    /// WTLS encryption key for the endpoint selected by the mechanism.
    WtlsKey,
}
pub(crate) enum MaterialIvs {
    Tls {
        client: crate::symmetric::memory::Buffer,
        server: crate::symmetric::memory::Buffer,
    },
    Wtls(crate::symmetric::memory::Buffer),
}
/// All observed native objects and IVs. No partial result is published. An absent
/// zero-length key is omitted; a native refusal remains an error, never an empty
/// successful result. IV storage is credited and erased when this result drops.
pub struct NativeTlsKeyMaterial {
    pub(crate) keys: Vec<(TlsKeyMaterialPart, NativeObjectView)>,
    pub(crate) ivs: MaterialIvs,
    pub(crate) mechanism: TlsKeyMaterialMechanism,
    pub(crate) _credit: crate::symmetric::memory::Credit,
}
impl NativeTlsKeyMaterial {
    /// Returned roles and references. No key bytes are exported here.
    pub fn keys(&self) -> &[(TlsKeyMaterialPart, NativeObjectView)] {
        &self.keys
    }
    /// Exact requested mechanism.
    pub fn mechanism(&self) -> TlsKeyMaterialMechanism {
        self.mechanism
    }
    /// TLS client/server IVs, or None for a WTLS operation. Empty slices mean no
    /// IV was requested or the selected SAFE mechanism cannot return IV data.
    pub fn tls_ivs(&self) -> Option<(&[u8], &[u8])> {
        match &self.ivs {
            MaterialIvs::Tls { client, server } => Some((client.as_slice(), server.as_slice())),
            _ => None,
        }
    }
    /// WTLS IV, or None for a TLS operation.
    pub fn wtls_iv(&self) -> Option<&[u8]> {
        match &self.ivs {
            MaterialIvs::Wtls(iv) => Some(iv.as_slice()),
            _ => None,
        }
    }
}
