// SPDX-License-Identifier: Apache-2.0
//! Native TLS/WTLS derivation parameters and auxiliary observations.
use crate::NativeObjectRef;
use fe11_sys::*;

/// Randoms passed unchanged to the native TLS/WTLS mechanism.
#[derive(Clone, Copy)]
pub struct TlsRandoms<'a> {
    /// Client random bytes.
    pub client: &'a [u8],
    /// Server random bytes.
    pub server: &'a [u8],
}
/// Select the master-secret mechanism and exact native parameter layout.
pub enum TlsMasterDerivation<'a> {
    /// SSL3 master derivation; DH supplies a NULL pVersion.
    Ssl3 {
        /// Exact client/server random inputs, copied into owned native storage.
        randoms: TlsRandoms<'a>,
        /// Select the DH mechanism variant and omit the native version-output pointer.
        dh: bool,
    },
    /// TLS 1.0/1.1 master derivation; DH supplies a NULL pVersion.
    Tls {
        /// Exact client/server random inputs, copied into owned native storage.
        randoms: TlsRandoms<'a>,
        /// Select the DH mechanism variant and omit the native version-output pointer.
        dh: bool,
    },
    /// TLS 1.2 with caller-selected base hash mechanism.
    Tls12 {
        /// Exact client/server random inputs, copied into owned native storage.
        randoms: TlsRandoms<'a>,

        /// Caller-selected native hash mechanism identifier (CKM); no implicit hashing substitution.
        hash: u64,

        /// Select the DH mechanism variant and omit the native version-output pointer.
        dh: bool,
    },
    /// TLS 1.2 extended master with the exact externally computed session hash.
    Tls12Extended {
        /// Externally computed session transcript hash bytes, without local recomputation.
        session_hash: &'a [u8],

        /// Caller-selected native hash mechanism identifier (CKM); no implicit hashing substitution.
        hash: u64,

        /// Select the DH mechanism variant and omit the native version-output pointer.
        dh: bool,
    },
    /// WTLS with caller-selected digest; DH/ECC supplies NULL pVersion.
    Wtls {
        /// Exact client/server random inputs, copied into owned native storage.
        randoms: TlsRandoms<'a>,

        /// Native digest mechanism identifier (CKM), passed unchanged.
        digest: u64,

        /// Select the DH/ECC mechanism variant and omit the native version-output pointer.
        dh_ecc: bool,
    },
}
impl TlsMasterDerivation<'_> {
    /// Exact native mechanism, without a capability claim.
    pub fn mechanism_number(&self) -> u64 {
        (match self {
            Self::Ssl3 { dh: false, .. } => CKM_SSL3_MASTER_KEY_DERIVE,
            Self::Ssl3 { dh: true, .. } => CKM_SSL3_MASTER_KEY_DERIVE_DH,
            Self::Tls { dh: false, .. } => CKM_TLS_MASTER_KEY_DERIVE,
            Self::Tls { dh: true, .. } => CKM_TLS_MASTER_KEY_DERIVE_DH,
            Self::Tls12 { dh: false, .. } => CKM_TLS12_MASTER_KEY_DERIVE,
            Self::Tls12 { dh: true, .. } => CKM_TLS12_MASTER_KEY_DERIVE_DH,
            Self::Tls12Extended { dh: false, .. } => CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE,
            Self::Tls12Extended { dh: true, .. } => CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE_DH,
            Self::Wtls { dh_ecc: false, .. } => CKM_WTLS_MASTER_KEY_DERIVE,
            Self::Wtls { dh_ecc: true, .. } => CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC,
        }) as u64
    }
}
/// Select the published TLS exporter KDF mechanism without substituting a PRF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsKdfMechanism {
    /// CKM_TLS_KDF.
    Tls,
    /// CKM_TLS12_KDF.
    Tls12,
}
/// Native CK_TLS_KDF_PARAMS. Context absence is distinct from present empty.
pub struct TlsKdfParameters<'a> {
    /// Exact KDF mechanism.
    pub mechanism: TlsKdfMechanism,
    /// Exact prfMechanism value supplied to the native parameter structure.
    pub prf: u64,
    /// Exporter label bytes, without an appended NUL.
    pub label: &'a [u8],
    /// Exact client and server randoms.
    pub randoms: TlsRandoms<'a>,
    /// Optional context data, with no implicit length prefix added by Fe11.
    pub context: Option<&'a [u8]>,
}
/// Defined auxiliary output of a successful native derivation. This is an
/// observation, not a check of protocol version or cryptographic suitability.
pub enum NativeDerivationOutput {
    /// Owned auxiliary bytes from an explicitly declared extension ABI. Capacity
    /// violations quarantine the graph before handle publication. After an intact
    /// boundary and registered creation, a local publication error remains separate
    /// from the created object. Do not repeat C_DeriveKey to recover that output.
    /// Buffers retain their credit and are erased on release. Read-only extensions
    /// return None.
    Extension(crate::Result<crate::ExtensionParameterOutputs>),
    /// The selected mechanism has no auxiliary output.
    None,
    /// Native CK_VERSION from SSL/TLS RSA master-secret derivation.
    TlsVersion {
        /// Major protocol version byte in the native CK_VERSION.
        major: u8,
        /// Minor protocol version byte in the native CK_VERSION.
        minor: u8,
    },
    /// Native single-byte WTLS version from RSA master-secret derivation.
    WtlsVersion(u8),
}
/// Created object plus the selected mechanism's auxiliary output.
pub struct NativeDerivedObject {
    /// Fully observed native object reference.
    pub object: crate::NativeObjectView,
    /// Mechanism-defined observation; validate protocol expectations separately.
    pub output: NativeDerivationOutput,
    /// Origin of the parameter representation, not a capability/conformance verdict.
    pub provenance: crate::MechanismLayoutProvenance,
}

/// Native PRF byte-output mechanism, distinct from a key-creating KDF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsPrfMechanism {
    /// CKM_TLS_PRF, with its protocol-defined native PRF.
    Tls,
    /// CKM_WTLS_PRF with caller-selected digest mechanism.
    Wtls {
        /// Native digest mechanism identifier (CKM), passed unchanged.
        digest: u64,
    },
}
/// Request exactly the selected number of native PRF output bytes.
pub struct TlsPrfRequest<'a> {
    /// Exact native mechanism and optional WTLS digest.
    pub mechanism: TlsPrfMechanism,
    /// Exact seed bytes.
    pub seed: &'a [u8],
    /// Exact label bytes, without an appended NUL.
    pub label: &'a [u8],
    /// Desired output length; checked against ABI and caller memory budget.
    pub output_bytes: usize,
}
/// Successful native PRF bytes. Storage remains credited and erased on drop;
/// copies created by the caller are outside that erasure guarantee.
pub struct NativePrfOutput {
    pub(crate) bytes: crate::symmetric::memory::Buffer,
    pub(crate) mechanism: TlsPrfMechanism,
}
impl NativePrfOutput {
    /// Exact completed output.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
    /// Mechanism requested by this operation, without a support claim.
    pub fn mechanism(&self) -> TlsPrfMechanism {
        self.mechanism
    }
}
impl crate::Session {
    /// Evaluate the native TLS/WTLS PRF. No object is created, no key value is
    /// exported, and no native retry or size probe is performed. Input limits
    /// count seed and label as two pieces; output follows the memory budget.
    pub fn derive_tls_prf(
        &self,
        base: &NativeObjectRef,
        request: TlsPrfRequest<'_>,
        limits: crate::InputLimits,
    ) -> crate::Result<NativePrfOutput> {
        let mut diagnostic = None;
        crate::native::derivation::prf::derive(self, base, request, limits, &mut diagnostic)
    }
}
impl crate::AdvancedSession {
    /// Synchronous PRF evaluation through the same owned native boundary.
    pub fn derive_tls_prf(
        &self,
        base: &NativeObjectRef,
        request: TlsPrfRequest<'_>,
        limits: crate::InputLimits,
    ) -> crate::Result<NativePrfOutput> {
        let mut diagnostic = None;
        crate::native::derivation::prf::derive(
            &self.session,
            base,
            request,
            limits,
            &mut diagnostic,
        )
    }
}
