// SPDX-License-Identifier: Apache-2.0
//! KEA has random-only phases as well as key-creating phases.
use crate::NativeObjectView;
/// Distinct historical and current KEA identifiers, with the same six-case contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeaMechanism {
    /// CKM_KEA_KEY_DERIVE, value 0x1011.
    KeyDerive,
    /// CKM_KEA_DERIVE, value 0x1012. No automatic substitution is performed.
    Derive,
}
impl KeaMechanism {
    pub(crate) fn native(self) -> fe11_sys::CK_MECHANISM_TYPE {
        match self {
            Self::KeyDerive => fe11_sys::CKM_KEA_KEY_DERIVE,
            Self::Derive => fe11_sys::CKM_KEA_DERIVE,
        }
    }
}
/// Exact KEA operands. Both random buffers must have the same byte length
/// because the native structure supplies one shared ulRandomLen field.
pub struct KeaRequest<'a> {
    /// Exact native identifier.
    pub mechanism: KeaMechanism,
    /// Native isSender flag.
    pub sender: bool,
    /// Initial random A; writable by the module in sender phases.
    pub random_a: &'a [u8],
    /// Big-endian integer B, including any leading zeroes. Zero selects the
    /// random-only phase; one selects email mode; larger values select full mode.
    pub random_b: &'a [u8],
    /// Peer public value, without local mathematical validation.
    pub peer_public: &'a [u8],
}
/// Random operands after successful native completion, without implicit export
/// of any derived key. The returned buffers are erased when this value drops.
pub struct KeaRandoms {
    pub(crate) a: crate::symmetric::memory::Buffer,
    pub(crate) b: crate::symmetric::memory::Buffer,
}
impl KeaRandoms {
    /// Native random A after the operation.
    pub fn random_a(&self) -> &[u8] {
        self.a.as_slice()
    }
    /// Native random B after the operation.
    pub fn random_b(&self) -> &[u8] {
        self.b.as_slice()
    }
}
/// The native six-case table determines whether an object was created.
pub enum KeaResult {
    /// RandomB was zero; no object is requested or invented locally.
    Randoms(KeaRandoms),
    /// RandomB was nonzero; the native key has been observed before publication.
    Derived {
        /// Newly derived native key, retaining its module/session and creation provenance.
        key: NativeObjectView,

        /// Native KEA random values returned for the selected exchange phase.
        randoms: KeaRandoms,
    },
}
