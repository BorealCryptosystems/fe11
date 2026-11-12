// SPDX-License-Identifier: Apache-2.0
//! Native SP800-108 requests and owned results; no software KDF or PRF fallback.
use crate::{symmetric::memory::Credit, NativeObjectView};

/// Counter serialization, passed in bits exactly as requested.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sp800CounterFormat {
    /// Least significant byte first when true.
    pub little_endian: bool,
    /// Exact ulWidthInBits; native code checks algorithmic validity.
    pub width_bits: u64,
}
/// DKM-length serialization; the native method is an explicit CK_ULONG value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sp800LengthFormat {
    /// CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS or SUM_OF_SEGMENTS.
    pub method: u64,
    /// Least significant byte first when true.
    pub little_endian: bool,
    /// Exact number of encoded length bits.
    pub width_bits: u64,
}
/// Ordered CK_PRF_DATA_PARAM segment. Repetition and PRF compatibility are
/// evaluated by the native mechanism, not a hidden local policy.
pub enum Sp800Data<'a> {
    /// Counter-mode iteration with an explicit counter format.
    CounterIteration(Sp800CounterFormat),
    /// Feedback/double-pipeline iteration, NULL parameter and zero length.
    Iteration,
    /// CK_SP800_108_COUNTER (alias OPTIONAL_COUNTER).
    Counter(Sp800CounterFormat),
    /// CK_SP800_108_DKM_LENGTH.
    Length(Sp800LengthFormat),
    /// Exact CK_SP800_108_BYTE_ARRAY bytes, copied into erased ownership.
    Bytes(&'a [u8]),
    /// CK_SP800_108_KEY_HANDLE; the key value is never exported by Fe11.
    Key(&'a crate::NativeObjectRef),
}
/// Select the native function-specific parameter structure.
#[derive(Clone, Copy)]
pub enum Sp800Mode<'a> {
    /// CKM_SP800_108_COUNTER_KDF.
    Counter,
    /// CKM_SP800_108_FEEDBACK_KDF, with an explicit optional IV.
    Feedback {
        /// None encodes NULL/0; present bytes are passed unchanged.
        iv: Option<&'a [u8]>,
    },
    /// CKM_SP800_108_DOUBLE_PIPELINE_KDF.
    DoublePipeline,
}
/// Complete ordered SP800-108 input; outputs have individual caller templates.
pub struct Sp800Request<'a> {
    /// Exact native mode.
    pub mode: Sp800Mode<'a>,
    /// CKM_* PRF identifier; no implicit HMAC or hash conversion.
    pub prf: u64,
    /// Ordered segments; labels, context and separators are caller decisions.
    pub data: &'a [Sp800Data<'a>],
}
/// Created object references in primary/additional output order.
/// The enclosing `CreatedObjects` reports optional observations separately;
/// an observation failure does not discard an established native reference.
pub struct NativeDerivedKeys {
    pub(crate) keys: Vec<NativeObjectView>,
    pub(crate) _credit: Credit,
}
impl NativeDerivedKeys {
    /// Primary output followed by each additional output in request order.
    pub fn as_slice(&self) -> &[NativeObjectView] {
        &self.keys
    }
    /// Number of returned keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }
    /// Whether no keys were returned.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}
