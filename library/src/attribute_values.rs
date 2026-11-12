// SPDX-License-Identifier: Apache-2.0
//! Declared attribute identities and protected, typed views of native values.
use crate::{bounds, AttributeUnavailableCause, Error, Result};
use fe11_sys::*;

mod batch;
mod catalog;
mod identity;
mod input;
pub(crate) mod read;
mod storage;
mod template;

pub use batch::{
    AttributeBatchCall, AttributeBatchCalls, FlatAttributeBatch, FlatAttributeIntoIter,
    FlatAttributeRequest,
};
pub use catalog::{AttributeLayout, StandardAttribute};
pub use identity::{AttributeType, ExtensionAttribute};
pub use input::{AttributeInput, AttributeInputValue, AttributeTemplateLimits};
pub(crate) use input::{InputTemplate, InputTemplatePlan, InputTemplateStorage};
pub use storage::AttributeBytes;
pub use template::{
    TemplateAttributeChildren, TemplateAttributeNode, TemplateAttributeReadPlan,
    TemplateAttributeSlot, TemplateAttributeTree, TemplateAttributeValue,
};

/// Choose a size observation or one bounded value retrieval, without retries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlatAttributeReadPlan {
    /// Submit a NULL value pointer and report the native size only.
    LengthOnly,
    /// Make one value call using the caller's capacity, without a size query.
    /// Zero supplies a non-NULL pointer and is distinct from LengthOnly.
    Buffer {
        /// Bytes to reserve before acquiring native access.
        capacity: usize,
    },
    /// Query size, then allocate and read once if the size fits this ceiling.
    /// After the query, the resource admission policy governs value allocation.
    /// The session retains earlier results and object protection while the caller
    /// waits without coordination guards. Neither native pass is replayed. A
    /// local preparation failure retains its completed-call provenance.
    Value {
        /// Maximum byte length chosen by the caller, excluding owner metadata.
        maximum_bytes: usize,
    },
}

/// Exact native return codes for the calls made by this observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttributeReadCalls {
    /// One value call with caller-supplied capacity, without a preceding query.
    Direct {
        /// C_GetAttributeValue return code.
        code: u64,
    },
    /// Only the size call was made, including when its result prevented a read.
    Size {
        /// C_GetAttributeValue return code.
        code: u64,
    },
    /// Both the size query and the value call returned known completion.
    Value {
        /// Return code of the first, size-only call.
        size_code: u64,
        /// Return code of the subsequent value call.
        code: u64,
    },
}

/// A protected observation, including absence and a caller's allocation limit.
/// No Debug or Clone implementation exposes or copies native value bytes.
pub enum FlatAttributeValue {
    /// Exact size reported without reading value bytes; zero is a valid size.
    SizeKnown {
        /// Required bytes reported by the module.
        required: usize,
    },
    /// Bytes returned by a completed call, with their memory credit retained.
    Available(AttributeBytes),
    /// The individual attribute could not be returned.
    Unavailable(AttributeUnavailableCause),
    /// No value allocation or value call followed the completed size query.
    AllocationLimit {
        /// Exact size returned by the module, without clamping.
        required: usize,
        /// Ceiling selected by the caller.
        maximum_bytes: usize,
    },
    /// The size fits its individual ceiling but not the remaining batch ceiling.
    /// No value buffer or second native read was prepared for this entry.
    AggregateAllocationLimit {
        /// Exact size reported by the module.
        required: usize,
        /// Remaining logical value capacity after earlier admitted entries.
        remaining_bytes: usize,
    },
    /// The size query completed, but preparing the value call failed locally.
    /// This distinguishes resource contention after an observation from a
    /// whole-operation Busy result promising that no native call occurred.
    PreparationFailed {
        /// Exact size reported by the completed query.
        required: usize,
        /// Local allocation or access error; no value call followed it.
        cause: Error,
    },
    /// The value changed or the module refused the supplied capacity.
    /// No partial bytes are published and no call is repeated automatically.
    BufferTooSmall {
        /// Capacity supplied in the value call.
        supplied: usize,
        /// Size reported, if available. PKCS#11 normally returns the unavailable
        /// sentinel here, so this is not an implicit retry recommendation.
        required: Option<usize>,
    },
}

/// One explicitly typed attribute observation with exact call provenance.
pub struct FlatAttributeObservation {
    /// Requested standard identity or explicit extension ABI contract.
    pub attribute: AttributeType,
    /// Native codes; a local interpretation never rewrites these values.
    pub calls: AttributeReadCalls,
    /// Protected value or the reason no bytes were returned.
    pub value: FlatAttributeValue,
}
impl FlatAttributeObservation {
    fn bytes_for(&self, layout: AttributeLayout, width: usize) -> Result<&[u8]> {
        if self.attribute.layout() != layout {
            return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeRepresentationDoesNotMatchConversion,
            )));
        }
        let FlatAttributeValue::Available(bytes) = &self.value else {
            return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeValueUnavailable,
            )));
        };
        let value = bytes.as_bytes();
        if value.len() != width {
            return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeNativeScalarWidth,
            )));
        }
        Ok(value)
    }

    /// Decode a normative CK_BBOOL without constructing an invalid Rust bool.
    pub fn boolean(&self) -> Result<bool> {
        match self.bytes_for(AttributeLayout::Boolean, 1)?[0] {
            CK_FALSE => Ok(false),
            CK_TRUE => Ok(true),
            _ => Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeBooleanRepresentation,
            ))),
        }
    }

    /// Decode a native CK_ULONG, including enum and flag typedefs, into u64.
    /// Unknown enum values remain values; this does not invent a Rust enum case.
    pub fn unsigned(&self) -> Result<u64> {
        let bytes = self.bytes_for(AttributeLayout::Unsigned, std::mem::size_of::<CK_ULONG>())?;
        let value = CK_ULONG::from_ne_bytes(bytes.try_into().map_err(|_| {
            Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeUnsignedWidth,
            ))
        })?);
        Ok(value as u64)
    }

    /// Read the eight CK_DATE bytes without imposing a date policy or calendar.
    pub fn date(&self) -> Result<[u8; 8]> {
        self.bytes_for(AttributeLayout::Date, 8)?
            .try_into()
            .map_err(|_| {
                Error::Rejected(crate::RejectionReason::AttributeValues(
                    crate::AttributeValuesRejection::AttributeDateWidth,
                ))
            })
    }

    /// Decode CK_VERSION as its major and minor bytes.
    pub fn version(&self) -> Result<(u8, u8)> {
        let bytes = self.bytes_for(AttributeLayout::Version, 2)?;
        Ok((bytes[0], bytes[1]))
    }

    /// Iterate a normative CK_ULONG/CK_MECHANISM_TYPE array after width checking.
    /// Each returned integer is an explicit caller-visible copy, not a buffer export.
    pub fn unsigned_values(&self) -> Result<AttributeIntegers<'_>> {
        if self.attribute.layout() != AttributeLayout::UnsignedArray {
            return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeIsNotAnUnsignedArray,
            )));
        }
        let FlatAttributeValue::Available(bytes) = &self.value else {
            return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeValueUnavailable,
            )));
        };
        let bytes = bytes.as_bytes();
        let width = std::mem::size_of::<CK_ULONG>();
        if bytes.len() % width != 0 {
            return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeUnsignedArrayWidth,
            )));
        }
        Ok(AttributeIntegers {
            chunks: bytes.chunks_exact(width),
        })
    }
}

/// Borrowed iterator over a width-checked native unsigned attribute array.
pub struct AttributeIntegers<'a> {
    chunks: std::slice::ChunksExact<'a, u8>,
}
impl Iterator for AttributeIntegers<'_> {
    type Item = u64;
    fn next(&mut self) -> Option<Self::Item> {
        self.chunks.next().map(|bytes| {
            // ChunksExact was constructed with exactly the native integer width.
            CK_ULONG::from_ne_bytes(bytes.try_into().expect("checked attribute array width")) as u64
        })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.chunks.size_hint()
    }
}
impl ExactSizeIterator for AttributeIntegers<'_> {}

impl crate::Session {
    /// Read flat attributes in request order, retaining duplicates and partial
    /// results. The first call mixes direct buffers and size queries. A second
    /// call contains only queried values admitted by the caller's ceilings.
    /// No direct buffer refusal is retried. The calls are not an atomic snapshot.
    ///
    /// `maximum_value_bytes` bounds the total logical capacities allocated for
    /// this request across both calls, including refused direct buffers; module
    /// resource admission also accounts for alignment, metadata and allocation
    /// capacity. Known allocations are admitted together before the first call.
    /// Queried values use the caller's resource-admission policy outside
    /// coordination guards, with cancellation and deadline checks. Earlier
    /// results retain their credits: concurrent partial reads may therefore
    /// wait for each other until cancellation or their selected deadline.
    /// Admission failure remains an individual PreparationFailed result.
    /// An empty request makes no native call. Nested layouts are
    /// rejected before dispatch. Returned storage is erased when dropped.
    pub fn read_flat_attributes(
        &self,
        object: &crate::NativeObjectRef,
        requests: &[FlatAttributeRequest],
        maximum_value_bytes: usize,
    ) -> Result<FlatAttributeBatch> {
        read::observe_batch(self, object, requests, maximum_value_bytes)
    }

    /// Observe one flat attribute through this session's managed reference.
    /// Private components are readable only when native policy permits them.
    /// Templates require recursive ownership and are rejected by this flat API
    /// before a native call. No object class or login policy is inferred here.
    pub fn read_flat_attribute(
        &self,
        object: &crate::NativeObjectRef,
        attribute: impl Into<AttributeType>,
        plan: FlatAttributeReadPlan,
    ) -> Result<FlatAttributeObservation> {
        let attribute = attribute.into();
        if attribute.layout() == AttributeLayout::Template {
            return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::NestedAttributeRequiresARecursiveReader,
            )));
        }
        read::observe(self, object, attribute, plan)
    }
}

impl crate::AdvancedSession {
    /// Synchronous grouped metadata reading, with the same contract as Session.
    /// This operation does not use cooperative pacing or native asynchronous mode.
    pub fn read_flat_attributes(
        &self,
        object: &crate::NativeObjectRef,
        requests: &[FlatAttributeRequest],
        maximum_value_bytes: usize,
    ) -> Result<FlatAttributeBatch> {
        self.session
            .read_flat_attributes(object, requests, maximum_value_bytes)
    }

    /// Perform the same synchronous protected attribute observation as Session.
    /// This metadata operation does not use cooperative pacing or native asynchronous mode.
    pub fn read_flat_attribute(
        &self,
        object: &crate::NativeObjectRef,
        attribute: impl Into<AttributeType>,
        plan: FlatAttributeReadPlan,
    ) -> Result<FlatAttributeObservation> {
        self.session.read_flat_attribute(object, attribute, plan)
    }
}
