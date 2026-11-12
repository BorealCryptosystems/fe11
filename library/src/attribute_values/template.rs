// SPDX-License-Identifier: Apache-2.0
//! Caller-directed nested reads. Native pointers never enter the public tree.
use super::*;
use crate::symmetric::memory::Credit;

mod native;
mod prepare;

/// One observation of an attribute whose declared value is an attribute array.
/// Successive observations are independent, not an atomic snapshot.
#[derive(Clone, Copy)]
pub enum TemplateAttributeReadPlan<'a> {
    /// Query the root's byte length without supplying an array.
    LengthOnly,
    /// Supply exactly these child slots, including a non-NULL empty array.
    Slots(&'a [TemplateAttributeSlot<'a>]),
}

/// Storage for one child position. PKCS#11 ignores child types on input: an
/// expected type validates the output, but does not select a child by name.
#[derive(Clone, Copy)]
pub enum TemplateAttributeSlot<'a> {
    /// Discover the identifier and byte length with a NULL value pointer.
    Discover,
    /// Read a known flat representation into an erased, aligned buffer.
    Value {
        /// Type expected at this position from an earlier observation.
        attribute: AttributeType,
        /// Logical capacity, chosen by the caller; zero remains non-NULL.
        capacity: usize,
    },
    /// Supply owned descriptors for a known nested template.
    Template {
        /// Declared template type expected at this position.
        attribute: AttributeType,
        /// Child positions; no pointer supplied by the caller reaches native code.
        slots: &'a [TemplateAttributeSlot<'a>],
    },
}

/// Protected, finite tree from one completed native call. There is no Debug or
/// Clone implementation exposing values, and destruction is not recursive.
pub struct TemplateAttributeTree {
    call: AttributeBatchCall,
    records: Vec<Record>,
    _credit: Credit,
}
impl TemplateAttributeTree {
    /// Exact global return code. Partial refusal codes do not identify a child.
    pub fn call(&self) -> AttributeBatchCall {
        self.call
    }
    /// The single requested root; only returned children can be traversed.
    pub fn root(&self) -> TemplateAttributeNode<'_> {
        TemplateAttributeNode {
            tree: self,
            index: 0,
        }
    }
}

/// Borrowed view of a returned node; retains the tree and its allocation credit.
#[derive(Clone, Copy)]
pub struct TemplateAttributeNode<'a> {
    tree: &'a TemplateAttributeTree,
    index: usize,
}
impl<'a> TemplateAttributeNode<'a> {
    /// Identifier returned by the module, including unknown child identifiers.
    pub fn attribute_identifier(&self) -> u64 {
        self.record().0
    }
    /// Value or precise reason this position cannot expose bytes or children.
    pub fn value(&self) -> TemplateAttributeValue<'a> {
        match self.record().1 {
            Observed::SizeKnown(required) => TemplateAttributeValue::SizeKnown {
                required_bytes: *required,
            },
            Observed::Flat(value) => TemplateAttributeValue::Flat(value),
            Observed::Template { start, count } => {
                TemplateAttributeValue::Template(TemplateAttributeChildren {
                    tree: self.tree,
                    next: *start,
                    end: start + count,
                })
            }
            Observed::Unavailable(cause) => TemplateAttributeValue::Unavailable(*cause),
            Observed::BufferTooSmall { supplied, required } => {
                TemplateAttributeValue::BufferTooSmall {
                    supplied: *supplied,
                    required: *required,
                }
            }
            Observed::TypeChanged { expected } => TemplateAttributeValue::TypeChanged {
                expected: *expected,
                observed: self.attribute_identifier(),
            },
            Observed::InvalidTemplateLength(bytes) => {
                TemplateAttributeValue::InvalidTemplateLength {
                    reported_bytes: *bytes,
                }
            }
        }
    }
    fn record(&self) -> (u64, &'a Observed) {
        match &self.tree.records[self.index] {
            Record::Returned { identifier, value } => (*identifier, value),
            Record::Hidden => unreachable!("only returned template positions are exposed"),
        }
    }
}

/// Typed observation of one position. No raw descriptor bytes or native
/// pointers are exposed, even if the provider changed that position's type.
pub enum TemplateAttributeValue<'a> {
    /// Exact byte length from a discovery slot.
    SizeKnown {
        /// Required native byte length, not a child count.
        required_bytes: usize,
    },
    /// Protected flat value, with the existing checked scalar conversions.
    Flat(&'a FlatAttributeObservation),
    /// Returned children only; unused planned positions are inaccessible.
    Template(TemplateAttributeChildren<'a>),
    /// Individual cause is unspecified when only a global partial code is known.
    Unavailable(AttributeUnavailableCause),
    /// No partial bytes or children are published and no retry is automatic.
    BufferTooSmall {
        /// Logical byte capacity supplied by the caller.
        supplied: usize,
        /// Native required byte length, when not the unavailable sentinel.
        required: Option<usize>,
    },
    /// The child's output type differs from the caller's previous observation.
    TypeChanged {
        /// Type selected in the read plan for this position.
        expected: u64,
        /// Different type returned at that position.
        observed: u64,
    },
    /// A template's byte length is not a whole number of native descriptors.
    InvalidTemplateLength {
        /// Exact byte length that cannot represent a native descriptor array.
        reported_bytes: usize,
    },
}

/// Iterate children in native order, retaining duplicates and unavailable nodes.
pub struct TemplateAttributeChildren<'a> {
    tree: &'a TemplateAttributeTree,
    next: usize,
    end: usize,
}
impl<'a> Iterator for TemplateAttributeChildren<'a> {
    type Item = TemplateAttributeNode<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.next == self.end {
            return None;
        }
        let index = self.next;
        self.next += 1;
        Some(TemplateAttributeNode {
            tree: self.tree,
            index,
        })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.end - self.next;
        (remaining, Some(remaining))
    }
}
impl ExactSizeIterator for TemplateAttributeChildren<'_> {}
impl std::iter::FusedIterator for TemplateAttributeChildren<'_> {}

enum Record {
    Hidden,
    Returned { identifier: u64, value: Observed },
}
enum Observed {
    SizeKnown(usize),
    Flat(FlatAttributeObservation),
    Template {
        start: usize,
        count: usize,
    },
    Unavailable(AttributeUnavailableCause),
    BufferTooSmall {
        supplied: usize,
        required: Option<usize>,
    },
    TypeChanged {
        expected: u64,
    },
    InvalidTemplateLength(usize),
}

impl crate::Session {
    /// Read a declared nested template with exactly one native call. Discover
    /// sizes/types first when needed, then explicitly select capacities for the
    /// next call. Children are positional, not selected by their expected types.
    /// There is no hidden allocation ceiling, retry, or snapshot guarantee.
    ///
    /// Limits count the root at depth zero and every supplied child descriptor;
    /// value bytes are the sum of flat capacities. The module budget also covers
    /// alignment, metadata and allocator capacity. Unknown child identifiers can
    /// be discovered; reading them requires an explicitly established extension
    /// contract, never a guessed value layout. Partial native
    /// results preserve usable branches. Returned storage is erased on drop.
    pub fn read_template_attribute(
        &self,
        object: &crate::NativeObjectRef,
        attribute: impl Into<AttributeType>,
        plan: TemplateAttributeReadPlan<'_>,
        limits: AttributeTemplateLimits,
    ) -> Result<TemplateAttributeTree> {
        native::observe(self, object, attribute.into(), plan, limits)
    }
}
impl crate::AdvancedSession {
    /// Synchronous metadata read with the same contract as
    /// [`crate::Session::read_template_attribute`]; no native asynchronous mode or pacing.
    pub fn read_template_attribute(
        &self,
        object: &crate::NativeObjectRef,
        attribute: impl Into<AttributeType>,
        plan: TemplateAttributeReadPlan<'_>,
        limits: AttributeTemplateLimits,
    ) -> Result<TemplateAttributeTree> {
        self.session
            .read_template_attribute(object, attribute, plan, limits)
    }
}
