// SPDX-License-Identifier: Apache-2.0
//! Explicit extension contracts share standard ownership, never guessed layouts.
use super::{AttributeLayout, StandardAttribute};
use crate::atomic_update::AtomicUpdate;
use crate::{Error, Result};
use fe11_sys::{CKA_DECAPSULATE_TEMPLATE, CKA_ENCAPSULATE_TEMPLATE, CK_ATTRIBUTE_TYPE};

/// A selected attribute representation, independent of availability or policy.
/// Unknown identifiers are never implicitly converted to extension contracts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttributeType {
    /// Reviewed normative identity and ABI layout.
    Standard(StandardAttribute),
    /// ABI contract explicitly supplied by the integrator for the loaded module.
    Extension(ExtensionAttribute),
}
impl AttributeType {
    /// Native identifier widened without changing its value.
    pub fn identifier(self) -> u64 {
        self.native() as u64
    }
    /// Declared native layout; this does not assert that an object exposes it.
    pub fn layout(self) -> AttributeLayout {
        match self {
            Self::Standard(a) => a.layout(),
            Self::Extension(a) => a.layout,
        }
    }
    /// Standard identity, if selected; extensions have no invented standard name.
    pub fn standard(self) -> Option<StandardAttribute> {
        match self {
            Self::Standard(a) => Some(a),
            Self::Extension(_) => None,
        }
    }
    pub(super) fn check_scope(self, scope: Option<u64>) -> Result<()> {
        if let Self::Extension(attribute) = self {
            if Some(attribute.scope) != scope {
                return Err(Error::Rejected(
                    crate::RejectionReason::AttributeValues(crate::AttributeValuesRejection::AttributeExtensionBelongsToAnotherModuleInstance),
                ));
            }
        }
        Ok(())
    }
    pub(super) fn native(self) -> CK_ATTRIBUTE_TYPE {
        match self {
            Self::Standard(a) => a.native(),
            Self::Extension(a) => a.kind,
        }
    }
}
impl From<StandardAttribute> for AttributeType {
    fn from(value: StandardAttribute) -> Self {
        Self::Standard(value)
    }
}
impl From<ExtensionAttribute> for AttributeType {
    fn from(value: ExtensionAttribute) -> Self {
        Self::Extension(value)
    }
}
impl PartialEq<StandardAttribute> for AttributeType {
    fn eq(&self, other: &StandardAttribute) -> bool {
        self.standard() == Some(*other)
    }
}
impl PartialEq<AttributeType> for StandardAttribute {
    fn eq(&self, other: &AttributeType) -> bool {
        other == self
    }
}

/// Caller-established ABI for an attribute absent from the standard catalogue.
/// Declare it with [`crate::Module::declare_attribute_extension`]; it remains
/// bound to that exact module instance even after that instance is dropped.
/// This is a layout contract, not a capability, provider allowlist or observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtensionAttribute {
    kind: CK_ATTRIBUTE_TYPE,
    layout: AttributeLayout,
    scope: u64,
}
impl ExtensionAttribute {
    // A public contract can only be declared through its actual Module owner.
    pub(super) fn new(identifier: u64, layout: AttributeLayout, scope: u64) -> Result<Self> {
        let kind = CK_ATTRIBUTE_TYPE::try_from(identifier).map_err(|_| {
            Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::ExtensionAttributeNativeIdentifierWidth,
            ))
        })?;
        if StandardAttribute::from_identifier(identifier).is_some() {
            return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::StandardAttributeLayoutCannotBeOverridden,
            )));
        }
        if matches!(kind, CKA_ENCAPSULATE_TEMPLATE | CKA_DECAPSULATE_TEMPLATE) {
            return Err(Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeTemplateSpecificationDeferred,
            )));
        }
        Ok(Self {
            kind,
            layout,
            scope,
        })
    }
    /// Exact external identifier; no standard capability is inferred.
    pub fn identifier(self) -> u64 {
        self.kind as u64
    }
    /// Layout established by the module declaration's safety contract.
    pub fn layout(self) -> AttributeLayout {
        self.layout
    }
}

static NEXT_SCOPE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
fn next_scope(counter: &std::sync::atomic::AtomicU64) -> Result<u64> {
    use std::sync::atomic::Ordering;
    counter
        .update_checked(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| {
            Error::Rejected(crate::RejectionReason::AttributeValues(
                crate::AttributeValuesRejection::AttributeExtensionScopeExhausted,
            ))
        })
}
fn module_scope(inner: &crate::module::Inner) -> Result<u64> {
    if let Some(scope) = inner.attribute_extension_scope.get() {
        return Ok(*scope);
    }
    let scope = next_scope(&NEXT_SCOPE)?;
    // Concurrent declarations may consume unused numbers, but never share a
    // number with another instance or reuse one after a Module is dropped.
    let _ = inner.attribute_extension_scope.set(scope);
    inner
        .attribute_extension_scope
        .get()
        .copied()
        .ok_or(Error::Rejected(crate::RejectionReason::AttributeValues(
            crate::AttributeValuesRejection::AttributeExtensionScopeMissing,
        )))
}
impl crate::Module {
    /// Declare an exact native layout for an otherwise unknown attribute.
    /// Numeric width is checked. Known standard attributes cannot be redefined;
    /// the deferred KEM templates cannot be promoted through this constructor.
    /// No vendor name or binary identity is embedded in the library.
    ///
    /// # Safety
    /// For every object/context in this module instance where the identifier
    /// can be used, the caller must establish precisely `layout`'s ABI for the
    /// instance's lifetime. The contract is checked against that instance before
    /// dispatch and is rejected on other Module owners, even for the same file.
    /// `Bytes` must be flat, pointer-free byte strings, not an ABI struct with
    /// additional alignment requirements; scalars and integer arrays must
    /// have the documented native widths. `Template` must be a CK_ATTRIBUTE
    /// array whose nested pointers obey PKCS#11 ownership and length rules.
    /// A flat struct containing pointers cannot be represented as `Bytes`.
    /// A module reload requires a new declaration. The library checks the
    /// instance binding but cannot discover or verify the declared ABI.
    ///
    /// Native code must respect capacities and retain referents only within the
    /// native completion contract, as for standard attributes. Dynamic output
    /// changes are not authorization to follow returned foreign pointers.
    pub unsafe fn declare_attribute_extension(
        &self,
        identifier: u64,
        layout: AttributeLayout,
    ) -> Result<ExtensionAttribute> {
        ExtensionAttribute::new(identifier, layout, module_scope(&self.inner)?)
    }
}
