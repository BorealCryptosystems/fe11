// SPDX-License-Identifier: Apache-2.0
//! Complete input owners shared by native object creation and copying.
use crate::{
    attribute_values::InputTemplate, attributes::OwnedTemplate,
    transport::secret_template::NativeSecretTemplate, Result,
};
use fe11_sys::{CK_ATTRIBUTE, CK_ULONG};

pub(crate) enum NativeTemplate {
    Public(OwnedTemplate),
    Protected(NativeSecretTemplate),
    Typed(InputTemplate),
}

impl NativeTemplate {
    pub(crate) fn check_extensions(&self, inner: &crate::module::Inner) -> Result<()> {
        match self {
            Self::Typed(template) => template.check_extensions(inner),
            _ => Ok(()),
        }
    }

    pub(crate) fn count(&self) -> Result<CK_ULONG> {
        match self {
            Self::Public(template) => template.count(),
            Self::Protected(template) => template.count(),
            Self::Typed(template) => Ok(template.count()),
        }
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut CK_ATTRIBUTE {
        match self {
            Self::Public(template) => template.as_mut_ptr(),
            Self::Protected(template) => template.as_mut_ptr(),
            Self::Typed(template) => template.as_mut_ptr(),
        }
    }

    pub(crate) fn unchanged(&mut self) -> bool {
        match self {
            Self::Public(template) => template.unchanged(),
            Self::Protected(template) => template.unchanged(),
            Self::Typed(template) => template.unchanged(),
        }
    }
}
