// SPDX-License-Identifier: Apache-2.0
//! The same public-template recipe counts storage before it materializes it.
//! Planning reads only borrowed public/policy values and allocates nothing.
use super::{InputValue, OwnedTemplate, Template};
use crate::{bounds, Error, Result};
use fe11_sys::{CK_ATTRIBUTE, CK_ATTRIBUTE_TYPE, CK_MECHANISM_TYPE, CK_ULONG};
use std::mem::size_of;

pub(crate) trait TemplateSink: Sized {
    fn empty() -> Self;
    fn bytes(&mut self, kind: CK_ATTRIBUTE_TYPE, value: &[u8]);
    fn byte_parts(&mut self, kind: CK_ATTRIBUTE_TYPE, value: super::ByteParts<'_>);
    fn boolean(&mut self, kind: CK_ATTRIBUTE_TYPE, value: bool);
    fn integer(&mut self, kind: CK_ATTRIBUTE_TYPE, value: CK_ULONG);
    fn mechanisms(&mut self, kind: CK_ATTRIBUTE_TYPE, value: &[CK_MECHANISM_TYPE]) -> Result<()>;
    fn mechanism_numbers(&mut self, kind: CK_ATTRIBUTE_TYPE, values: &[u64]) -> Result<()>;
    fn identity_parts(
        &mut self,
        field: crate::IdentityAttribute,
        value: super::ByteParts<'_>,
    ) -> Result<()> {
        if let Some(bytes) = value.contiguous() {
            return self.identity_attribute(field, bytes);
        }
        if matches!(
            field,
            crate::IdentityAttribute::Class | crate::IdentityAttribute::KeyType
        ) {
            return Err(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::ReferenceTemplateIntegerWidth,
                ),
            ));
        }
        self.byte_parts(field.attribute().raw(), value);
        Ok(())
    }
    fn identity_attribute(&mut self, field: crate::IdentityAttribute, value: &[u8]) -> Result<()> {
        match field {
            crate::IdentityAttribute::Class | crate::IdentityAttribute::KeyType => {
                self.integer(
                    field.attribute().raw(),
                    CK_ULONG::from_ne_bytes(value.try_into().map_err(|_| {
                        Error::Rejected(crate::RejectionReason::AttributePreparation(
                            crate::AttributePreparationRejection::ReferenceTemplateIntegerWidth,
                        ))
                    })?),
                );
            }
            _ => self.bytes(field.attribute().raw(), value),
        }
        Ok(())
    }
}
impl TemplateSink for Template {
    fn mechanism_numbers(&mut self, kind: CK_ATTRIBUTE_TYPE, values: &[u64]) -> Result<()> {
        if let Some(cause) = self.1 {
            return Err(Error::Rejected(cause));
        }
        let mut native = Vec::new();
        native.try_reserve_exact(values.len()).map_err(|_| {
            Error::Rejected(crate::RejectionReason::Mechanisms(
                crate::MechanismsRejection::MechanismRequestAllocation,
            ))
        })?;
        for value in values {
            native.push(CK_MECHANISM_TYPE::try_from(*value).map_err(|_| {
                Error::Rejected(crate::RejectionReason::Mechanisms(
                    crate::MechanismsRejection::MechanismRequestWidth,
                ))
            })?);
        }
        self.0.try_reserve(1).map_err(|_| {
            Error::Rejected(crate::RejectionReason::AttributePreparation(
                crate::AttributePreparationRejection::TemplateDescriptorAllocation,
            ))
        })?;
        self.0.push((kind, InputValue::Mechanisms(native)));
        Ok(())
    }
    fn identity_parts(
        &mut self,
        field: crate::IdentityAttribute,
        value: super::ByteParts<'_>,
    ) -> Result<()> {
        self.try_identity_parts(field, value)
    }
    fn byte_parts(&mut self, kind: CK_ATTRIBUTE_TYPE, value: super::ByteParts<'_>) {
        if self.1.is_some() {
            return;
        }
        if bounds::ck_length(value.len()).is_err() {
            self.1 = Some(crate::RejectionReason::AttributePreparation(
                crate::AttributePreparationRejection::TemplateByteLengthConversion,
            ));
            return;
        }
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(value.len()).is_err() {
            self.1 = Some(crate::RejectionReason::AttributePreparation(
                crate::AttributePreparationRejection::TemplateByteAllocation,
            ));
            return;
        }
        for segment in value.segments() {
            bytes.extend_from_slice(segment);
        }
        self.push(kind, InputValue::Bytes(bytes));
    }

    fn identity_attribute(&mut self, field: crate::IdentityAttribute, value: &[u8]) -> Result<()> {
        self.try_identity_attribute(field, value)
    }

    fn empty() -> Self {
        Self::new()
    }
    fn bytes(&mut self, kind: CK_ATTRIBUTE_TYPE, value: &[u8]) {
        self.bytes(kind, value);
    }
    fn boolean(&mut self, kind: CK_ATTRIBUTE_TYPE, value: bool) {
        self.boolean(kind, value);
    }
    fn integer(&mut self, kind: CK_ATTRIBUTE_TYPE, value: CK_ULONG) {
        self.integer(kind, value);
    }
    fn mechanisms(&mut self, kind: CK_ATTRIBUTE_TYPE, value: &[CK_MECHANISM_TYPE]) -> Result<()> {
        self.mechanisms(kind, value)
    }
}

/// Known minimum capacities, before any allocator-selected excess exists.
pub(crate) struct TemplateSize {
    fields: usize,
    payload: usize,
    error: Option<crate::RejectionReason>,
}
impl TemplateSize {
    pub(crate) fn attribute_count(&self) -> Result<usize> {
        self.owned_bytes()?;
        Ok(self.fields)
    }

    fn add(&mut self, payload: usize) {
        if self.error.is_some() {
            return;
        }
        match (
            self.fields.checked_add(1),
            self.payload.checked_add(payload),
        ) {
            (Some(fields), Some(payload)) => {
                self.fields = fields;
                self.payload = payload;
            }
            _ => {
                self.error = Some(crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::TemplateAllocationSize,
                ))
            }
        }
    }
    pub(crate) fn owned_bytes(&self) -> Result<usize> {
        if let Some(error) = self.error {
            return Err(Error::Rejected(error));
        }
        bounds::ck_length(self.fields)?;
        self.fields
            .checked_mul(
                2 * size_of::<(CK_ATTRIBUTE_TYPE, InputValue)>() + size_of::<CK_ATTRIBUTE>(),
            )
            .and_then(|n| self.payload.checked_mul(2).and_then(|p| n.checked_add(p)))
            .and_then(|n| n.checked_add(size_of::<OwnedTemplate>()))
            .ok_or(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::TemplateAllocationSize,
                ),
            ))
    }
}
impl TemplateSink for TemplateSize {
    fn mechanism_numbers(&mut self, _kind: CK_ATTRIBUTE_TYPE, values: &[u64]) -> Result<()> {
        if let Some(error) = self.error {
            return Err(Error::Rejected(error));
        }
        let bytes = values
            .len()
            .checked_mul(size_of::<CK_MECHANISM_TYPE>())
            .ok_or(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::TemplateAllocationSize,
                ),
            ))?;
        bounds::ck_length(bytes)?;
        for value in values {
            CK_MECHANISM_TYPE::try_from(*value).map_err(|_| {
                Error::Rejected(crate::RejectionReason::Mechanisms(
                    crate::MechanismsRejection::MechanismRequestWidth,
                ))
            })?;
        }
        self.add(bytes);
        match self.error {
            Some(error) => Err(Error::Rejected(error)),
            None => Ok(()),
        }
    }
    fn byte_parts(&mut self, _kind: CK_ATTRIBUTE_TYPE, value: super::ByteParts<'_>) {
        if bounds::ck_length(value.len()).is_err() {
            self.error
                .get_or_insert(crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::TemplateByteLengthConversion,
                ));
        } else {
            self.add(value.len());
        }
    }

    fn empty() -> Self {
        Self {
            fields: 0,
            payload: 0,
            error: None,
        }
    }
    fn bytes(&mut self, _kind: CK_ATTRIBUTE_TYPE, value: &[u8]) {
        if bounds::ck_length(value.len()).is_err() {
            self.error
                .get_or_insert(crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::TemplateByteLengthConversion,
                ));
        } else {
            self.add(value.len());
        }
    }
    fn boolean(&mut self, _kind: CK_ATTRIBUTE_TYPE, _value: bool) {
        self.add(0);
    }
    fn integer(&mut self, _kind: CK_ATTRIBUTE_TYPE, _value: CK_ULONG) {
        self.add(0);
    }
    fn mechanisms(&mut self, _kind: CK_ATTRIBUTE_TYPE, value: &[CK_MECHANISM_TYPE]) -> Result<()> {
        if let Some(error) = self.error {
            return Err(Error::Rejected(error));
        }
        let bytes = value
            .len()
            .checked_mul(size_of::<CK_MECHANISM_TYPE>())
            .ok_or(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::TemplateAllocationSize,
                ),
            ))?;
        bounds::ck_length(bytes)?;
        self.add(bytes);
        if let Some(error) = self.error {
            return Err(Error::Rejected(error));
        }
        Ok(())
    }
}

/// Complete unpublished input/witness/descriptor graph. Allocation occurs only
/// after the enclosing owner has admitted TemplateSize::owned_bytes().
pub(crate) struct OwnedTemplateStorage {
    template: Template,
    witness: Template,
    descriptors: Vec<CK_ATTRIBUTE>,
}
// SAFETY: descriptors refer only to the owned template's heap allocations,
// including scalar values stored inside its vector. The private template cannot
// grow or mutate after allocation. Moving this unpublished owner, or consuming
// it into OwnedTemplate, preserves every allocation and grants no shared access.
unsafe impl Send for OwnedTemplateStorage {}
impl OwnedTemplateStorage {
    pub(crate) fn allocate(mut template: Template) -> Result<Self> {
        let witness = template.try_duplicate()?;
        let descriptors = template.descriptors()?;
        Ok(Self {
            template,
            witness,
            descriptors,
        })
    }
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        let templates = self
            .template
            .retained_bytes()?
            .checked_add(self.witness.retained_bytes()?)
            .ok_or(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::TemplateAllocationSize,
                ),
            ))?;
        self.descriptors
            .capacity()
            .checked_mul(size_of::<CK_ATTRIBUTE>())
            .and_then(|n| n.checked_add(templates))
            .and_then(|n| n.checked_add(size_of::<OwnedTemplate>() - 2 * size_of::<Template>()))
            .ok_or(Error::Rejected(
                crate::RejectionReason::AttributePreparation(
                    crate::AttributePreparationRejection::TemplateAllocationSize,
                ),
            ))
    }
    pub(crate) fn bind(
        self,
        prepaid: &mut crate::symmetric::memory::Credit,
    ) -> Result<OwnedTemplate> {
        let credit = prepaid.split(self.allocated_bytes()?)?;
        Ok(self.into_prepaid(credit))
    }

    /// Transfer after the enclosing preparation has split exactly
    /// allocated_bytes(). No validation, allocation or resource wait remains.
    pub(crate) fn into_prepaid(self, credit: crate::symmetric::memory::Credit) -> OwnedTemplate {
        OwnedTemplate {
            template: self.template,
            witness: self.witness,
            descriptors: self.descriptors,
            _credit: credit,
        }
    }
}

impl Template {
    /// Size the same public recipe before cloning either input or witness.
    pub(crate) fn owned_storage_bytes(&self) -> Result<usize> {
        let mut size = TemplateSize::empty();
        for (kind, value) in &self.0 {
            match value {
                InputValue::Bytes(value) => size.bytes(*kind, value),
                InputValue::Boolean(value) => size.boolean(*kind, *value != 0),
                InputValue::Integer(value) => size.integer(*kind, *value),
                InputValue::Mechanisms(value) => size.mechanisms(*kind, value)?,
            }
        }
        size.owned_bytes()
    }
}
