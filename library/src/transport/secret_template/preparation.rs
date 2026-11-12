// SPDX-License-Identifier: Apache-2.0
//! Allocate the entire private template without copying secret bytes. Every
//! sibling is measured before binding; an excess discards the complete graph.
use super::*;
use crate::attributes::{OwnedTemplate, TemplateSize};
use crate::symmetric::memory::UnboundBuffer;
use std::mem::size_of;

type EmptyComponent = (CK_ATTRIBUTE_TYPE, UnboundBuffer, UnboundBuffer);
type DescriptorWitness = (CK_ATTRIBUTE_TYPE, CK_VOID_PTR, CK_ULONG);

pub(crate) struct NativeSecretStorage<'a> {
    public: Template,
    public_witness: Template,
    public_descriptors: Vec<CK_ATTRIBUTE>,
    native: Vec<CK_ATTRIBUTE>,
    expected: Vec<DescriptorWitness>,
    components: Vec<(CK_ATTRIBUTE_TYPE, Buffer)>,
    witnesses: Vec<Buffer>,
    empty: Vec<EmptyComponent>,
    identifiers: Vec<CK_ATTRIBUTE_TYPE>,
    source: &'a [(CK_ATTRIBUTE_TYPE, &'a [u8])],
    // A bind failure must drop every unbound sibling before releasing credit.
    credit: Option<Credit>,
}

fn add(size: usize, count: usize, width: usize) -> Result<usize> {
    count
        .checked_mul(width)
        .and_then(|bytes| size.checked_add(bytes))
        .ok_or(Error::Rejected(crate::RejectionReason::KeyTransport(
            crate::KeyTransportRejection::PrivateTemplateStorageSize,
        )))
}

fn reserve<T>(count: usize) -> Result<Vec<T>> {
    let mut values = Vec::new();
    values.try_reserve_exact(count).map_err(|_| {
        Error::Rejected(crate::RejectionReason::KeyTransport(
            crate::KeyTransportRejection::PrivateTemplateStorageAllocation,
        ))
    })?;
    Ok(values)
}

impl<'a> NativeSecretStorage<'a> {
    pub(crate) fn allocation_bytes(
        public: &TemplateSize,
        components: &[(CK_ATTRIBUTE_TYPE, &[u8])],
    ) -> Result<usize> {
        let count = public
            .attribute_count()?
            .checked_add(components.len())
            .ok_or(Error::Rejected(crate::RejectionReason::KeyTransport(
                crate::KeyTransportRejection::TransportAttributeCountOverflow,
            )))?;
        bounds::ck_length(count)?;
        let mut size = public
            .owned_bytes()?
            .checked_sub(size_of::<OwnedTemplate>())
            .and_then(|bytes| bytes.checked_add(size_of::<NativeSecretTemplate>()))
            .ok_or(Error::Rejected(crate::RejectionReason::KeyTransport(
                crate::KeyTransportRejection::PrivateTemplateStorageSize,
            )))?;
        for width in [
            size_of::<CK_ATTRIBUTE>(),
            size_of::<DescriptorWitness>(),
            size_of::<CK_ATTRIBUTE_TYPE>(),
        ] {
            size = add(size, count, width)?;
        }
        for width in [
            size_of::<(CK_ATTRIBUTE_TYPE, Buffer)>(),
            size_of::<Buffer>(),
            size_of::<EmptyComponent>(),
        ] {
            size = add(size, components.len(), width)?;
        }
        for (_, bytes) in components {
            bounds::ck_length(bytes.len())?;
            size = add(size, bytes.len(), 2)?;
        }
        Ok(size)
    }

    pub(crate) fn allocate(
        mut public: Template,
        source: &'a [(CK_ATTRIBUTE_TYPE, &'a [u8])],
    ) -> Result<Self> {
        let public_descriptors = public.descriptors()?;
        let count = public_descriptors
            .len()
            .checked_add(source.len())
            .ok_or(Error::Rejected(crate::RejectionReason::KeyTransport(
                crate::KeyTransportRejection::TransportAttributeCountOverflow,
            )))?;
        bounds::ck_length(count)?;
        let mut identifiers = reserve(count)?;
        for descriptor in &public_descriptors {
            if private_field(descriptor.r#type) {
                return Err(Error::Rejected(crate::RejectionReason::KeyTransport(
                    crate::KeyTransportRejection::TransportPublicTemplateField,
                )));
            }
            identifiers.push(descriptor.r#type);
        }
        for (kind, bytes) in source {
            if !private_field(*kind) {
                return Err(Error::Rejected(crate::RejectionReason::KeyTransport(
                    crate::KeyTransportRejection::TransportPrivateTemplateField,
                )));
            }
            bounds::ck_length(bytes.len())?;
            identifiers.push(*kind);
        }
        identifiers.sort_unstable();
        if identifiers.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(Error::Rejected(crate::RejectionReason::KeyTransport(
                crate::KeyTransportRejection::TransportDuplicateTemplateField,
            )));
        }
        if source
            .iter()
            .any(|(kind, _)| matches!(*kind, CKA_SEED | CKA_VALUE))
            && source
                .iter()
                .any(|(kind, _)| !matches!(*kind, CKA_SEED | CKA_VALUE))
        {
            return Err(Error::Rejected(crate::RejectionReason::KeyTransport(
                crate::KeyTransportRejection::TransportMixedPrivateRepresentations,
            )));
        }
        let public_witness = public.try_duplicate()?;
        let mut empty = reserve(source.len())?;
        for (kind, bytes) in source {
            empty.push((
                *kind,
                UnboundBuffer::allocate(bytes.len())?,
                UnboundBuffer::allocate(bytes.len())?,
            ));
        }
        Ok(Self {
            public,
            public_witness,
            public_descriptors,
            native: reserve(count)?,
            expected: reserve(count)?,
            components: reserve(source.len())?,
            witnesses: reserve(source.len())?,
            empty,
            identifiers,
            source,
            credit: None,
        })
    }

    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        let mut size = size_of::<NativeSecretTemplate>() - 2 * size_of::<Template>();
        let witness_bytes = self.public_witness.retained_bytes()?;
        size = size
            .checked_add(self.public.retained_bytes()?)
            .and_then(|bytes| bytes.checked_add(witness_bytes))
            .ok_or(Error::Rejected(crate::RejectionReason::KeyTransport(
                crate::KeyTransportRejection::PrivateTemplateStorageSize,
            )))?;
        for (count, width) in [
            (
                self.public_descriptors.capacity(),
                size_of::<CK_ATTRIBUTE>(),
            ),
            (self.native.capacity(), size_of::<CK_ATTRIBUTE>()),
            (self.expected.capacity(), size_of::<DescriptorWitness>()),
            (
                self.components.capacity(),
                size_of::<(CK_ATTRIBUTE_TYPE, Buffer)>(),
            ),
            (self.witnesses.capacity(), size_of::<Buffer>()),
            (self.empty.capacity(), size_of::<EmptyComponent>()),
            (self.identifiers.capacity(), size_of::<CK_ATTRIBUTE_TYPE>()),
        ] {
            size = add(size, count, width)?;
        }
        for (_, value, witness) in &self.empty {
            size = add(size, value.allocated(), 1)?;
            size = add(size, witness.allocated(), 1)?;
        }
        Ok(size)
    }

    pub(crate) fn bind(mut self, prepaid: &mut Credit) -> Result<NativeSecretTemplate> {
        let scratch = add(
            add(0, self.empty.capacity(), size_of::<EmptyComponent>())?,
            self.identifiers.capacity(),
            size_of::<CK_ATTRIBUTE_TYPE>(),
        )?;
        let scratch = add(
            scratch,
            self.public_descriptors.capacity(),
            size_of::<CK_ATTRIBUTE>(),
        )?;
        self.credit = Some(prepaid.split(self.allocated_bytes()?)?);
        let credit = self.credit.as_mut().expect("private graph credit attached");
        // Moving final vectors into locals only after attaching credit ensures
        // partial bindings erase and free them before the remaining graph credit.
        let mut components = std::mem::take(&mut self.components);
        let mut witnesses = std::mem::take(&mut self.witnesses);
        for ((kind, value, witness), (_, source)) in self.empty.drain(..).zip(self.source) {
            let mut value = value.bind(credit)?;
            let mut witness = witness.bind(credit)?;
            value.as_mut().copy_from_slice(source);
            witness.as_mut().copy_from_slice(source);
            components.push((kind, value));
            witnesses.push(witness);
        }
        self.native
            .extend(self.public_descriptors.iter().map(|field| CK_ATTRIBUTE {
                r#type: field.r#type,
                pValue: field.pValue,
                ulValueLen: field.ulValueLen,
            }));
        for (kind, value) in &mut components {
            self.native.push(CK_ATTRIBUTE {
                r#type: *kind,
                pValue: value.as_mut().as_mut_ptr().cast(),
                ulValueLen: bounds::ck_length(value.capacity())?,
            });
        }
        self.expected.extend(
            self.native
                .iter()
                .map(|field| (field.r#type, field.pValue, field.ulValueLen)),
        );
        // Descriptor entries were copied above; their referents remain in public.
        // Validation and unbound-allocation metadata also cease to be needed.
        // Free each scratch array before returning its share of the graph credit.
        drop(std::mem::take(&mut self.empty));
        drop(std::mem::take(&mut self.identifiers));
        drop(std::mem::take(&mut self.public_descriptors));
        credit.release(scratch);
        // NativeSecretTemplate drops its complete data graph before this credit.
        // The former inner credit has no allocation to account for separately.
        let inner_credit = credit.split(0)?;
        Ok(NativeSecretTemplate {
            inner: SecretTemplate {
                _public: self.public,
                components,
                _descriptor_credit: inner_credit,
            },
            native: self.native,
            expected: self.expected,
            public_witness: self.public_witness,
            secret_witnesses: witnesses,
            _credit: self
                .credit
                .take()
                .expect("private graph credit transferred"),
        })
    }
}
