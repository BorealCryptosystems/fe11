// SPDX-License-Identifier: Apache-2.0
//! Empty candidates for historical public metadata reads.
use super::*;
use crate::{
    symmetric::memory::{Budget, ControlledReservation},
    ResourceAdmission,
};
use std::{mem::size_of, sync::Arc};

pub(crate) struct Storage {
    kinds: Vec<CK_ATTRIBUTE_TYPE>,
    descriptors: Vec<CK_ATTRIBUTE>,
    indices: Vec<usize>,
    buffers: Vec<Option<AlignedOutput>>,
    fields: Vec<CK_ATTRIBUTE_TYPE>,
    unique: Vec<CK_ATTRIBUTE_TYPE>,
    values: Vec<PreciseAttributeValue>,
    retained: Vec<Option<(AlignedOutput, usize)>>,
    export: AttributeSnapshot,
    diagnostic: crate::error::CompletionStorage,
}

// SAFETY: every private descriptor has a null pValue and zero length. Storage
// exposes no descriptor or payload access and is never passed to C. Binding
// consumes it into ReadCall before pointers are installed; that native owner
// enforces its own stable-allocation and access contract.
unsafe impl Send for Storage {}

fn size(counts: [usize; 8]) -> Result<usize> {
    let widths = [
        size_of::<CK_ATTRIBUTE_TYPE>(),
        size_of::<CK_ATTRIBUTE>(),
        size_of::<usize>(),
        size_of::<Option<AlignedOutput>>(),
        size_of::<CK_ATTRIBUTE_TYPE>(),
        size_of::<CK_ATTRIBUTE_TYPE>(),
        size_of::<PreciseAttributeValue>(),
        size_of::<Option<(AlignedOutput, usize)>>(),
    ];
    counts.into_iter().zip(widths).try_fold(
        size_of::<ReadCall>()
            + SessionFrame::<'static, ReadCall>::allocation_bytes()
            + crate::error::CompletionStorage::allocation_bytes(),
        |sum, (count, width)| {
            count
                .checked_mul(width)
                .and_then(|bytes| sum.checked_add(bytes))
                .ok_or(Error::Rejected(
                    crate::RejectionReason::AttributePreparation(
                        crate::AttributePreparationRejection::AttributeObservationStorageSize,
                    ),
                ))
        },
    )
}

impl Storage {
    fn resident_bytes(&self) -> Result<usize> {
        [
            (self.fields.capacity(), size_of::<CK_ATTRIBUTE_TYPE>()),
            (self.unique.capacity(), size_of::<CK_ATTRIBUTE_TYPE>()),
            (self.values.capacity(), size_of::<PreciseAttributeValue>()),
            (
                self.retained.capacity(),
                size_of::<Option<(AlignedOutput, usize)>>(),
            ),
        ]
        .into_iter()
        .try_fold(0usize, |sum, (count, width)| {
            count
                .checked_mul(width)
                .and_then(|bytes| sum.checked_add(bytes))
                .ok_or(Error::Rejected(
                    crate::RejectionReason::AttributePreparation(
                        crate::AttributePreparationRejection::AttributeResidentStorageSize,
                    ),
                ))
        })
    }
    /// Plan a closed set of distinct fields without allocating their descriptor
    /// list. The eventual recipe validates the supplied fields before binding.
    pub(crate) fn requested_unique(count: usize) -> Result<usize> {
        size([count; 8])
    }
    pub(crate) fn requested(recipe: Recipe<'_>) -> Result<usize> {
        let unique = recipe.unique_len();
        let retained = unique;
        size([
            unique,
            unique,
            unique,
            unique,
            recipe.len(),
            unique,
            unique,
            retained,
        ])?
        .checked_add(AttributeSnapshot::requested(recipe.export_len())?)
        .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
            crate::KeyAdmissionRejection::AttributeProjectionStorageSize,
        )))
    }
    pub(crate) fn allocate(recipe: Recipe<'_>) -> Result<Self> {
        let mut unique = reserved(recipe.unique_len())?;
        for index in 0..recipe.len() {
            let field = recipe.field(index);
            if !unique.contains(&field) {
                unique.push(field);
            }
        }
        let mut kinds = reserved(unique.len())?;
        let mut descriptors = reserved(unique.len())?;
        let mut indices = reserved(unique.len())?;
        let mut buffers = reserved(unique.len())?;
        let mut values = reserved(unique.len())?;
        let mut retained = reserved(unique.len())?;
        for (index, kind) in unique.iter().copied().enumerate() {
            kinds.push(kind);
            descriptors.push(CK_ATTRIBUTE {
                r#type: kind,
                pValue: std::ptr::null_mut(),
                ulValueLen: 0,
            });
            indices.push(index);
            buffers.push(None);
            values.push(PreciseAttributeValue::Indeterminate);
            retained.push(None);
        }
        let mut original = reserved(recipe.len())?;
        original.extend((0..recipe.len()).map(|index| recipe.field(index)));
        Ok(Self {
            kinds,
            descriptors,
            indices,
            buffers,
            fields: original,
            unique,
            values,
            retained,
            export: AttributeSnapshot::allocate(recipe)?,
            diagnostic: crate::error::CompletionStorage::allocate()?,
        })
    }
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        size([
            self.kinds.capacity(),
            self.descriptors.capacity(),
            self.indices.capacity(),
            self.buffers.capacity(),
            self.fields.capacity(),
            self.unique.capacity(),
            self.values.capacity(),
            self.retained.capacity(),
        ])?
        .checked_add(self.export.allocated_bytes()?)
        .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
            crate::KeyAdmissionRejection::AttributeProjectionStorageSize,
        )))
    }
    pub(crate) fn bind(
        self,
        prepaid: &mut Credit,
        recipe: Recipe<'_>,
        handle: CK_OBJECT_HANDLE,
        authentication: Option<u64>,
        reader: crate::registry::ReadPermit,
    ) -> Result<LegacyOwner> {
        self.bind_with_protection(
            prepaid,
            recipe,
            handle,
            authentication,
            ObservationProtection::object(reader),
        )
    }
    /// The enclosing inventory retains this exact catalogue protection across
    /// every child read and wait. No unprotected raw-handle constructor is exposed.
    pub(crate) fn bind_inventory(
        self,
        prepaid: &mut Credit,
        recipe: Recipe<'_>,
        handle: CK_OBJECT_HANDLE,
        authentication: Option<u64>,
        session: &crate::Session,
        inventory: &crate::managed::InventoryGuard,
    ) -> Result<LegacyOwner> {
        let protection = ObservationProtection::inventory(session, inventory)?;
        self.bind_with_protection(prepaid, recipe, handle, authentication, protection)
    }
    pub(crate) fn bind_with_protection(
        self,
        prepaid: &mut Credit,
        recipe: Recipe<'_>,
        handle: CK_OBJECT_HANDLE,
        authentication: Option<u64>,
        protection: ObservationProtection,
    ) -> Result<LegacyOwner> {
        let credit = prepaid.split(self.allocated_bytes()?)?;
        Ok(self.into_prepaid(credit, recipe, handle, authentication, protection))
    }

    /// Transfer a storage graph whose exact allocated_bytes() share was
    /// already split by the enclosing candidate. No fallible step remains.
    pub(crate) fn into_prepaid(
        self,
        mut credit: Credit,
        recipe: Recipe<'_>,
        handle: CK_OBJECT_HANDLE,
        authentication: Option<u64>,
        protection: ObservationProtection,
    ) -> LegacyOwner {
        // The caller supplied allocated_bytes(), which includes these exact
        // capacities. Keep their share with the resident tables, not with the
        // temporary native call: an ordinary native error may destroy that call
        // while the observation registry still owns the tables.
        let resident_bytes = self
            .resident_bytes()
            .expect("resident capacities already accounted");
        let export = self
            .export
            .bind(&mut credit)
            .expect("complete projection credit supplied");
        let resident_credit = credit
            .split(resident_bytes)
            .expect("complete metadata credit supplied");
        LegacyOwner {
            state: ReadState::Size(ReadCall {
                kinds: self.kinds,
                descriptors: self.descriptors,
                indices: self.indices,
                buffers: self.buffers,
                diagnostic: Some(self.diagnostic),
                _credit: credit,
            }),
            request: recipe.request(),
            fields: self.fields,
            kinds: self.unique,
            values: self.values,
            retained: self.retained,
            export,
            mechanisms: None,
            plan: recipe.plan(),
            output: recipe.output(),
            handle,
            authentication,
            total: 0,
            next_clarification: 0,
            _protection: protection,
            _credit: resident_credit,
        }
    }
}

pub(crate) fn prepare_value(
    need: ValueNeed,
    budget: &Arc<Budget>,
    policy: &ResourceAdmission,
    mut check: impl FnMut() -> Result<()>,
) -> Result<ValueCandidate> {
    let length = match need {
        ValueNeed::Native { length, .. } => length,
        ValueNeed::PublicCopy { length, .. } => {
            return PublicCopy::prepare(length, budget, policy, check)
                .map(ValueCandidate::PublicCopy);
        }
        ValueNeed::Mechanisms { length } => {
            return MechanismCopy::prepare(length, budget, policy, check)
                .map(ValueCandidate::Mechanisms);
        }
    };
    let width = size_of::<CK_ULONG>();
    let mut required = length
        .checked_add(width - 1)
        .map(|bytes| bytes / width * width)
        .ok_or(Error::Rejected(
            crate::RejectionReason::AttributePreparation(
                crate::AttributePreparationRejection::AttributeAlignmentSize,
            ),
        ))?;
    loop {
        let mut credit = match budget.reserve_controlled_retaining(
            required,
            crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
            policy,
            || {
                check()?;
                Ok(None::<()>)
            },
            || Ok(None),
        )? {
            ControlledReservation::Acquired(credit) => credit,
            ControlledReservation::Redirect(()) => unreachable!("no redirect requested"),
        };
        let storage = AlignedOutput::new(length)?;
        let actual = storage.allocated_bytes()?;
        if actual > required {
            drop(storage);
            drop(credit);
            required = actual;
            continue;
        }
        credit.release(required - actual);
        return storage
            .bind_prepaid(&mut credit)
            .map(ValueCandidate::Native);
    }
}
