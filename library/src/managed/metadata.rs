// SPDX-License-Identifier: Apache-2.0
//! Pure inventory format, shared by guarded and resident observation paths.

use super::*;
pub(super) struct Fields {
    values: [Attribute; 8],
    length: usize,
}
impl Fields {
    pub(super) fn as_slice(&self) -> &[Attribute] {
        &self.values[..self.length]
    }
}
pub(super) fn fields(class: ManagedClass, lifecycle: bool) -> Fields {
    let mut fields = [Attribute::Label; 8];
    let mut length = 0;
    let mut push = |field| {
        fields[length] = field;
        length += 1;
    };
    push(Attribute::Label);
    push(Attribute::UniqueId);
    if lifecycle {
        push(Attribute::Private);
        push(Attribute::Token);
    }
    let has_key_type = class.has_key_type() || matches!(class, ManagedClass::Other(_));
    let has_id = class.key() || class == ManagedClass::Certificate;
    if has_key_type {
        push(Attribute::KeyType);
    }
    if has_id {
        push(Attribute::Id);
    }
    if class == ManagedClass::Data {
        push(Attribute::Application);
        push(Attribute::ObjectType);
    }
    Fields {
        values: fields,
        length,
    }
}
// Inventory builds the read with fields(class, lifecycle), then publishes one
// value for every requested field, including unavailable attributes. The private
// reader keeps that count/order; only the matching Details phase calls row.
pub(super) fn row(
    class: ManagedClass,
    lifecycle: bool,
    values: Vec<AttributeValue>,
    budget: &mut usize,
) -> Result<ObjectMetadata> {
    let has_key_type = class.has_key_type() || matches!(class, ManagedClass::Other(_));
    let has_id = class.key() || class == ManagedClass::Certificate;
    for value in &values {
        if let AttributeValue::Available(bytes) = value {
            *budget = budget.checked_sub(bytes.len()).ok_or(Error::Rejected(
                crate::RejectionReason::ObjectSearch(
                    crate::ObjectSearchRejection::InventoryByteQuota,
                ),
            ))?;
        }
    }
    let mut values = values.into_iter();
    let (label, unique_id) = (
        values
            .next()
            .expect("inventory field count and order preserved"),
        values
            .next()
            .expect("inventory field count and order preserved"),
    );
    let (private, persistent) = if lifecycle {
        (
            values
                .next()
                .expect("inventory field count and order preserved"),
            values
                .next()
                .expect("inventory field count and order preserved"),
        )
    } else {
        (AttributeValue::NotRequested, AttributeValue::NotRequested)
    };
    let key_type = if has_key_type {
        values
            .next()
            .expect("inventory field count and order preserved")
    } else {
        AttributeValue::NotRequested
    };
    let id = if has_id {
        values
            .next()
            .expect("inventory field count and order preserved")
    } else {
        AttributeValue::NotRequested
    };
    let (application, object_type) = if class == ManagedClass::Data {
        (
            values
                .next()
                .expect("inventory field count and order preserved"),
            values
                .next()
                .expect("inventory field count and order preserved"),
        )
    } else {
        (AttributeValue::NotRequested, AttributeValue::NotRequested)
    };
    Ok(ObjectMetadata {
        class,
        key_type,
        id,
        label,
        unique_id,
        private,
        persistent,
        application,
        object_type,
        ambiguous: false,
    })
}

/// Preserve native discovery order for equal keys without the stable sort's
/// hidden scratch allocation. The caller has prepaid the ordinal index.
pub(super) fn sort(rows: &mut [ObjectMetadata], order: &mut Vec<usize>) -> Result<()> {
    if !order.is_empty() || order.capacity() < rows.len() {
        return Err(Error::Rejected(crate::RejectionReason::ObjectReferences(
            crate::ObjectReferencesRejection::InventorySortCapacity,
        )));
    }
    order.extend(0..rows.len());
    order.sort_unstable_by(|&left, &right| {
        let (a, b) = (&rows[left], &rows[right]);
        (
            a.class,
            &a.id,
            &a.application,
            &a.object_type,
            &a.label,
            &a.unique_id,
        )
            .cmp(&(
                b.class,
                &b.id,
                &b.application,
                &b.object_type,
                &b.label,
                &b.unique_id,
            ))
            .then_with(|| left.cmp(&right))
    });
    // order[destination] identifies the original source row. Rotate each
    // permutation cycle with swaps, then mark its entries as fixed points.
    // The index was built from 0..len, so every cycle terminates at its start.
    for start in 0..order.len() {
        let mut current = start;
        while order[current] != start {
            let next = order[current];
            rows.swap(current, next);
            order[current] = current;
            current = next;
        }
        order[current] = current;
    }
    for i in 1..rows.len() {
        let a = &rows[i - 1];
        let b = &rows[i];
        let same = a.class == b.class
            && if a.class == ManagedClass::Data {
                a.application == b.application
                    && a.object_type == b.object_type
                    && a.label == b.label
            } else {
                a.id == b.id
            };
        if same {
            rows[i - 1].ambiguous = true;
            rows[i].ambiguous = true;
        }
    }
    Ok(())
}
