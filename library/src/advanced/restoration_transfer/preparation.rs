// SPDX-License-Identifier: Apache-2.0
//! Complete, unpublished restore-transfer storage, prepared without possession.
use super::{DetachedOperation, RestoreTransfer};
use crate::advanced::{asynchronous::GetId, preparation, progress};
use crate::symmetric::memory::{Buffer, ControlledReservation, Credit, UnboundBuffer};
use crate::{Error, Result, Session};
use fe11_sys::CK_SLOT_ID;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Shape {
    pub function: &'static str,
    pub source_slot: CK_SLOT_ID,
    pub preview_length: usize,
    pub record_length: usize,
}
pub(super) struct Publication {
    pub record: Buffer,
    pub credit: Credit,
}
pub(super) struct Prepared {
    pub shape: Shape,
    pub get_id: GetId,
    pub preview: Buffer,
    pub publication: Publication,
    pub control_credit: Credit,
}
pub(super) fn prepare(
    session: &Session,
    budget: &std::sync::Arc<crate::symmetric::memory::Budget>,
    shape: Shape,
    authentication: u64,
    waiter: &progress::Waiter<'_>,
) -> Result<Option<Prepared>> {
    let policy = crate::admission_wait::current();
    let metadata = GetId::allocation_bytes()
        .checked_add(std::mem::size_of::<RestoreTransfer>() - std::mem::size_of::<GetId>())
        .and_then(|n| n.checked_add(std::mem::size_of::<DetachedOperation>()))
        .ok_or(Error::Rejected(crate::RejectionReason::Restoration(
            crate::RestorationRejection::TransferStorageAccounting,
        )))?;
    let total = |preview: usize, record: usize| {
        metadata
            .checked_add(preview)
            .and_then(|n| n.checked_add(record))
            .ok_or(Error::Rejected(crate::RejectionReason::Restoration(
                crate::RestorationRejection::TransferStorageAccounting,
            )))
    };
    let mut required = total(shape.preview_length, shape.record_length)?;
    loop {
        let mut credit = match budget.reserve_controlled_retaining(
            required,
            crate::session::lifecycle_diagnostics::Store::allocation_bytes(),
            &policy,
            || {
                preparation::context(session)?;
                session
                    .snapshot
                    .observe_authentication_unchanged(authentication)?;
                Ok(waiter.changed().then_some(()))
            },
            || Ok(None),
        )? {
            ControlledReservation::Acquired(credit) => credit,
            ControlledReservation::Redirect(()) => return Ok(None),
        };
        let preview = UnboundBuffer::allocate(shape.preview_length)?;
        let record = UnboundBuffer::allocate(shape.record_length)?;
        let actual = total(preview.allocated(), record.allocated())?;
        if actual > required {
            // Release the whole unpublished graph and its credit before retry.
            drop(record);
            drop(preview);
            drop(credit);
            required = actual;
            continue;
        }
        credit.release(required - actual);
        let preview = preview.bind(&mut credit)?;
        let record = record.bind(&mut credit)?;
        let get_id = GetId::new_prepaid(&mut credit, shape.function)?;
        let control_credit =
            credit.split(std::mem::size_of::<RestoreTransfer>() - std::mem::size_of::<GetId>())?;
        return Ok(Some(Prepared {
            shape,
            get_id,
            preview,
            control_credit,
            publication: Publication { record, credit },
        }));
    }
}
