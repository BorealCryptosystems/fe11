// SPDX-License-Identifier: Apache-2.0
//! Undispatched detachment controls, allocated outside source possession.
use super::{DetachControl, DetachedOperation};
use crate::advanced::{
    asynchronous::GetId,
    preparation, progress,
    state_io::{Inspection, StateIo},
};
use crate::symmetric::memory::{Buffer, ControlledReservation, Credit, UnboundBuffer};
use crate::{Error, Result, Session};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Shape {
    pub function: &'static str,
    pub preview_length: Option<usize>,
    pub inspection: bool,
}
pub(super) struct Prepared {
    pub shape: Shape,
    pub get_id: GetId,
    pub inspection: Option<Box<Inspection>>,
    pub preview: Option<Buffer>,
    pub control_credit: Credit,
    pub publication_credit: Credit,
}
pub(super) fn prepare(
    session: &Session,
    budget: &std::sync::Arc<crate::symmetric::memory::Budget>,
    shape: Shape,
    authentication: u64,
    waiter: &progress::Waiter<'_>,
) -> Result<Option<Prepared>> {
    let policy = crate::admission_wait::current();
    let fixed = GetId::allocation_bytes()
        .checked_add(std::mem::size_of::<DetachControl>() - std::mem::size_of::<GetId>())
        .and_then(|n| n.checked_add(std::mem::size_of::<DetachedOperation>()))
        .and_then(|n| {
            n.checked_add(if shape.inspection {
                StateIo::allocation_bytes()
            } else {
                0
            })
        })
        .ok_or(Error::Rejected(crate::RejectionReason::Detachment(
            crate::DetachmentRejection::DetachmentStorageAccounting,
        )))?;
    let mut required =
        fixed
            .checked_add(shape.preview_length.unwrap_or(0))
            .ok_or(Error::Rejected(crate::RejectionReason::Detachment(
                crate::DetachmentRejection::DetachmentStorageAccounting,
            )))?;
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
        let preview = shape
            .preview_length
            .map(UnboundBuffer::allocate)
            .transpose()?;
        let actual = fixed
            .checked_add(preview.as_ref().map_or(0, UnboundBuffer::allocated))
            .ok_or(Error::Rejected(crate::RejectionReason::Detachment(
                crate::DetachmentRejection::DetachmentStorageAccounting,
            )))?;
        if actual > required {
            drop(preview);
            drop(credit);
            required = actual;
            continue;
        }
        credit.release(required - actual);
        let preview = preview.map(|bytes| bytes.bind(&mut credit)).transpose()?;
        let get_id = GetId::new_prepaid(&mut credit, shape.function)?;
        let inspection = if shape.inspection {
            Some(Box::new(Inspection::new_prepaid(&mut credit)?))
        } else {
            None
        };
        let publication_credit = credit.split(std::mem::size_of::<DetachedOperation>())?;
        return Ok(Some(Prepared {
            shape,
            get_id,
            inspection,
            preview,
            control_credit: credit,
            publication_credit,
        }));
    }
}
