// SPDX-License-Identifier: Apache-2.0
//! Prepaid thread-local identities for calls made by an external participant.
use crate::symmetric::memory::{Budget, ControlledReservation, Credit};
use crate::Result;
use std::{cell::RefCell, convert::Infallible, sync::Arc};

struct Node {
    image: usize,
    next: Option<PreparedScope>,
}

// Destruction order is part of accounting: the node leaves before its credit.
pub(super) struct PreparedScope {
    node: Box<Node>,
    _credit: Credit,
}
struct Images(Option<PreparedScope>);
impl Drop for Images {
    fn drop(&mut self) {
        // Forgotten guards do not turn thread teardown into recursive Drop.
        while let Some(mut entry) = self.0.take() {
            self.0 = entry.node.next.take();
            drop(entry);
        }
    }
}
thread_local! {
    static IMAGES: RefCell<Images> = const { RefCell::new(Images(None)) };
}

pub(crate) fn in_call(image: usize) -> bool {
    IMAGES.with(|images| {
        let images = images.borrow();
        let mut cursor = images.0.as_ref();
        while let Some(entry) = cursor {
            if entry.node.image == image {
                return true;
            }
            cursor = entry.node.next.as_ref();
        }
        false
    })
}

impl PreparedScope {
    /// Prepare outside module, token and session possession. The caller drops
    /// this candidate before waiting for any of those gates and replans after
    /// admission becomes possible, so another operation can obtain its memory.
    pub(super) fn new(
        image: usize,
        budget: &Arc<Budget>,
        mut validate: impl FnMut() -> Result<()>,
    ) -> Result<Self> {
        let credit = match budget.reserve_controlled::<Infallible>(
            std::mem::size_of::<Node>(),
            &crate::admission_wait::current(),
            || {
                validate()?;
                Ok(None)
            },
            || Ok(None),
        )? {
            ControlledReservation::Acquired(credit) => credit,
            ControlledReservation::Redirect(never) => match never {},
        };
        let node = crate::allocation::boxed(Node { image, next: None }).map_err(|_| {
            crate::Error::Rejected(crate::RejectionReason::ExternalExecution(
                crate::ExternalExecutionRejection::ForeignCallScopeAllocation,
            ))
        })?;
        Ok(Self {
            node,
            _credit: credit,
        })
    }

    /// Install only after all fallible admission checks have succeeded.
    pub(super) fn enter(mut self) -> CallScope {
        let identity = std::ptr::addr_of!(*self.node) as usize;
        IMAGES.with(|images| {
            let mut images = images.borrow_mut();
            self.node.next = images.0.take();
            images.0 = Some(self);
        });
        CallScope {
            identity,
            _thread: std::marker::PhantomData,
        }
    }
}

pub(super) struct CallScope {
    identity: usize,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
impl Drop for CallScope {
    fn drop(&mut self) {
        let removed = IMAGES.with(|images| {
            let mut images = images.borrow_mut();
            let mut cursor = &mut images.0;
            while let Some(entry) = cursor.as_ref() {
                if std::ptr::addr_of!(*entry.node) as usize == self.identity {
                    let mut removed = cursor.take().expect("observed call scope");
                    *cursor = removed.node.next.take();
                    return Some(removed);
                }
                cursor = &mut cursor.as_mut().expect("observed call scope").node.next;
            }
            None
        });
        // The native admission guards must already have left. End the TLS
        // borrow too before releasing credit, which can notify resource waiters.
        drop(removed);
    }
}
