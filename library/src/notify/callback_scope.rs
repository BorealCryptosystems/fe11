// SPDX-License-Identifier: Apache-2.0
//! Thread-local callback identities with storage charged to the owning module.
use crate::symmetric::memory::{Budget, ControlledReservation, Credit};
use std::{
    cell::{Cell, RefCell},
    convert::Infallible,
    sync::Arc,
};

// Each live scope owns one stable node. The TLS chain owns nodes, while scopes
// retain only their identity. Removing a middle node supports foreign guards
// dropped out of nesting order without keeping an inactive allocation alive.
struct Node {
    image: usize,
    next: Option<CreditedNode>,
}
struct CreditedNode {
    node: Box<Node>,
    // Field order frees the allocation before returning its credit.
    _credit: Credit,
}
struct Images {
    head: Option<CreditedNode>,
}
impl Drop for Images {
    fn drop(&mut self) {
        // Safe Rust permits forgetting a scope. Thread exit must release any
        // remaining chain with bounded stack use, before refunding each node.
        while let Some(mut entry) = self.head.take() {
            self.head = entry.node.next.take();
            drop(entry);
        }
    }
}
thread_local! {
    static DEPTH: Cell<usize> = const { Cell::new(0) };
    static IMAGES: RefCell<Images> = const { RefCell::new(Images { head: None }) };
}

pub(crate) fn in_callback() -> bool {
    DEPTH.with(|depth| depth.get() != 0)
}

pub(crate) fn in_callback_for(image: usize) -> bool {
    IMAGES.with(|images| {
        let images = images.borrow();
        let mut cursor = images.head.as_ref();
        while let Some(entry) = cursor {
            if entry.node.image == image {
                return true;
            }
            cursor = entry.node.next.as_ref();
        }
        false
    })
}

pub(crate) struct CallbackScope {
    // The stable address identifies a node; it is never dereferenced here.
    node: Option<usize>,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl CallbackScope {
    pub(crate) fn enter(image: Option<usize>, budget: &Arc<Budget>) -> Option<Self> {
        let depth = DEPTH.with(|depth| depth.get().checked_add(1))?;
        let node = if let Some(image) = image {
            // A callback cannot wait for an operation that it is interrupting.
            // Allocation failure follows the existing callback refusal path.
            let credit = match crate::admission_wait::current()
                .try_once(|| {
                    budget.reserve_controlled::<Infallible>(
                        std::mem::size_of::<Node>(),
                        &crate::ResourceAdmission::Immediate,
                        || Ok(None),
                        || Ok(None),
                    )
                })
                .ok()?
            {
                ControlledReservation::Acquired(credit) => credit,
                ControlledReservation::Redirect(never) => match never {},
            };
            let node = crate::allocation::boxed(Node { image, next: None }).ok()?;
            let identity = std::ptr::addr_of!(*node) as usize;
            let mut entry = CreditedNode {
                node,
                _credit: credit,
            };
            IMAGES.with(|images| {
                let mut images = images.borrow_mut();
                entry.node.next = images.head.take();
                images.head = Some(entry);
            });
            Some(identity)
        } else {
            None
        };
        DEPTH.with(|current| current.set(depth));
        Some(Self {
            node,
            _thread: std::marker::PhantomData,
        })
    }
}

impl Drop for CallbackScope {
    fn drop(&mut self) {
        if let Some(identity) = self.node {
            let removed = IMAGES.with(|images| {
                let mut images = images.borrow_mut();
                let mut cursor = &mut images.head;
                while let Some(entry) = cursor.as_ref() {
                    if std::ptr::addr_of!(*entry.node) as usize == identity {
                        let mut removed = cursor.take().expect("observed callback node");
                        *cursor = removed.node.next.take();
                        return Some(removed);
                    }
                    cursor = &mut cursor.as_mut().expect("observed callback node").node.next;
                }
                None
            });
            // The TLS borrow ends before destruction can return credit and wake.
            drop(removed);
        }
        DEPTH.with(|depth| depth.set(depth.get() - 1));
    }
}
