// SPDX-License-Identifier: Apache-2.0
//! Stable ownership of descriptors and output slots across a native call.
use crate::{error::check, Error, Result};

mod logout;
mod replacement;
pub(crate) use replacement::{AcceptedInitTransfer, ClassicInit};
use fe11_sys::{CKR_GENERAL_ERROR, CKR_PENDING, CK_RV};
pub(crate) use logout::LogoutFrame;
use std::{
    cell::Cell,
    ops::{Deref, DerefMut},
};

/// A single stable allocation owns the complete call-specific representation.
/// T must itself own (or retain) every allocation addressed by its descriptors.
/// No callback or native code may use a pointer before construction is complete.
pub(crate) struct NativeFrame<T> {
    // Both constructors allocate exactly one element; no API can resize it.
    // Only consuming into_inner or Drop takes the body, so every live borrow
    // still has Some. Disposition separately forbids inspection while native
    // memory return is unproven, even though the retained body remains present.
    body: Option<Box<[T]>>,
    disposition: Cell<Disposition>,
    call: Cell<CallPhase>,
    scope: CallScope,
    recovery: Option<fn(Box<[T]>, Disposition, CallPhase)>,
    // Bare discovery/open frames have no Entry/token recovery owner. Their
    // image must remain pinned even if explicit Finalize later returns OK.
    quarantined_image: Option<std::sync::Arc<super::image::LoadedImage>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Disposition {
    Owned,
    Active,
    Recoverable,
    Uncompleted,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CallPhase {
    Prepared,
    Issued,
    Returned(CK_RV),
}

/// The data is destroyed before its access guards on an ordinary return.
/// A recorded return permits detaching the stable data from SessionAccess.
/// A call without that proof retains both the guards and their referents.
pub(crate) struct SessionFrame<'a, T, G = crate::session::TokenActivity<'a>> {
    pub(crate) data: CallData<T>,
    pub(crate) access: crate::session::SessionAccess<'a, G>,
    recovery: crate::session::recovery::Ticket,
}

impl<T, G> SessionFrame<'_, T, G> {
    /// Only an already disarmed frame can reach this consuming path. Keep its
    /// returned payload alive while releasing possession and recovery metadata.
    pub(crate) fn retire_after_access(self) -> T {
        let Self { data, access, recovery } = self;
        drop(access);
        drop(recovery);
        data.into_inner()
    }

    /// Account the frame plus recovery metadata coallocated with its CallData.
    /// Call-specific planners add size_of::<T>() and its indirect capacities.
    pub(crate) const fn allocation_bytes() -> usize {
        std::mem::size_of::<Self>() + crate::session::recovery::Stored::<T>::overhead()
    }
}
impl<T> crate::module::TokenCallFrame<'_, T> {
    pub(crate) const fn allocation_bytes() -> usize {
        std::mem::size_of::<Self>() + crate::session::recovery::Stored::<T>::overhead()
    }
}

/// Independent stable storage lets a returned-but-active sequence release its
/// borrowed call guards without moving any address previously given to C.
pub(crate) struct CallData<T>(Box<[crate::session::recovery::Stored<T>; 1]>);
impl<T> CallData<T> {
    fn new(data: T) -> Result<Self> {
        let mut values = Vec::new();
        values.try_reserve_exact(1).map_err(|_| {
            Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::NativeDataAllocation,
            ))
        })?;
        values.push(crate::session::recovery::Stored::new(data));
        let values: Box<[crate::session::recovery::Stored<T>; 1]> = values
            .into_boxed_slice()
            .try_into()
            .unwrap_or_else(|_| unreachable!("one native data value"));
        Ok(Self(values))
    }
    pub(crate) fn into_inner(self) -> T {
        let [value] = *self.0;
        value.into_inner()
    }
}
impl<T> Deref for CallData<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.0[0].value()
    }
}
impl<T> DerefMut for CallData<T> {
    fn deref_mut(&mut self) -> &mut T {
        self.0[0].value_mut()
    }
}

fn recover_session<'a, T: Send + 'static, G>(
    body: Box<[SessionFrame<'a, T, G>]>,
    disposition: Disposition,
    call: CallPhase,
) {
    use crate::session::recovery::Lifetime;
    let access = &body[0].access;
    let lifetime = match call {
        CallPhase::Returned(CKR_PENDING) => Lifetime::Pending,
        CallPhase::Returned(_) if disposition == Disposition::Uncompleted => Lifetime::Quarantined,
        CallPhase::Returned(_) => Lifetime::UntilClose,
        // A parent may have prepared a frame around a returned child without
        // dispatching a call of its own. It shares the child's withdrawal.
        CallPhase::Prepared if access.recovery_requested() => Lifetime::UntilClose,
        _ => {
            // No recorded return: keep possession, not merely the input graph.
            access.native.mark_uncertain();
            std::mem::forget(body);
            return;
        }
    };
    let SessionFrame {
        data,
        access,
        recovery,
    } = body.into_vec().pop().expect("one session frame");
    // Coercion to a trait object does not allocate or move the boxed array.
    // Snapshot retirement invalidates use, not ownership. Retain against this
    // exact Entry/UID even if its token context is stale. The session ledger
    // preserves that Entry across handle reuse; only its native termination
    // proof may release these bytes and object protections.
    recovery.retain(data.0, &access, lifetime);
    drop(access);
}

fn recover_token<T: Send + 'static>(
    body: Box<[crate::module::TokenCallFrame<'_, T>]>,
    _disposition: Disposition,
    call: CallPhase,
) {
    let CallPhase::Returned(rv) = call else {
        // There is no return proof. Keep the writer and its referents as well
        // as the addressed data; a local unwind is not native termination.
        body[0].access.native.mark_uncertain();
        std::mem::forget(body);
        return;
    };
    let crate::module::TokenCallFrame { data, access } =
        body.into_vec().pop().expect("one token frame");
    // Token administration has no crypto sequence to finish later. Reaching
    // recovery means its call storage was quarantined. Retain that graph at
    // its original addresses, but release coordination after the known return.
    access.quarantine_returned(data, rv == CKR_PENDING);
}

/// Split from the stable body before dispatch. Mark the native result before
/// examining any output or calling code that can unwind.
#[derive(Clone, Copy)]
pub(crate) struct FrameReturn<'a> {
    disposition: &'a Cell<Disposition>,
    call: &'a Cell<CallPhase>,
    scope: CallScope,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CallScope {
    /// An exact Entry owns the completion receipt and all retained arguments.
    Session,
    /// No session receipt can exclude later module-wide recovery dispatch.
    Unscoped,
}

impl FrameReturn<'_> {
    /// Arm before dispatch. Even an unwind before result classification must
    /// preserve the representation of a possibly active native sequence.
    pub(crate) fn arm(&self) {
        if matches!(
            self.disposition.get(),
            Disposition::Owned | Disposition::Active
        ) {
            self.disposition.set(Disposition::Active);
            self.call.set(CallPhase::Issued);
        }
    }

    /// Sequence retention is not a new dispatch. Preserve the last raw return
    /// when its function-specific contract leaves a sequence active.
    pub(crate) fn active(&self) {
        if self.disposition.get() == Disposition::Owned {
            self.disposition.set(Disposition::Active);
        }
    }

    /// Only a function-specific termination proof releases ordinary ownership.
    /// A prior boundary anomaly cannot be erased by a later completion claim.
    pub(crate) fn terminated(&self) {
        if self.disposition.get() == Disposition::Active {
            self.disposition.set(Disposition::Owned);
        }
    }

    /// An inspected, refused non-NULL Init returns this attempt's loan without
    /// proving termination of any native sequence. Preserve earlier anomalies.
    pub(crate) fn attempt_returned(&self) {
        if self.disposition.get() == Disposition::Active
            && matches!(self.call.get(), CallPhase::Returned(code) if code != CKR_PENDING)
        {
            self.disposition.set(Disposition::Owned);
        }
    }

    pub(crate) fn observe(&self, rv: CK_RV, native: &super::Native) -> CK_RV {
        native.observe_runtime_return(rv);
        self.call.set(CallPhase::Returned(rv));
        if rv == CKR_PENDING && self.scope == CallScope::Unscoped {
            native.mark_unscoped_pending();
        }
        if rv == CKR_PENDING {
            self.quarantine(native);
        }
        rv
    }

    pub(crate) fn quarantine(&self, native: &super::Native) {
        self.disposition.set(Disposition::Uncompleted);
        native.mark_uncertain();
    }

    /// Only for an already returned, still-active operation whose buffers must
    /// survive until session closure (for example epoch loss or a completed
    /// contextual-login refusal). Pending or a known boundary anomaly cannot
    /// be downgraded into recoverable work.
    pub(crate) fn recoverable(&self) {
        if self.disposition.get() == Disposition::Active {
            self.disposition.set(Disposition::Recoverable);
        }
    }
    pub(crate) fn uncompleted(&self) {
        self.disposition.set(Disposition::Uncompleted);
    }
}

impl<'a, T: Send + 'static, G> NativeFrame<SessionFrame<'a, T, G>> {
    pub(crate) fn session(access: crate::session::SessionAccess<'a, G>, data: T) -> Result<Self> {
        Self::session_with(|| data, access)
    }

    /// Allocate both stable owners and the recovery ticket before consuming
    /// call inputs. A retained caller lends its inputs to this infallible
    /// factory and takes them only when construction can no longer refuse.
    /// The access parameter is last so rejection drops it before the factory.
    pub(crate) fn session_with(
        prepare: impl FnOnce() -> T,
        access: crate::session::SessionAccess<'a, G>,
    ) -> Result<Self> {
        let recovery = access.recovery_ticket()?;
        let mut values = Vec::new();
        values.try_reserve_exact(1).map_err(|_| {
            Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::NativeDataAllocation,
            ))
        })?;
        let mut body = Vec::new();
        body.try_reserve_exact(1).map_err(|_| {
            Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::NativeFrameAllocation,
            ))
        })?;
        // No fallible operation follows the transfer. The allocations keep the
        // same pointee types and stable addresses as ordinary session frames.
        values.push(crate::session::recovery::Stored::new(prepare()));
        let values: Box<[crate::session::recovery::Stored<T>; 1]> = values
            .into_boxed_slice()
            .try_into()
            .unwrap_or_else(|_| unreachable!("one native data value"));
        body.push(SessionFrame {
            data: CallData(values),
            access,
            recovery,
        });
        Ok(Self {
            body: Some(body.into_boxed_slice()),
            disposition: Cell::new(Disposition::Owned),
            call: Cell::new(CallPhase::Prepared),
            scope: CallScope::Session,
            recovery: Some(recover_session),
            quarantined_image: None,
        })
    }

    pub(crate) fn session_parts(&mut self) -> (FrameReturn<'_>, &mut SessionFrame<'a, T, G>) {
        self.parts()
    }
}

impl<'a, T: Send + 'static> NativeFrame<crate::module::TokenCallFrame<'a, T>> {
    pub(crate) fn token(access: crate::module::TokenAccess<'a>, data: T) -> Result<Self> {
        let data = CallData::new(data)?;
        let mut frame = Self::new(crate::module::TokenCallFrame { data, access })?;
        frame.recovery = Some(recover_token);
        // A token-wide call is not an Entry-scoped call. PENDING must also
        // exclude instance Finalize; recovery publishes its token close gate.
        Ok(frame)
    }
}

impl<T> NativeFrame<T> {
    /// Split the completion marker from the stable owned representation.
    /// T must include all guards and referents needed by the dispatched call.
    pub(crate) fn parts(&mut self) -> (FrameReturn<'_>, &mut T) {
        assert!(self.disposition.get() == Disposition::Owned);
        let body = &mut self.body.as_mut().expect("native frame still owned")[0];
        (
            FrameReturn {
                disposition: &self.disposition,
                call: &self.call,
                scope: self.scope,
            },
            body,
        )
    }

    pub(crate) fn new(value: T) -> Result<Self> {
        // One exact stable payload, without a temporary Vec whose allocator
        // capacity could exceed the single element charged by its owner.
        let body: Box<[T]> = crate::allocation::boxed([value]).map_err(|_| {
            Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::NativeFrameAllocation,
            ))
        })?;
        Ok(Self {
            body: Some(body),
            disposition: Cell::new(Disposition::Owned),
            call: Cell::new(CallPhase::Prepared),
            scope: CallScope::Unscoped,
            recovery: None,
            quarantined_image: None,
        })
    }

    /// A synchronous PENDING is not completion. Retain the entire frame and
    /// notify the image owner before returning the original native error.
    /// The caller classifies effects separately: discovery does not initialize
    /// a module, even when its memory return is uncertain. This does not
    /// activate the deferred native asynchronous protocol.
    pub(crate) fn loading_result(
        &mut self,
        rv: CK_RV,
        function: &'static str,
        image_uncertain: &Cell<bool>,
        may_have_effect: bool,
    ) -> Result<()> {
        self.call.set(CallPhase::Returned(rv));
        if matches!(rv, CKR_PENDING | CKR_GENERAL_ERROR) {
            self.retain();
            image_uncertain.set(true);
        }
        check(rv, function, may_have_effect)
    }

    pub(crate) fn quarantine_loading(&mut self, image_uncertain: &Cell<bool>) {
        self.retain();
        image_uncertain.set(true);
    }

    /// Preserve call storage and image on PENDING. Its normal
    /// error classifier still handles the code; a returned quarantine can allow
    /// explicit native cleanup without releasing this graph.
    pub(crate) fn retain_if_pending(&mut self, rv: CK_RV, native: &super::Native) {
        native.observe_runtime_return(rv);
        self.call.set(CallPhase::Returned(rv));
        if rv == CKR_PENDING && self.scope == CallScope::Unscoped {
            native.mark_unscoped_pending();
        }
        if rv == CKR_PENDING {
            self.quarantine(native);
        }
    }

    pub(crate) fn quarantine(&mut self, native: &super::Native) {
        self.retain();
        native.mark_uncertain();
        if self.recovery.is_none() && self.quarantined_image.is_none() {
            // Arc cloning cannot relocate data or allocate. Session/token
            // recovery owns the equivalent lease with its detached payload.
            self.quarantined_image = Some(native.image.clone());
        }
    }

    /// Transfer a completed frame's value to its next Rust owner.
    pub(crate) fn into_inner(mut self) -> Result<T> {
        if self.disposition.get() != Disposition::Owned {
            return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::NativeFrameCompletionUnproven,
            )));
        }
        let body =
            self.body
                .take()
                .ok_or(Error::Rejected(crate::RejectionReason::NativeExecution(
                    crate::NativeExecutionRejection::NativeFrameCompletionUnproven,
                )))?;
        Ok(body.into_vec().pop().expect("one native frame value"))
    }

    /// Retain after an uncompleted call whose image lease is owned separately.
    /// The caller must also prevent image unloading and further native use.
    pub(crate) fn retain_uncompleted(&mut self) {
        self.retain();
    }

    fn retain(&mut self) {
        self.disposition.set(Disposition::Uncompleted);
    }
}

impl<T> Drop for NativeFrame<T> {
    fn drop(&mut self) {
        if self.disposition.get() != Disposition::Owned {
            if let Some(recovery) = self.recovery {
                if let Some(body) = self.body.take() {
                    recovery(body, self.disposition.get(), self.call.get());
                    return;
                }
            }
        }
        if self.disposition.get() != Disposition::Owned {
            if let Some(body) = self.body.take() {
                std::mem::forget(body);
            }
            if let Some(image) = self.quarantined_image.take() {
                std::mem::forget(image);
            }
        }
    }
}

impl<T> Deref for NativeFrame<T> {
    type Target = T;
    fn deref(&self) -> &T {
        assert!(self.disposition.get() == Disposition::Owned);
        &self.body.as_ref().expect("native frame still owned")[0]
    }
}

impl<T> DerefMut for NativeFrame<T> {
    fn deref_mut(&mut self) -> &mut T {
        assert!(self.disposition.get() == Disposition::Owned);
        &mut self.body.as_mut().expect("native frame still owned")[0]
    }
}
