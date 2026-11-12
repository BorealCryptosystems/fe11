// SPDX-License-Identifier: Apache-2.0
//! Owned initialization callbacks and explicitly declared extension arguments.

use crate::mechanism_extension::{GraphStorage, OwnedGraph};
use crate::{Error, ExtensionParameters, Result, SymmetricLimits};
use fe11_sys::{CK_C_INITIALIZE_ARGS, CK_VOID_PTR};
use std::sync::Arc;

/// Exact PKCS#11 application mutex callbacks. Null or partial selections are
/// transmitted unchanged so C_Initialize can report CKR_ARGUMENTS_BAD itself.
/// Construct an InitializationMutexes owner before installing these functions.
#[derive(Clone, Copy, Default)]
pub struct InitializationMutexFunctions {
    /// Create a native mutex and write its application-owned handle.
    pub create: fe11_sys::CK_CREATEMUTEX,
    /// Destroy a handle allocated by the matching create callback.
    pub destroy: fe11_sys::CK_DESTROYMUTEX,
    /// Acquire the application-owned mutex.
    pub lock: fe11_sys::CK_LOCKMUTEX,
    /// Release the application-owned mutex.
    pub unlock: fe11_sys::CK_UNLOCKMUTEX,
}
impl InitializationMutexFunctions {
    // Compare the exact addresses supplied, not semantic function identity.
    // Copy packed native fields into this aligned value before inspecting them.
    fn addresses(self) -> [usize; 4] {
        [
            self.create.map_or(0, |f| f as usize),
            self.destroy.map_or(0, |f| f as usize),
            self.lock.map_or(0, |f| f as usize),
            self.unlock.map_or(0, |f| f as usize),
        ]
    }
    fn complete(self) -> bool {
        self.create.is_some()
            && self.destroy.is_some()
            && self.lock.is_some()
            && self.unlock.is_some()
    }
}

/// Retains the application runtime needed by its mutex callbacks through
/// C_Finalize. An uncertain native lifetime retains this owner with the image.
/// This is separate from pReserved; no context pointer is invented for callbacks.
pub struct InitializationMutexes {
    functions: InitializationMutexFunctions,
    _owner: Box<dyn Send + Sync>,
}
impl InitializationMutexes {
    /// Bind the callbacks to their runtime owner. Use `()` for functions whose
    /// code and state already have process lifetime; no callback is invoked here.
    /// This autonomous owner is constructed before selecting a module budget.
    /// Opening moves it without copying its allocation; its application-owned
    /// storage is separate from the credited native initialization descriptor.
    ///
    /// # Safety
    /// Every supplied function must obey the PKCS#11 mutex ABI and semantics,
    /// including valid output pointers, mutex ownership and native-thread use.
    /// The owner must retain all code and state needed until its destruction,
    /// including any dynamically loaded callback image. Callbacks must not
    /// unwind across C or reenter Fe11/native operations on the same instance;
    /// they may be invoked while its dispatch/lifecycle locks are held. Native
    /// mutex allocations must be destroyed by the matching application callback,
    /// never by a different allocator. Partial selections must remain safe if a
    /// module invokes a supplied callback before returning an initialization error.
    pub unsafe fn new<T: Send + Sync + 'static>(
        functions: InitializationMutexFunctions,
        owner: T,
    ) -> Self {
        Self {
            functions,
            _owner: Box::new(owner),
        }
    }
    pub(crate) fn complete(&self) -> bool {
        self.functions.complete()
    }
}

enum Storage {
    Graph(OwnedGraph),
    External {
        // This owner, not the projected address, establishes Rust lifetime.
        _owner: Box<dyn Send>,
        pointer: CK_VOID_PTR,
    },
}

/// An initialization extension retained through finalization, including pending
/// or uncertain outcomes. No standard PKCS#11 meaning is inferred for pReserved.
/// The usual opening path supplies NULL when this owner is not selected.
pub struct InitializationReserved {
    storage: Storage,
}

// SAFETY: graph pointers address owned stable allocations. The external
// constructor requires the same lifetime and cross-thread native-use contract.
// Rust never dereferences the external pointer; inspection is behind the image
// owner's mutex. Concurrency inside native code remains part of that contract.
unsafe impl Send for InitializationReserved {}

impl InitializationReserved {
    /// Copy a declared, aligned graph, including its internal pointers.
    /// The supplied limit accounts for this independently owned argument graph;
    /// it is not the module's later operation-buffer budget.
    ///
    /// # Safety
    /// The graph must represent the exact initialization ABI of the selected
    /// native module. Its pointer directions, extents and alignments must be
    /// truthful. The module may use it until Finalize; that use must be safe in
    /// the requested concurrency mode. Fe11 cannot verify those ABI assertions.
    pub unsafe fn graph(
        parameters: ExtensionParameters<'_>,
        limits: SymmetricLimits,
    ) -> Result<Self> {
        let budget = Arc::new(crate::symmetric::memory::Budget::new(limits)?);
        let mut required = OwnedGraph::allocation_bytes(&parameters)?;
        loop {
            let mut prepaid = budget.reserve(required)?;
            let storage = GraphStorage::allocate(&parameters)?;
            let actual = storage.allocated_bytes()?;
            if actual > required {
                drop(storage);
                drop(prepaid);
                required = actual;
                continue;
            }
            prepaid.release(required - actual);
            return Ok(Self {
                storage: Storage::Graph(storage.bind(&mut prepaid)?),
            });
        }
    }

    /// Retain an external ABI owner that cannot be represented as a byte graph.
    /// The projection is evaluated once, before loading any native module.
    ///
    /// # Safety
    /// `project` must return the correct, stable pReserved address for the
    /// selected module, owned or otherwise retained by `owner`. All reachable
    /// storage must remain valid until owner destruction and must permit the
    /// module's reads/writes, including use on native threads. Native code must
    /// not destroy Rust allocations. The owner must also retain any external
    /// runtime needed by its projected object. No safe raw-address entry exists.
    pub unsafe fn external<T: Send + 'static>(
        mut owner: Box<T>,
        project: unsafe fn(*mut T) -> CK_VOID_PTR,
    ) -> Self {
        // SAFETY: the caller supplies and guarantees the projection contract.
        let pointer = unsafe { project(&mut *owner) };
        Self {
            storage: Storage::External {
                _owner: owner,
                pointer,
            },
        }
    }

    fn pointer(&mut self) -> CK_VOID_PTR {
        match &mut self.storage {
            Storage::Graph(graph) => graph.projection().0,
            Storage::External { pointer, .. } => *pointer,
        }
    }

    fn unchanged(&self) -> bool {
        match &self.storage {
            Storage::Graph(graph) => graph.unchanged(),
            Storage::External { .. } => true,
        }
    }
}

/// The native argument descriptor also has a stable address after Initialize.
/// No reference to it escapes Rust; native retention is covered by the image.
pub(crate) struct InitializationFrame {
    pub(crate) args: Box<CK_C_INITIALIZE_ARGS>,
    mutexes: Option<InitializationMutexes>,
    reserved: Option<InitializationReserved>,
    pointer: CK_VOID_PTR,
    flags: fe11_sys::CK_FLAGS,
    // The descriptor and enclosing stable frame can outlive a refused or
    // uncertain Initialize. Keep their module-resident charge with that frame.
    _credit: crate::symmetric::memory::ResidentCredit,
}

// SAFETY: both descriptor and projected storage are owned at stable addresses.
// Callback owners are Send + Sync; their unsafe constructor covers native thread
// use and executable-code lifetime. Rust inspection takes the image's mutex.
unsafe impl Send for InitializationFrame {}

impl InitializationFrame {
    pub(crate) const fn allocation_bytes() -> usize {
        std::mem::size_of::<Self>() + std::mem::size_of::<CK_C_INITIALIZE_ARGS>()
    }

    pub(crate) fn new(
        flags: fe11_sys::CK_FLAGS,
        mut reserved: Option<InitializationReserved>,
        mutexes: Option<InitializationMutexes>,
        credit: crate::symmetric::memory::ResidentCredit,
    ) -> Result<Self> {
        let pointer = reserved
            .as_mut()
            .map_or(std::ptr::null_mut(), InitializationReserved::pointer);
        let functions = mutexes
            .as_ref()
            .map_or(InitializationMutexFunctions::default(), |m| m.functions);
        Ok(Self {
            args: crate::allocation::boxed(CK_C_INITIALIZE_ARGS {
                flags,
                CreateMutex: functions.create,
                DestroyMutex: functions.destroy,
                LockMutex: functions.lock,
                UnlockMutex: functions.unlock,
                pReserved: pointer,
            })?,
            reserved,
            mutexes,
            pointer,
            flags,
            _credit: credit,
        })
    }

    pub(crate) fn validate_return(&self) -> Result<()> {
        // Copy function fields before Option methods borrow them: Windows
        // Cryptoki structures may be packed according to the admitted ABI.
        let create = self.args.CreateMutex;
        let destroy = self.args.DestroyMutex;
        let lock = self.args.LockMutex;
        let unlock = self.args.UnlockMutex;
        let observed = InitializationMutexFunctions {
            create,
            destroy,
            lock,
            unlock,
        };
        let expected = self
            .mutexes
            .as_ref()
            .map_or(InitializationMutexFunctions::default(), |m| m.functions);
        if self.args.flags != self.flags
            || self.args.pReserved != self.pointer
            || observed.addresses() != expected.addresses()
            || !self
                .reserved
                .as_ref()
                .map_or(true, InitializationReserved::unchanged)
        {
            return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                crate::ModuleLifecycleRejection::InitializationArgumentGraphChanged,
            )));
        }
        Ok(())
    }
}
