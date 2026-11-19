// SPDX-License-Identifier: Apache-2.0
//! Real application mutexes for the PKCS#11 initialization callback contract.
//!
//! Each native handle owns one boxed mutex/condition pair. The native module
//! must obey the standard handle and destruction rules; these callbacks neither
//! reenter Fe11 nor retain credentials. Counters have process lifetime.
use fe11::InitializationMutexFunctions;
use fe11_sys::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Condvar, Mutex,
};

static CREATED: AtomicUsize = AtomicUsize::new(0);
static DESTROYED: AtomicUsize = AtomicUsize::new(0);
static LOCKED: AtomicUsize = AtomicUsize::new(0);
static UNLOCKED: AtomicUsize = AtomicUsize::new(0);
static PANICKED: AtomicUsize = AtomicUsize::new(0);

struct ApplicationMutex {
    locked: Mutex<bool>,
    available: Condvar,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Counts {
    pub created: usize,
    pub destroyed: usize,
    pub locked: usize,
    pub unlocked: usize,
    pub panicked: usize,
}

pub(super) fn counts() -> Counts {
    Counts {
        created: CREATED.load(Ordering::SeqCst),
        destroyed: DESTROYED.load(Ordering::SeqCst),
        locked: LOCKED.load(Ordering::SeqCst),
        unlocked: UNLOCKED.load(Ordering::SeqCst),
        panicked: PANICKED.load(Ordering::SeqCst),
    }
}

fn boundary(body: impl FnOnce() -> CK_RV + std::panic::UnwindSafe) -> CK_RV {
    match std::panic::catch_unwind(body) {
        Ok(code) => code,
        Err(_) => {
            PANICKED.fetch_add(1, Ordering::SeqCst);
            CKR_GENERAL_ERROR
        }
    }
}

unsafe extern "C" fn create(output: *mut CK_VOID_PTR) -> CK_RV {
    boundary(|| {
        if output.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let allocation = Box::new(ApplicationMutex {
            locked: Mutex::new(false),
            available: Condvar::new(),
        });
        // SAFETY: the PKCS#11 caller supplies a writable pointer-sized output.
        // Ownership transfers to its handle until the matching destroy callback.
        unsafe {
            *output = Box::into_raw(allocation).cast();
        }
        CREATED.fetch_add(1, Ordering::SeqCst);
        CKR_OK
    })
}

unsafe extern "C" fn destroy(handle: CK_VOID_PTR) -> CK_RV {
    boundary(|| {
        if handle.is_null() {
            return CKR_MUTEX_BAD;
        }
        // SAFETY: the provider returns a live handle from create, quiescent at
        // destruction; no concurrent callback may still address this allocation.
        let mutex = unsafe { &*handle.cast::<ApplicationMutex>() };
        match mutex.locked.lock() {
            Ok(guard) if !*guard => (),
            Ok(_) => return CKR_MUTEX_BAD,
            Err(_) => return CKR_GENERAL_ERROR,
        }
        // SAFETY: the checked handle is owned by this allocator and destroyed
        // once, after every native user and callback has relinquished it.
        unsafe {
            drop(Box::from_raw(handle.cast::<ApplicationMutex>()));
        }
        DESTROYED.fetch_add(1, Ordering::SeqCst);
        CKR_OK
    })
}

unsafe extern "C" fn lock(handle: CK_VOID_PTR) -> CK_RV {
    boundary(|| {
        if handle.is_null() {
            return CKR_MUTEX_BAD;
        }
        // SAFETY: the provider retains this create-owned handle through the call.
        let mutex = unsafe { &*handle.cast::<ApplicationMutex>() };
        let mut guard = match mutex.locked.lock() {
            Ok(guard) => guard,
            Err(_) => return CKR_GENERAL_ERROR,
        };
        while *guard {
            guard = match mutex.available.wait(guard) {
                Ok(guard) => guard,
                Err(_) => return CKR_GENERAL_ERROR,
            };
        }
        *guard = true;
        LOCKED.fetch_add(1, Ordering::SeqCst);
        CKR_OK
    })
}

unsafe extern "C" fn unlock(handle: CK_VOID_PTR) -> CK_RV {
    boundary(|| {
        if handle.is_null() {
            return CKR_MUTEX_BAD;
        }
        // SAFETY: the provider retains this create-owned handle through the call.
        let mutex = unsafe { &*handle.cast::<ApplicationMutex>() };
        let mut guard = match mutex.locked.lock() {
            Ok(guard) => guard,
            Err(_) => return CKR_GENERAL_ERROR,
        };
        if !*guard {
            return CKR_MUTEX_NOT_LOCKED;
        }
        *guard = false;
        UNLOCKED.fetch_add(1, Ordering::SeqCst);
        mutex.available.notify_one();
        CKR_OK
    })
}

pub(super) fn functions() -> InitializationMutexFunctions {
    InitializationMutexFunctions {
        create: Some(create),
        destroy: Some(destroy),
        lock: Some(lock),
        unlock: Some(unlock),
    }
}
