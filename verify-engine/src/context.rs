// SPDX-License-Identifier: Apache-2.0
//! One request's isolated context. No provider or key is cached between calls.
use crate::{native, Failure, Result};
use std::{marker::PhantomData, ptr, rc::Rc, sync::OnceLock};

pub(crate) const PROPERTIES: &[u8] = b"provider=default\0";

/// The component's private libcrypto is initialized only after its image has
/// been pinned by the caller. This does not initialize the application's copy.
fn initialize() -> Result<()> {
    static INITIALIZED: OnceLock<bool> = OnceLock::new();
    let ready = INITIALIZED.get_or_init(|| {
        // SAFETY: fixed documented options, no settings object. Local binding of
        // this symbol is a distribution requirement verified on the final image.
        unsafe {
            native::OPENSSL_init_crypto(
                native::INIT_NO_LOAD_CONFIG | native::INIT_NO_ATEXIT,
                ptr::null(),
            ) == 1
        }
    });
    if *ready {
        Ok(())
    } else {
        // SAFETY: initialization failure can still leave private error state
        // on the initiating thread. No context or dependent object exists yet.
        unsafe { native::OPENSSL_thread_stop() };
        Err(Failure::Unavailable)
    }
}

/// Thread-affine so cleanup runs on the thread that made the OpenSSL calls.
/// Native objects borrow this owner and are freed before its provider/context.
pub(crate) struct Context {
    raw: *mut native::OSSL_LIB_CTX,
    provider: *mut native::OSSL_PROVIDER,
    _thread: PhantomData<Rc<()>>,
}

impl Context {
    pub(crate) fn new() -> Result<Self> {
        initialize()?;
        // Construct the owner before fallible allocation so every failure drains
        // this request thread's private OpenSSL state as well as partial objects.
        let mut owner = Self {
            raw: ptr::null_mut(),
            provider: ptr::null_mut(),
            _thread: PhantomData,
        };
        // SAFETY: initialization precedes this first context allocation.
        owner.raw = unsafe { native::OSSL_LIB_CTX_new() };
        if owner.raw.is_null() {
            return Err(Failure::Allocation);
        }
        // SAFETY: live private context and a static terminated provider name.
        // Only the built-in default provider is selected, with no config load.
        owner.provider =
            unsafe { native::OSSL_PROVIDER_load(owner.raw, b"default\0".as_ptr().cast()) };
        if owner.provider.is_null() {
            return Err(Failure::Unavailable);
        }
        Ok(owner)
    }

    pub(crate) fn raw(&self) -> *mut native::OSSL_LIB_CTX {
        self.raw
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: every native object borrows this owner, all calls are
        // synchronous, and !Send/!Sync preserve the request thread. Null partial
        // allocations are handled explicitly. Never call OPENSSL_cleanup.
        unsafe {
            if !self.provider.is_null() {
                native::OSSL_PROVIDER_unload(self.provider);
            }
            if !self.raw.is_null() {
                native::OPENSSL_thread_stop_ex(self.raw);
            }
            native::OPENSSL_thread_stop();
            if !self.raw.is_null() {
                native::OSSL_LIB_CTX_free(self.raw);
            }
            // Context destruction may itself use the error queue. Drain private
            // thread resources once more without touching application libcrypto.
            native::OPENSSL_thread_stop();
        }
    }
}
