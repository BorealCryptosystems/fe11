// SPDX-License-Identifier: Apache-2.0
use libloading::Library;
use std::sync::atomic::{AtomicBool, Ordering};

pub(super) enum InitializationOwner {
    Fe11 {
        _frame: crate::module::initialization::InitializationFrame,
    },
    External {
        owner: crate::ExternalInitialization,
        _credit: crate::symmetric::memory::ResidentCredit,
    },
}

impl InitializationOwner {
    fn finalized(&mut self) {
        if let Self::External { owner, .. } = self {
            owner.finalized();
        }
    }
}

/// Independent image lease for native callbacks, without a module-owner cycle.
pub(crate) struct LoadedImage {
    library: Option<Library>,
    file: Option<super::platform::SourceFiles>,
    providers: Vec<Library>,
    finalized: AtomicBool,
    initialization: std::sync::Mutex<Option<InitializationOwner>>,
}

impl LoadedImage {
    pub(super) fn with_initialization(
        library: Option<Library>,
        file: Option<super::platform::SourceFiles>,
        providers: Vec<Library>,
        initialization: InitializationOwner,
    ) -> Self {
        Self {
            library,
            file,
            finalized: AtomicBool::new(false),
            initialization: std::sync::Mutex::new(Some(initialization)),
            providers,
        }
    }

    pub(crate) fn finalized(&self) {
        self.finalized.store(true, Ordering::Release);
    }
}

impl Drop for LoadedImage {
    fn drop(&mut self) {
        let initialization = self
            .initialization
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if !self.finalized.load(Ordering::Acquire) {
            std::mem::forget(std::mem::take(&mut self.providers));
            if let Some(initialization) = initialization {
                std::mem::forget(initialization);
            }
            // Last Rust owner is not proof of native completion.
            if let Some(library) = self.library.take() {
                std::mem::forget(library);
            }
            if let Some(file) = self.file.take() {
                std::mem::forget(file);
            }
        } else {
            // Run the opaque owner's destructor while its native image is
            // still mapped. The following field drops may then unload it.
            if let Some(mut initialization) = initialization {
                initialization.finalized();
                drop(initialization);
            }
        }
    }
}
