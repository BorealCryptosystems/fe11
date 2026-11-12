// SPDX-License-Identifier: Apache-2.0
//! File observations and local image ownership are distinct module identities.
use super::{Limits, ModuleConfig, ModuleIntegrityReport};
use crate::{Error, Result};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) enum Source {
    File(ModuleConfig),
    Process(Limits),
}
impl Source {
    pub(crate) fn limits(&self) -> Limits {
        match self {
            Self::File(config) => config.limits,
            Self::Process(limits) => *limits,
        }
    }
}

/// An actual opened file observed while its associated native image is retained.
#[derive(Clone, Debug)]
pub struct ModuleFileObservation {
    /// Observed source path, not a provider identity or allowlist entry.
    pub path: PathBuf,
    /// Digest of the opened file's observed bytes, not of relocated memory.
    pub sha256: [u8; 32],
}

/// How the native module was obtained. A process source has no invented path,
/// digest or successful file-pinning report when its file cannot be observed.
#[derive(Clone, Debug)]
pub enum ModuleProvenance {
    /// The caller selected this file and its independent integrity comparison.
    File {
        /// Opened source file.
        file: ModuleFileObservation,
        /// Caller-selected comparison performed before loading.
        integrity: ModuleIntegrityReport,
    },
    /// Exports resolved from the process's already loaded image scope.
    Process {
        /// Optional evidence for an autonomous archive binding. A failure here
        /// does not prevent native operations or in-process state transfer.
        file: Result<ModuleFileObservation>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum BindingIdentity {
    File([u8; 32]),
    Local(u64),
}
impl ModuleProvenance {
    pub(crate) fn binding(&self) -> Result<BindingIdentity> {
        match self {
            Self::File { file, .. } | Self::Process { file: Ok(file) } => {
                Ok(BindingIdentity::File(file.sha256))
            }
            Self::Process { file: Err(_) } => {
                // Never reuse an instance number, even after image unloading.
                // It is used only by live owned captures, never serialized.
                static NEXT: AtomicU64 = AtomicU64::new(1);
                let mut current = NEXT.load(Ordering::Relaxed);
                loop {
                    let next = current.checked_add(1).ok_or(Error::Rejected(
                        crate::RejectionReason::ModuleConfiguration(
                            crate::ModuleConfigurationRejection::LocalModuleIdentityExhausted,
                        ),
                    ))?;
                    // The counter allocates identities; it does not publish
                    // associated data. Relaxed ordering is therefore enough.
                    // Use the CAS primitive shared by both supported Rust
                    // versions rather than the renamed atomic update helper.
                    match NEXT.compare_exchange_weak(
                        current,
                        next,
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => return Ok(BindingIdentity::Local(current)),
                        Err(observed) => current = observed,
                    }
                }
            }
        }
    }
}

pub(crate) fn digest(file: &mut File) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    let mut chunk = [0u8; 65536];
    loop {
        let count = match file.read(&mut chunk) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                return Err(Error::Rejected(
                    crate::RejectionReason::ModuleConfiguration(
                        crate::ModuleConfigurationRejection::ModuleFileRead,
                    ),
                ))
            }
        };
        if count == 0 {
            break;
        }
        hash.update(&chunk[..count]);
    }
    Ok(hash.finalize().into())
}

/// Observe a file only when the loader mapping can be matched to that same
/// opened object. Addresses are transient lookup operands, never identity bytes.
pub(crate) fn observe_process_file(addresses: &[usize]) -> Result<ModuleFileObservation> {
    #[cfg(target_os = "linux")]
    {
        use std::ffi::{c_char, c_int, c_void, CStr, OsStr};
        use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
        #[repr(C)]
        struct Info {
            name: *const c_char,
            base: *mut c_void,
            symbol: *const c_char,
            address: *mut c_void,
        }
        #[link(name = "dl")]
        extern "C" {
            fn dladdr(address: *const c_void, info: *mut Info) -> c_int;
        }
        let address = *addresses.first().ok_or(Error::Rejected(
            crate::RejectionReason::ModuleConfiguration(
                crate::ModuleConfigurationRejection::ProcessExportObservationAbsent,
            ),
        ))?;
        let mut info = Info {
            name: std::ptr::null(),
            base: std::ptr::null_mut(),
            symbol: std::ptr::null(),
            address: std::ptr::null_mut(),
        };
        // SAFETY: all supplying images are retained by Native while observing;
        // info is initialized and the documented loader string remains live.
        if unsafe { dladdr(address as *const c_void, &mut info) } == 0 || info.name.is_null() {
            return Err(Error::Rejected(
                crate::RejectionReason::ModuleConfiguration(
                    crate::ModuleConfigurationRejection::ProcessImageFilenameUnavailable,
                ),
            ));
        }
        let path = PathBuf::from(OsStr::from_bytes(
            unsafe { CStr::from_ptr(info.name) }.to_bytes(),
        ));
        let mut file = File::open(&path).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ModuleConfiguration(
                crate::ModuleConfigurationRejection::ProcessImageFileUnavailable,
            ))
        })?;
        let metadata = file.metadata().map_err(|_| {
            Error::Rejected(crate::RejectionReason::ModuleConfiguration(
                crate::ModuleConfigurationRejection::ProcessImageFileMetadata,
            ))
        })?;
        if !metadata.is_file() {
            return Err(Error::Rejected(
                crate::RejectionReason::ModuleConfiguration(
                    crate::ModuleConfigurationRejection::ProcessImageFileIsNotRegular,
                ),
            ));
        }
        let identity = (metadata.dev(), u128::from(metadata.ino()));
        for address in addresses {
            if !crate::native::mapped_image_matches(*address, identity)? {
                return Err(Error::Rejected(
                    crate::RejectionReason::ModuleConfiguration(crate::ModuleConfigurationRejection::ProcessExportsDoNotShareTheObservedFile),
                ));
            }
        }
        Ok(ModuleFileObservation {
            path,
            sha256: digest(&mut file)?,
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = addresses;
        // A loader pathname alone does not establish that opening it now
        // observes the file object backing an earlier Windows mapping. Keep
        // local ownership rather than inventing a persistent digest binding.
        Err(Error::Unsupported(
            crate::UnsupportedReason::ModuleConfiguration(
                crate::ModuleConfigurationUnsupported::ProcessImageFileIdentityObservation,
            ),
        ))
    }
}
