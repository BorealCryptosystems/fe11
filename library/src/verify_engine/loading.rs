// SPDX-License-Identifier: Apache-2.0
//! File observations, one load attempt and process-lifetime image ownership.
use super::{calls::check_status, platform, VerifyEngine, VerifyEngineBuilder, VerifyEngineInfo};
use crate::{native::platform as files, Error, Result};
use fe11_verify_engine_api as api;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Read,
    mem::size_of,
    sync::{Arc, Mutex, OnceLock},
};

/// This registry only protects insertion/lookup. Loading, ABI calls and disposal
/// of a losing library reference all occur after its short guard is released.
static IMAGES: OnceLock<Mutex<BTreeMap<usize, Arc<Image>>>> = OnceLock::new();

// Linux's NODELETE also retains an image whose ABI is subsequently refused.
// Keep its /proc/self/fd name from being reused for a different source, including
// on this error path. Deduplicate by the opened file identity, without a quota.
#[cfg(target_os = "linux")]
static SOURCES: OnceLock<Mutex<BTreeMap<files::FileIdentity, Arc<files::SourceFiles>>>> =
    OnceLock::new();

#[cfg(target_os = "linux")]
fn retain_source(identity: files::FileIdentity, source: &Arc<files::SourceFiles>) -> Result<()> {
    let mut sources = SOURCES
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| Error::Poisoned)?;
    sources
        .entry(identity)
        .or_insert_with(|| Arc::clone(source));
    Ok(())
}

pub(super) struct Image {
    pub(super) table: api::Interface,
    identity: usize,
    source_identity: files::FileIdentity,
    source_sha256: [u8; 32],
    // Registry-owned images are never dropped during normal process lifetime.
    // Field order also preserves the ordinary library-before-file destruction
    // order when a duplicate reference is discarded before publication.
    _library: libloading::Library,
    _source: Arc<files::SourceFiles>,
}

pub(super) struct Lease {
    pub(super) image: Arc<Image>,
    pub(super) info: VerifyEngineInfo,
    // A later open may request stricter file pins than the first open did.
    // Keep that open's actual pins, rather than claiming the cached image supplied
    // those observations. The process image keeps its own original source.
    _source: Arc<files::SourceFiles>,
}

fn addresses(table: &api::Interface) -> [usize; 6] {
    [
        table.information.map_or(0, |f| f as usize),
        table.probe.map_or(0, |f| f as usize),
        table.verification_algorithms.map_or(0, |f| f as usize),
        table.verify.map_or(0, |f| f as usize),
        table.digest.map_or(0, |f| f as usize),
        table.release.map_or(0, |f| f as usize),
    ]
}

fn validate(table: &api::Interface, identity: usize) -> Result<()> {
    if table.abi_version != api::ABI_VERSION
        || table.structure_size as usize != size_of::<api::Interface>()
        || table.information.is_none()
        || (table.verify.is_some() && table.probe.is_none())
        || (table.digest.is_some() && table.release.is_none())
    {
        return Err(Error::Rejected(crate::RejectionReason::VerificationEngine(
            crate::VerificationEngineRejection::VerificationEngineInterfaceShape,
        )));
    }
    for address in addresses(table).into_iter().filter(|address| *address != 0) {
        platform::require_same_image(address, identity)?;
    }
    Ok(())
}

fn retain(candidate: Arc<Image>) -> Result<Arc<Image>> {
    let selected = {
        let mut images = IMAGES
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| Error::Poisoned)?;
        if let Some(existing) = images.get(&candidate.identity) {
            if existing.source_identity == candidate.source_identity
                && existing.source_sha256 != candidate.source_sha256
            {
                Err(Error::Rejected(
                    crate::RejectionReason::VerificationEngine(crate::VerificationEngineRejection::VerificationEngineSourceChangedProcessRestartRequired),
                ))
            } else if addresses(&existing.table) != addresses(&candidate.table) {
                Err(Error::Rejected(
                    crate::RejectionReason::VerificationEngine(crate::VerificationEngineRejection::VerificationEngineInterfaceChangedInPinnedImage),
                ))
            } else {
                Ok(Arc::clone(existing))
            }
        } else {
            images.insert(candidate.identity, Arc::clone(&candidate));
            Ok(Arc::clone(&candidate))
        }
    };
    // In the duplicate case this can release a loader reference and file handles.
    // It must not run under IMAGES, even though the OS image is already pinned.
    drop(candidate);
    selected
}

pub(super) fn open(builder: VerifyEngineBuilder) -> Result<VerifyEngine> {
    files::validate_image_selection(
        builder.windows_file_pinning,
        builder.windows_image_consistency,
    )?;
    files::dependency_search_flags(builder.windows_dependency_search)?;
    files::validate_observations(builder.windows_loader_observations)?;
    if !builder.path.is_absolute() {
        return Err(Error::Rejected(crate::RejectionReason::VerificationEngine(
            crate::VerificationEngineRejection::AbsoluteVerificationEnginePathRequired,
        )));
    }
    let (path, mut source, pinning) =
        files::open_source(&builder.path, builder.windows_file_pinning)?;
    if !source
        .file
        .metadata()
        .map_err(|_| {
            Error::Rejected(crate::RejectionReason::VerificationEngine(
                crate::VerificationEngineRejection::VerificationEngineMetadata,
            ))
        })?
        .is_file()
    {
        return Err(Error::Rejected(crate::RejectionReason::VerificationEngine(
            crate::VerificationEngineRejection::VerificationEngineIsNotARegularFile,
        )));
    }
    let mut hash = Sha256::new();
    let mut chunk = [0u8; 65536];
    loop {
        let length = source.file.read(&mut chunk).map_err(|_| {
            Error::Rejected(crate::RejectionReason::VerificationEngine(
                crate::VerificationEngineRejection::VerificationEngineRead,
            ))
        })?;
        if length == 0 {
            break;
        }
        hash.update(&chunk[..length]);
    }
    let source_sha256: [u8; 32] = hash.finalize().into();
    let integrity = builder.integrity.evaluate(source_sha256)?;
    let (load_path, source_identity, export_check) =
        files::prepare(&source.file, &path, builder.windows_image_consistency)?;
    let source = Arc::new(source);
    // SAFETY: the caller explicitly selects native code under the documented
    // application trust boundary. No failure causes another load attempt.
    let (library, windows_loader) = unsafe {
        platform::load(
            &load_path,
            builder.windows_dependency_search,
            builder.windows_loader_observations,
        )
    }?;
    #[cfg(target_os = "linux")]
    retain_source(source_identity, &source)?;
    let (library, export_check) = files::check_loaded_image(library, export_check)?;
    // SAFETY: the selected Fe11 component supplies the published C getter ABI.
    // It writes only the exact provided table and does not initialize OpenSSL.
    let getter = *unsafe { library.get::<api::GetInterface>(api::ENTRY_POINT) }.map_err(|_| {
        Error::Rejected(crate::RejectionReason::VerificationEngine(
            crate::VerificationEngineRejection::VerificationEngineInterfaceExport,
        ))
    })?;
    export_check.check(getter as usize)?;
    let (library, identity) = platform::identify(library, getter as usize)?;
    // SAFETY: all-zero scalar fields and nullable function pointers are valid;
    // initialize the entire exact table so partial native output is never read
    // from uninitialized Rust storage.
    let mut table: api::Interface = unsafe { std::mem::zeroed() };
    check_status(unsafe { getter(api::ABI_VERSION, &mut table, size_of::<api::Interface>()) })?;
    validate(&table, identity)?;
    let image = retain(Arc::new(Image {
        table,
        identity,
        source_identity,
        source_sha256,
        _library: library,
        _source: Arc::clone(&source),
    }))?;
    let information = image.table.information.ok_or(Error::Rejected(
        crate::RejectionReason::VerificationEngine(
            crate::VerificationEngineRejection::VerificationEngineInformationUnavailable,
        ),
    ))?;
    let mut version: api::Information = unsafe { std::mem::zeroed() };
    // SAFETY: the validated image is pinned and retained before its first engine
    // initialization. The version output is disjoint, initialized and exact-size.
    check_status(unsafe { information(&mut version, size_of::<api::Information>()) })?;
    if version.abi_version != api::ABI_VERSION
        || version.structure_size as usize != size_of::<api::Information>()
    {
        return Err(Error::Rejected(crate::RejectionReason::VerificationEngine(
            crate::VerificationEngineRejection::VerificationEngineInformationShape,
        )));
    }
    let info = VerifyEngineInfo {
        source_path: path,
        source_sha256,
        integrity,
        windows_file_pinned: pinning,
        image_matches_source: export_check.completed_observation()?,
        windows_loader,
        abi_version: version.abi_version,
        implementation_version: version.implementation_version,
        openssl_version: version.openssl_version,
        verification_service: image.table.verify.is_some() && image.table.probe.is_some(),
        verification_algorithms_service: image.table.verification_algorithms.is_some(),
        digest_service: image.table.digest.is_some(),
    };
    Ok(VerifyEngine {
        lease: Arc::new(Lease {
            image,
            info,
            _source: source,
        }),
    })
}
