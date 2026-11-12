// SPDX-License-Identifier: Apache-2.0
//! Requested initialization and attachment have different native effects.

use super::{frame, image, image_reservation, loading};
use crate::{Error, Result};
use fe11_sys::*;
use std::sync::Arc;

pub(crate) enum Request<'a> {
    Initialize {
        successor: Option<&'a image_reservation::Successor>,
        options: crate::InitializationOptions,
        reserved: Option<crate::InitializationReserved>,
        mutexes: Option<crate::InitializationMutexes>,
        diagnostic: &'a mut crate::error::PreparedCompletion,
        credit: crate::symmetric::memory::ResidentCredit,
    },
    Attach {
        successor: Option<&'a image_reservation::Successor>,
        owner: crate::ExternalInitialization,
        credit: crate::symmetric::memory::ResidentCredit,
    },
}

impl<'a> Request<'a> {
    pub(super) fn successor(&self) -> Option<&'a image_reservation::Successor> {
        match self {
            Self::Initialize { successor, .. } | Self::Attach { successor, .. } => *successor,
        }
    }
    pub(crate) fn prepare(
        external: Option<crate::ExternalInitialization>,
        options: crate::InitializationOptions,
        reserved: Option<crate::InitializationReserved>,
        mutexes: Option<crate::InitializationMutexes>,
        budget: &Arc<crate::symmetric::memory::Budget>,
        diagnostic: &'a mut Option<crate::error::PreparedCompletion>,
        successor: Option<&'a image_reservation::Successor>,
    ) -> Result<Self> {
        if let Some(owner) = external {
            if reserved.is_some() || mutexes.is_some() {
                return Err(Error::Rejected(
                    crate::RejectionReason::ModuleConfiguration(crate::ModuleConfigurationRejection::InitializationArgumentsDuringAttachment),
                ));
            }
            let credit = budget
                .reserve(std::mem::size_of::<image::InitializationOwner>())?
                .into_module_resident()?;
            return Ok(Self::Attach {
                owner,
                credit,
                successor,
            });
        }
        let frame_bytes = crate::module::initialization::InitializationFrame::allocation_bytes();
        let mut prepaid =
            budget.reserve(crate::error::PreparedCompletion::allocation_bytes() + frame_bytes)?;
        let credit = prepaid.split(frame_bytes)?.into_module_resident()?;
        let diagnostic = diagnostic.insert(crate::error::PreparedCompletion::prepare(
            "C_Initialize",
            &mut prepaid,
        )?);
        Ok(Self::Initialize {
            successor,
            options,
            reserved,
            mutexes,
            diagnostic,
            credit,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DropPolicy {
    Automatic,
    Explicit,
}

pub(super) struct Prepared {
    pub owner: image::InitializationOwner,
    pub serialized: bool,
    pub initialize_calls: u64,
    pub drop_policy: DropPolicy,
}

pub(super) fn establish(
    request: Request<'_>,
    table: &crate::interfaces::CommonFunctions,
    initialize: super::functions::InitializationCall,
    interface_flags: u64,
    image: &loading::LoadingImage<'_>,
    reservation: &image_reservation::Reservation<'_>,
) -> Result<Prepared> {
    let (options, reserved, mutexes, diagnostic, credit) = match request {
        Request::Attach { owner, credit, .. } => {
            owner.check(table, interface_flags)?;
            if reservation.borrowed_owner() {
                return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
                    crate::NativeLoadingRejection::ExternalImageAlreadyHasARuntime,
                )));
            }
            // The unsafe declaration establishes the actual active locking and
            // lifetime contract. No flags, mutexes or Initialize are resubmitted.
            let serialized = owner.serialized();
            return Ok(Prepared {
                owner: image::InitializationOwner::External {
                    owner,
                    _credit: credit,
                },
                serialized,
                initialize_calls: 0,
                drop_policy: DropPolicy::Explicit,
            });
        }
        Request::Initialize {
            successor: _,
            options,
            reserved,
            mutexes,
            diagnostic,
            credit,
        } => (options, reserved, mutexes, diagnostic, credit),
    };
    let flags = (if options.concurrency == crate::NativeConcurrency::Concurrent {
        CKF_OS_LOCKING_OK
    } else {
        0
    }) | if options.cannot_create_os_threads {
        CKF_LIBRARY_CANT_CREATE_OS_THREADS
    } else {
        0
    };
    let serialized = match options.concurrency {
        crate::NativeConcurrency::Concurrent => false,
        crate::NativeConcurrency::Serialized => true,
        crate::NativeConcurrency::ApplicationMutexes => !mutexes
            .as_ref()
            .is_some_and(crate::InitializationMutexes::complete),
    };
    let mut args =
        frame::NativeFrame::new(crate::module::initialization::InitializationFrame::new(
            flags as _, reserved, mutexes, credit,
        )?)?;
    reservation.check_borrowed()?;
    let diagnostic = diagnostic.take()?;
    // SAFETY: the descriptor and all callback/pReserved referents have stable
    // owners through the native result, including the existing quarantine path.
    // The caller's unsafe ABI declarations cover native-thread callback use.
    let rv = unsafe { initialize((&mut *args.args as *mut CK_C_INITIALIZE_ARGS).cast()) };
    let result = match args.loading_result(
        rv,
        "C_Initialize",
        &image.uncertain,
        crate::native_return::effect_uncertain(rv),
    ) {
        Err(error) if matches!(rv, CKR_PENDING | CKR_GENERAL_ERROR) => return Err(error),
        result => result,
    };
    // A terminal refusal is not evidence that input-only fields stayed intact.
    if let Err(error) = args.validate_return() {
        args.quarantine_loading(&image.uncertain);
        return Err(diagnostic.boundary_failure(rv, error));
    }
    result?;
    if reservation.borrowed_owner() {
        args.quarantine_loading(&image.uncertain);
        return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::ModuleAcceptedCompetingInitialization,
        )));
    }
    Ok(Prepared {
        owner: image::InitializationOwner::Fe11 {
            _frame: args.into_inner()?,
        },
        serialized,
        initialize_calls: 1,
        drop_policy: DropPolicy::Automatic,
    })
}
