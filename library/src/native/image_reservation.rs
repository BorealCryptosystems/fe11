// SPDX-License-Identifier: Apache-2.0
//! Image retention, initialization attempts and Finalize authority are distinct.
use super::{dispatch, Uncertainty};
use crate::{Error, Result};
use std::cell::Cell;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};

#[derive(Clone, Copy)]
pub(super) struct Lease {
    address: usize,
    generation: u64,
}

enum Phase {
    SuccessorReserved,
    Loading,
    Active {
        dispatch: Option<Arc<dispatch::Dispatch>>,
        uncertainty: Weak<Uncertainty>,
    },
}

struct Image {
    generation: u64,
    phase: Phase,
    attempts: usize,
    finalizing: bool,
}

#[derive(Default)]
struct Images {
    next: u64,
    entries: HashMap<usize, Image>,
}
static IMAGES: OnceLock<Mutex<Images>> = OnceLock::new();

/// A second loader may observe the module's Initialize refusal, but cannot
/// acquire the earlier generation's Finalize authority. Its short reservation
/// excludes Finalize during initialization; C never holds the global mutex.
pub(super) struct Reservation<'a> {
    successor: Option<&'a Successor>,
    owned: Vec<Lease>,
    borrowed: Vec<Lease>,
    dispatch: Vec<dispatch::Guard>,
    uncertain: &'a Cell<bool>,
    published: bool,
}

impl<'a> Reservation<'a> {
    /// Coordinate only the runtime identified by the selected initializer.
    /// Discovery exports may belong to unrelated runtimes in the same scope.
    pub(super) fn for_initializer(
        address: usize,
        uncertain: &'a Cell<bool>,
        successor: Option<&'a Successor>,
    ) -> Result<Self> {
        let mut reservation = Self {
            successor,
            owned: Vec::new(),
            borrowed: Vec::new(),
            dispatch: Vec::new(),
            uncertain,
            published: false,
        };
        reservation.include(address)?;
        reservation.check_borrowed()?;
        Ok(reservation)
    }

    fn include(&mut self, address: usize) -> Result<()> {
        if self
            .owned
            .iter()
            .chain(&self.borrowed)
            .any(|lease| lease.address == address)
        {
            return Ok(());
        }
        self.owned.try_reserve(1).map_err(|_| {
            Error::Rejected(crate::RejectionReason::NativeLoading(
                crate::NativeLoadingRejection::ImageReservationAllocation,
            ))
        })?;
        self.borrowed.try_reserve(1).map_err(|_| {
            Error::Rejected(crate::RejectionReason::NativeLoading(
                crate::NativeLoadingRejection::ImageReservationAllocation,
            ))
        })?;
        self.dispatch.try_reserve(1).map_err(|_| {
            Error::Rejected(crate::RejectionReason::NativeLoading(
                crate::NativeLoadingRejection::ImageDispatchAllocation,
            ))
        })?;
        let mut images = IMAGES
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| Error::Poisoned)?;
        if let Some(image) = images.entries.get_mut(&address) {
            if let Some(successor) = self.successor {
                if successor
                    .leases
                    .iter()
                    .any(|lease| lease.address == address && lease.generation == image.generation)
                    && matches!(image.phase, Phase::SuccessorReserved)
                {
                    image.phase = Phase::Loading;
                    self.owned.push(Lease {
                        address,
                        generation: image.generation,
                    });
                    return Ok(());
                }
                return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
                    crate::NativeLoadingRejection::SuccessorImageReservationMismatch,
                )));
            }
            if image.finalizing {
                return Err(Error::Busy(crate::BusyReason::NativeLoading(
                    crate::NativeLoadingBusy::NativeImageFinalizing,
                )));
            }
            if image.attempts != 0 {
                return Err(Error::Busy(crate::BusyReason::NativeLoading(
                    crate::NativeLoadingBusy::NativeImageInitializationAttemptActive,
                )));
            }
            let Phase::Active {
                dispatch,
                uncertainty,
            } = &image.phase
            else {
                return Err(Error::Busy(crate::BusyReason::NativeLoading(
                    crate::NativeLoadingBusy::NativeImageInitializing,
                )));
            };
            let uncertainty = uncertainty.upgrade().ok_or(Error::Rejected(
                crate::RejectionReason::NativeLoading(
                    crate::NativeLoadingRejection::NativeImageOwnerWithdrawn,
                ),
            ))?;
            if uncertainty.is_uncertain() {
                return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::NativeStateUncertain,
                )));
            }
            let dispatch = dispatch.clone();
            image.attempts = image.attempts.checked_add(1).ok_or(Error::Rejected(
                crate::RejectionReason::NativeLoading(
                    crate::NativeLoadingRejection::InitializationAttemptCountExhausted,
                ),
            ))?;
            self.borrowed.push(Lease {
                address,
                generation: image.generation,
            });
            drop(images);
            // Use A's dispatch contract, never B's proposed flags/callbacks.
            // The generation reservation already excludes A's Finalize.
            if let Some(dispatch) = dispatch {
                self.dispatch.push(dispatch.enter_loading(
                    &crate::admission_wait::current(),
                    &|| {
                        if uncertainty.is_uncertain() {
                            Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                                crate::ModuleLifecycleRejection::NativeStateUncertain,
                            )))
                        } else {
                            Ok(())
                        }
                    },
                )?);
            }
            if uncertainty.is_uncertain() {
                return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::NativeStateUncertain,
                )));
            }
        } else {
            if self.successor.is_some() {
                return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
                    crate::NativeLoadingRejection::SuccessorSelectsADifferentNativeImage,
                )));
            }
            let generation = images.next.checked_add(1).ok_or(Error::Rejected(
                crate::RejectionReason::NativeLoading(
                    crate::NativeLoadingRejection::ImageGenerationExhausted,
                ),
            ))?;
            images.entries.try_reserve(1).map_err(|_| {
                Error::Rejected(crate::RejectionReason::NativeLoading(
                    crate::NativeLoadingRejection::ImageReservationAllocation,
                ))
            })?;
            images.next = generation;
            images.entries.insert(
                address,
                Image {
                    generation,
                    phase: Phase::Loading,
                    attempts: 0,
                    finalizing: false,
                },
            );
            self.owned.push(Lease {
                address,
                generation,
            });
        }
        Ok(())
    }

    pub(super) fn borrowed_owner(&self) -> bool {
        !self.borrowed.is_empty()
    }

    /// Revalidate the borrowed runtime generation after preparation, before
    /// issuing the next native phase. Discovery itself does not borrow a runtime.
    pub(super) fn check_borrowed(&self) -> Result<()> {
        let images = IMAGES
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| Error::Poisoned)?;
        for lease in &self.borrowed {
            let image = images
                .entries
                .get(&lease.address)
                .filter(|image| image.generation == lease.generation)
                .ok_or(Error::Rejected(crate::RejectionReason::NativeLoading(
                    crate::NativeLoadingRejection::ImageInitializationGenerationChanged,
                )))?;
            let Phase::Active { uncertainty, .. } = &image.phase else {
                return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
                    crate::NativeLoadingRejection::NativeImageNotInitialized,
                )));
            };
            let uncertainty = uncertainty.upgrade().ok_or(Error::Rejected(
                crate::RejectionReason::NativeLoading(
                    crate::NativeLoadingRejection::NativeImageOwnerWithdrawn,
                ),
            ))?;
            if uncertainty.is_uncertain() {
                return Err(Error::Rejected(crate::RejectionReason::ModuleLifecycle(
                    crate::ModuleLifecycleRejection::NativeStateUncertain,
                )));
            }
        }
        Ok(())
    }

    pub(super) fn publish(
        mut self,
        dispatch: Option<&Arc<dispatch::Dispatch>>,
        uncertainty: &Arc<Uncertainty>,
    ) -> Result<Vec<Lease>> {
        if self.borrowed_owner() {
            self.uncertain.set(true);
            return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
                crate::NativeLoadingRejection::CompetingInitializerCannotOwnFinalize,
            )));
        }
        let mut images = IMAGES.get_or_init(Default::default).lock().map_err(|_| {
            self.uncertain.set(true);
            Error::Poisoned
        })?;
        if !self.owned.iter().all(|lease| {
            images.entries.get(&lease.address).is_some_and(|image| {
                image.generation == lease.generation && matches!(image.phase, Phase::Loading)
            })
        }) {
            self.uncertain.set(true);
            return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
                crate::NativeLoadingRejection::ImageInitializationGenerationChanged,
            )));
        }
        // The complete set was checked under this same mutex. Updating phase
        // cannot remove entries; neither callbacks nor another thread can mutate
        // the map between validation and these generation-preserving updates.
        for lease in &self.owned {
            images
                .entries
                .get_mut(&lease.address)
                .expect("checked image generation")
                .phase = Phase::Active {
                dispatch: dispatch.cloned(),
                uncertainty: Arc::downgrade(uncertainty),
            };
        }
        self.published = true;
        Ok(std::mem::take(&mut self.owned))
    }
}

pub(super) fn contains(leases: &[Lease]) -> bool {
    let images = IMAGES
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    !leases.is_empty()
        && leases.iter().all(|lease| {
            images
                .entries
                .get(&lease.address)
                .is_some_and(|image| image.generation == lease.generation)
        })
}

/// Reserve all aliases atomically before Finalize can be dispatched. A loading
/// attempt cannot join after this point, including while a slot waiter returns.
pub(super) fn reserve_finalize(leases: &[Lease]) -> Result<()> {
    let mut images = IMAGES
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| Error::Poisoned)?;
    for lease in leases {
        let image = images
            .entries
            .get(&lease.address)
            .filter(|image| image.generation == lease.generation)
            .ok_or(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::ModuleIdentityReservationAbsent,
            )))?;
        if image.attempts != 0 {
            return Err(Error::Busy(crate::BusyReason::NativeLoading(
                crate::NativeLoadingBusy::NativeInitializationAttemptActive,
            )));
        }
    }
    // Validation and mutation share one mutex guard; no map mutation or
    // user code intervenes, so each checked generation remains present.
    for lease in leases {
        images
            .entries
            .get_mut(&lease.address)
            .expect("checked image generation")
            .finalizing = true;
    }
    Ok(())
}

/// A returned refusal keeps the same generation and initialization authority,
/// but no finalization call remains in flight. Reopen loading-attempt admission
/// atomically across its aliases; never transfer or recreate a reservation.
pub(super) fn finalization_refused(leases: &[Lease]) -> Result<()> {
    let mut images = IMAGES
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| Error::Poisoned)?;
    for lease in leases {
        if !images
            .entries
            .get(&lease.address)
            .is_some_and(|image| image.generation == lease.generation)
        {
            return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::ModuleIdentityReservationAbsent,
            )));
        }
    }
    for lease in leases {
        images
            .entries
            .get_mut(&lease.address)
            .expect("generation validated under image registry lock")
            .finalizing = false;
    }
    Ok(())
}

pub(super) fn release(leases: &[Lease]) -> bool {
    release_with_file(leases, None)
}

/// Validate all image leases before decrementing the file reservation. Keep
/// the image lock through the file update, then perform only infallible removals.
/// File-registry operations never acquire the image lock: this order cannot
/// reverse. A failed validation changes neither registry, so local repair cannot
/// decrement a different owner's file count after a partially completed release.
pub(super) fn release_with_file(leases: &[Lease], identity: Option<super::FileIdentity>) -> bool {
    let mut images = IMAGES
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if !leases.iter().all(|lease| {
        images
            .entries
            .get(&lease.address)
            .is_some_and(|image| image.generation == lease.generation && image.attempts == 0)
    }) {
        return false;
    }
    if !identity.map_or(true, super::release_file) {
        return false;
    }
    for lease in leases {
        images.entries.remove(&lease.address);
    }
    true
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if self.uncertain.get() {
            if let Some(successor) = self.successor {
                successor
                    .retained
                    .store(true, std::sync::atomic::Ordering::Release);
            }
            // An uncompleted attempt may still use its callbacks/arguments.
            // Keep reservations and withdraw every earlier owner it touched.
            // Notify outside the global mutex: wake callbacks can inspect
            // other admission domains.
            for lease in &self.borrowed {
                let uncertainty = {
                    let images = IMAGES
                        .get_or_init(Default::default)
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    images
                        .entries
                        .get(&lease.address)
                        .and_then(|image| match &image.phase {
                            Phase::Active { uncertainty, .. }
                                if image.generation == lease.generation =>
                            {
                                uncertainty.upgrade()
                            }
                            _ => None,
                        })
                };
                if let Some(uncertainty) = uncertainty {
                    uncertainty.mark();
                }
            }
            return;
        }
        // Release borrowed dispatch before its reservation can admit Finalize.
        self.dispatch.clear();
        {
            let mut images = IMAGES
                .get_or_init(Default::default)
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            for lease in &self.borrowed {
                if let Some(image) = images
                    .entries
                    .get_mut(&lease.address)
                    .filter(|image| image.generation == lease.generation)
                {
                    // include increments once per distinct address and pushes
                    // its lease into pre-reserved storage before releasing the
                    // mutex. This consuming Drop is the only decrement; Finalize
                    // and succession reject nonzero attempts. Poison recovery
                    // cannot introduce an unpaired lease or decrement twice.
                    image.attempts = image
                        .attempts
                        .checked_sub(1)
                        .expect("reserved initialization attempt");
                }
            }
        }
        if !self.published {
            release(&self.owned);
        }
    }
}

/// Exclusive reservation of the next generation, before loading or Initialize.
/// Old leases can never remove these entries: release compares both identities.
pub(crate) struct Successor {
    leases: Vec<Lease>,
    retained: std::sync::atomic::AtomicBool,
}

pub(super) fn reserve_successor(previous: &[Lease]) -> Result<Successor> {
    if previous.is_empty() {
        return Err(Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::SuccessorImageIdentityAbsent,
        )));
    }
    let mut leases = Vec::new();
    leases.try_reserve_exact(previous.len()).map_err(|_| {
        Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::SuccessorReservationAllocation,
        ))
    })?;
    let mut images = IMAGES
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| Error::Poisoned)?;
    for lease in previous {
        if let Some(image) = images.entries.get(&lease.address) {
            if image.generation != lease.generation || image.attempts != 0 {
                return Err(Error::Busy(crate::BusyReason::NativeLoading(
                    crate::NativeLoadingBusy::DifferentNativeGenerationOrInitializerActive,
                )));
            }
        }
    }
    let generation = images.next.checked_add(1).ok_or(Error::Rejected(
        crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::ImageGenerationExhausted,
        ),
    ))?;
    images.entries.try_reserve(previous.len()).map_err(|_| {
        Error::Rejected(crate::RejectionReason::NativeLoading(
            crate::NativeLoadingRejection::SuccessorRegistryAllocation,
        ))
    })?;
    // All fallible preparation precedes mutation; no C or opaque Drop here.
    images.next = generation;
    for previous in previous {
        images.entries.insert(
            previous.address,
            Image {
                generation,
                phase: Phase::SuccessorReserved,
                attempts: 0,
                finalizing: false,
            },
        );
        leases.push(Lease {
            address: previous.address,
            generation,
        });
    }
    Ok(Successor {
        leases,
        retained: std::sync::atomic::AtomicBool::new(false),
    })
}

impl Drop for Successor {
    fn drop(&mut self) {
        if self.retained.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        let mut images = IMAGES
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for lease in &self.leases {
            if images.entries.get(&lease.address).is_some_and(|image| {
                image.generation == lease.generation
                    && matches!(image.phase, Phase::SuccessorReserved)
            }) {
                images.entries.remove(&lease.address);
            }
        }
    }
}
