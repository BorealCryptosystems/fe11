// SPDX-License-Identifier: Apache-2.0
use crate::{Error, MechanismInfo, Result};

/// Exact result of querying an advertised mechanism during discovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MechanismObservation {
    /// Native properties were returned successfully; parameters remain untested.
    Available(MechanismInfo),
    /// The identifier was listed, but C_GetMechanismInfo is absent from the
    /// selected table. This is not a native refusal or an empty property set.
    Unavailable,
    /// C_GetMechanismInfo refused this advertised identifier. The mechanism is
    /// not established by discovery; the original return code remains visible.
    /// Ordinary operations still preserve their own native result.
    Refused {
        /// Exact public PKCS#11 return code.
        code: u64,
    },
}

/// Outcome of listing mechanisms, separate from querying each mechanism.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MechanismDiscovery {
    /// Listing was deliberately not performed, for example on a blank token.
    NotRequested,
    /// The native list completed within the caller's chosen resource limits.
    Complete,
    /// Listing did not complete. An empty catalogue does not mean non-support.
    Unavailable(Error),
}

/// Immutable mechanism observations, with one canonical state per identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MechanismCatalog {
    observations: Vec<(u64, MechanismObservation)>,
    discovery: MechanismDiscovery,
}

impl Default for MechanismCatalog {
    fn default() -> Self {
        Self {
            observations: Vec::new(),
            discovery: MechanismDiscovery::NotRequested,
        }
    }
}

impl MechanismCatalog {
    /// Provenance of the list, without converting an unavailable list to empty.
    pub fn discovery(&self) -> &MechanismDiscovery {
        &self.discovery
    }

    pub(crate) fn set_discovery(&mut self, discovery: MechanismDiscovery) {
        self.discovery = discovery;
    }
    /// Return successfully observed properties only. Use observation to
    /// distinguish a native refusal from an identifier absent from the list.
    pub fn get(&self, mechanism: &u64) -> Option<&MechanismInfo> {
        match self.observation(mechanism) {
            Some(MechanismObservation::Available(info)) => Some(info),
            _ => None,
        }
    }

    /// Return the exact observation, including a native refusal if present.
    pub fn observation(&self, mechanism: &u64) -> Option<&MechanismObservation> {
        self.observations
            .binary_search_by_key(mechanism, |entry| entry.0)
            .ok()
            .map(|index| &self.observations[index].1)
    }

    /// Iterate all advertised identifiers and their exact observed results.
    pub fn observations(&self) -> impl Iterator<Item = (&u64, &MechanismObservation)> {
        self.observations
            .iter()
            .map(|(mechanism, value)| (mechanism, value))
    }

    /// Return properties or the original native refusal, without a native call.
    /// An unadvertised mechanism is a distinct local rejection.
    pub fn properties(&self, mechanism: &u64) -> Result<&MechanismInfo> {
        self.require(
            mechanism,
            crate::RejectionReason::Mechanisms(crate::MechanismsRejection::MechanismNotAnnounced),
        )
    }

    pub(crate) fn require(
        &self,
        mechanism: &u64,
        absent: crate::RejectionReason,
    ) -> Result<&MechanismInfo> {
        match self.observation(mechanism) {
            Some(MechanismObservation::Available(info)) => Ok(info),
            Some(MechanismObservation::Unavailable) => {
                Err(Error::Unsupported(crate::UnsupportedReason::Mechanisms(
                    crate::MechanismsUnsupported::CGetMechanismInfoUnavailable,
                )))
            }
            Some(MechanismObservation::Refused { code }) => Err(Error::Native {
                function: "C_GetMechanismInfo",
                code: *code,
                may_have_effect: false,
            }),
            None => match &self.discovery {
                MechanismDiscovery::Complete => Err(Error::Rejected(absent)),
                MechanismDiscovery::Unavailable(error) => Err(error.clone()),
                MechanismDiscovery::NotRequested => {
                    Err(Error::Unsupported(crate::UnsupportedReason::Mechanisms(
                        crate::MechanismsUnsupported::MechanismListNotObserved,
                    )))
                }
            },
        }
    }

    pub(crate) fn insert(&mut self, mechanism: u64, value: MechanismObservation) -> Result<()> {
        match self
            .observations
            .binary_search_by_key(&mechanism, |entry| entry.0)
        {
            Err(index) => {
                // Reserve before mutation. Insertion preserves the sorted,
                // unique identifiers used by lookup and public iteration.
                self.observations.try_reserve(1).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::Mechanisms(
                        crate::MechanismsRejection::MechanismCatalogueAllocation,
                    ))
                })?;
                self.observations.insert(index, (mechanism, value));
                Ok(())
            }
            Ok(index) if self.observations[index].1 == value => Ok(()),
            Ok(_) => Err(Error::Rejected(crate::RejectionReason::Mechanisms(
                crate::MechanismsRejection::ConflictingMechanismProperties,
            ))),
        }
    }
}


