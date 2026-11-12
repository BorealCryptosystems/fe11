// SPDX-License-Identifier: Apache-2.0
//! Explicit native content reads, protected values and value-free status reports.

use crate::{
    attributes, AttributeReadPlan, AttributeUnavailableCause, Error, Result, SecretBytes, Session,
};
use fe11_sys::*;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub(crate) mod fingerprint_observation;
pub(crate) mod owned;

/// Explicit content operation and resource budget; no default or inherited read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentReadPlan {
    /// Read CKA_VALUE into erased storage. The module decides whether it is readable.
    Value {
        /// Maximum native value length accepted before allocation.
        maximum_bytes: usize,
    },
    /// Historical public management fingerprint, not a normative/security profile.
    /// SHA-256 of domain tag, key type and ordered attribute tag/length/value tuples.
    PublicFingerprintV1 {
        /// Aggregate native bytes, including both class/type reads and selected material.
        read: AttributeReadPlan,
    },
}

/// A content observation could not be interpreted; no expected value is included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentIssue {
    /// A native scalar does not have CK_ULONG width.
    IntegerEncoding,
    /// PublicFingerprintV1 was requested for an observed non-public-key class.
    NotPublicKey,
    /// A public-material component is empty and cannot form this fingerprint.
    EmptyPublicMaterial,
    /// Class/type observations changed around the material read.
    ObjectChanged,
}

/// Availability only, independent of comparisons or the value's bytes/length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentStatus {
    /// No content operation was selected.
    NotRequested,
    /// Bytes were returned by the selected observation.
    Available,
    /// A required attribute was unavailable, with its native cause if known.
    Unavailable {
        /// Actual PKCS#11 attribute identifier.
        attribute: u64,
        /// Cause established by the attribute response.
        cause: AttributeUnavailableCause,
    },
    /// The requested interpretation could not be established.
    Unusable {
        /// Attribute responsible for the interpretation failure.
        attribute: u64,
        /// Exact interpretation issue, not a native return code.
        issue: ContentIssue,
    },
}

/// Observation with protected bytes. Neither Debug nor Clone exposes/copies them.
pub enum ProtectedContent {
    /// Exact bytes in one erased owner.
    Available(SecretBytes),
    /// A native attribute was unavailable.
    Unavailable {
        /// Native attribute identifier.
        attribute: u64,
        /// Native attribute availability cause.
        cause: AttributeUnavailableCause,
    },
    /// Available attributes did not support the requested interpretation.
    Unusable {
        /// Attribute whose interpretation failed.
        attribute: u64,
        /// Interpretation issue.
        issue: ContentIssue,
    },
}
impl ProtectedContent {
    /// Public observation status only; no native call.
    pub fn status(&self) -> ContentStatus {
        match self {
            Self::Available(_) => ContentStatus::Available,
            Self::Unavailable { attribute, cause } => ContentStatus::Unavailable {
                attribute: *attribute,
                cause: *cause,
            },
            Self::Unusable { attribute, issue } => ContentStatus::Unusable {
                attribute: *attribute,
                issue: *issue,
            },
        }
    }
    /// Consume an available observation; missing bytes produce a local diagnostic.
    /// This does not invent a native CK_RV or substitute a value.
    pub fn into_bytes(self) -> Result<SecretBytes> {
        match self {
            Self::Available(bytes) => Ok(bytes),
            missing => Err(Error::ContentUnavailable {
                status: missing.status(),
            }),
        }
    }
}

/// Explicit content reading choice. Reading a value may copy a readable secret
/// into this process; the native buffer is erased when its owner is dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentObservation {
    /// Perform no content read.
    NotRequested,
    /// Read the selected content and report availability. To obtain its bytes,
    /// use the explicit content-reading API returning ProtectedContent.
    Observe(ContentReadPlan),
}

/// Independent content observations around a mutation.
pub struct ContentMutationPlan {
    /// Explicit observation before the native mutation.
    pub before: ContentObservation,
    /// Explicit observation after native success.
    pub after: ContentObservation,
}

/// Value-free status of one content observation, with no equality verdict.
/// A selected observation is not atomic with a later native call. Local
/// possession coordinates Fe11 participants, not other processes using the token.
#[derive(Debug)]
pub struct ContentReport {
    selection: ContentObservation,
    status: ContentStatus,
}
impl ContentReport {
    /// Exact requested read, without native content bytes.
    pub fn selection(&self) -> &ContentObservation {
        &self.selection
    }
    /// Native availability or local interpretation status.
    pub fn status(&self) -> ContentStatus {
        self.status
    }
}
impl ContentObservation {
    /// Only an unrequested observation can complete without its resident reader.
    pub(crate) fn observe_local(self) -> Result<ContentReport> {
        self.observe_with(|_| {
            Err(Error::Rejected(crate::RejectionReason::ObjectContent(
                crate::ObjectContentRejection::ContentObservationRequiresPreparedOwner,
            )))
        })
    }
    /// The callback owns its read permission and protected buffers until it returns.
    pub(crate) fn observe_with(
        self,
        observe: impl FnOnce(ContentReadPlan) -> Result<ProtectedContent>,
    ) -> Result<ContentReport> {
        let status = match self {
            Self::NotRequested => ContentStatus::NotRequested,
            Self::Observe(read) => observe(read)?.status(),
        };
        Ok(ContentReport {
            selection: self,
            status,
        })
    }
}

fn unavailable(attribute: CK_ATTRIBUTE_TYPE, cause: AttributeUnavailableCause) -> ProtectedContent {
    ProtectedContent::Unavailable {
        attribute: attribute as u64,
        cause,
    }
}
fn unusable(attribute: CK_ATTRIBUTE_TYPE, issue: ContentIssue) -> ProtectedContent {
    ProtectedContent::Unusable {
        attribute: attribute as u64,
        issue,
    }
}

// The pinned SHA-256 implementation stores flat state/buffer data, not heap
// owners. Keep that state in one aligned stable allocation and erase it on all
// exits, including a later class/type change. Digest implementation temporaries,
// compiler/register copies and native-provider copies are outside this guarantee.
const _: () = assert!(!std::mem::needs_drop::<Sha256>());
pub(crate) struct ProtectedFingerprintHash {
    state: Vec<std::mem::MaybeUninit<Sha256>>,
    output: Option<SecretBytes>,
    _credit: Option<crate::symmetric::memory::Credit>,
}
impl ProtectedFingerprintHash {
    fn new() -> Result<Self> {
        let mut state = Vec::new();
        state.try_reserve_exact(1).map_err(|_| {
            Error::Rejected(crate::RejectionReason::ObjectContent(
                crate::ObjectContentRejection::FingerprintStateAllocation,
            ))
        })?;
        state.push(std::mem::MaybeUninit::new(Sha256::new()));
        Ok(Self {
            state,
            output: Some(SecretBytes::new(32)?),
            _credit: None,
        })
    }
    fn requested_bytes() -> usize {
        std::mem::size_of::<Sha256>() + 32
    }
    fn allocated_bytes(&self) -> Result<usize> {
        self.state
            .capacity()
            .checked_mul(std::mem::size_of::<Sha256>())
            .and_then(|n| {
                n.checked_add(self.output.as_ref().map_or(0, SecretBytes::allocated_bytes))
            })
            .ok_or(Error::Rejected(crate::RejectionReason::ObjectContent(
                crate::ObjectContentRejection::FingerprintHashAccounting,
            )))
    }
    fn bind(mut self, prepaid: &mut crate::symmetric::memory::Credit) -> Result<Self> {
        let bytes = self.allocated_bytes()?;
        self._credit = Some(prepaid.split(bytes)?);
        let credit = self._credit.as_mut().expect("fingerprint storage credited");
        self.output = self
            .output
            .take()
            .map(|output| output.bind_prepaid_payload(credit))
            .transpose()?;
        // Headers are inline in the already credited FingerprintOwner. Output
        // payload keeps its own credit when the owner publishes the fingerprint.
        Ok(self)
    }
    fn update(&mut self, bytes: impl AsRef<[u8]>) {
        // SAFETY: exactly one initialized state is installed by new; no method
        // removes it or exposes a borrow, and erasure occurs only in Drop.
        unsafe { self.state[0].assume_init_mut() }.update(bytes);
    }
    fn finish(&mut self) -> Result<SecretBytes> {
        let mut output =
            self.output
                .take()
                .ok_or(Error::Rejected(crate::RejectionReason::ObjectContent(
                    crate::ObjectContentRejection::FingerprintAlreadyFinished,
                )))?;
        // SAFETY: same initialized-state invariant as update. finalize_reset
        // leaves a valid initialized SHA-256 state for the later Drop erasure.
        let mut hash = unsafe { self.state[0].assume_init_mut() }.finalize_reset();
        output.as_mut_slice().copy_from_slice(&hash[..]);
        hash[..].zeroize();
        Ok(output)
    }
}
impl Drop for ProtectedFingerprintHash {
    fn drop(&mut self) {
        // SAFETY: a single live aligned MaybeUninit<Sha256> allocation, exclusively
        // owned. Pinned Sha256 owns only flat state/buffer data and has no Drop.
        // Zeroing MaybeUninit cannot create an invalid typed SHA value; there is
        // no later assume_init access. Vec only deallocates the erased storage.
        unsafe { zeroize::zeroize_flat_type(self.state.as_mut_ptr()) };
    }
}
