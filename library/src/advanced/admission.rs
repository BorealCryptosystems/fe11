// SPDX-License-Identifier: Apache-2.0
//! Owned selection and policy reads; never export secret-key values.
use super::{
    drive, spend, AdvancedSession, AdvancedSessionMode, Operation, OperationBody, OperationPacing,
    OperationProgress, OperationTicket,
};

use crate::crypto::KeyAdmissionDescription;
use crate::error::check;
use crate::module::{SessionEntry, State};
use crate::symmetric::memory::{Budget, Credit};

use crate::{
    attributes::{RequiredAttributes, Template},
    managed,
    symmetric::keys,
    ManagedClass, SymmetricKeySpec,
};
use crate::{bounds, Error, Result, Session};

use fe11_sys::{
    CKF_FIND_OBJECTS, CKR_OK, CKR_PENDING, CK_ASYNC_DATA, CK_ATTRIBUTE, CK_FLAGS,
    CK_INVALID_HANDLE, CK_OBJECT_HANDLE, CK_RV, CK_ULONG, CK_UNAVAILABLE_INFORMATION,
};
use std::sync::atomic::Ordering;
use std::sync::Arc;

mod active;
use active::Frames;
mod selector;
use selector::Selector;
mod read;

mod initial;
mod input;
mod resources;
use read::{ReadOwner, ReadPlans};
pub(super) use resources::{PreparedResource, ResourceCandidate, ResourceNeed};
mod destination;
mod generation;
mod pair;
mod pair_policy;
mod publication;
use pair_policy::PreparedPair;
mod symmetric_publication;
mod synchronous;
use destination::CreationDestinations;
use generation::Generation;
use pair::PairFrame;
use symmetric_publication::Publication;
pub(crate) use synchronous::{
    aes_kek_synchronous, agreement_pair_synchronous, classical_pair_synchronous,
    derivation_base_synchronous, find_kem_synchronous, generate_kem_synchronous,
    introduced_symmetric_synchronous, pqc_pair_synchronous, rsa_transport_synchronous,
    symmetric_synchronous, transport_signing_synchronous, verification_synchronous,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Init,
    Find,
    Final,
    Required,
    RequiredLocal { rv: CK_RV },
    PublicMaterial,
    History,
    Allowed,
    Properties,
    Generate,
    Destroy,
    Done,
    Failed,
}

#[derive(Clone, Copy)]
enum SearchAcceptance {
    Native,
    Preparing {
        rv: CK_RV,
        count: usize,
        need: managed::search::SearchNeed,
    },
    Prepared {
        rv: CK_RV,
        count: usize,
    },
}

struct FindFrame {
    acceptance: SearchAcceptance,
    _template: Box<Template>,
    attrs: Vec<CK_ATTRIBUTE>,
    handles: Vec<CK_OBJECT_HANDLE>,
    count: Box<CK_ULONG>,
    _selector_credit: Option<Credit>,
}
// SAFETY: boxed/template Vec storage is frozen before Init, retained by the
// operation and accessed only under the owning session and operation guards.
unsafe impl Send for FindFrame {}

struct CompletionFrame {
    result: Box<CK_ASYNC_DATA>,
    name: [u8; 32],
}
// SAFETY: the completion union and function name are exclusively accessed under
// the same session/operation guards as the active frame. Their storage remains
// owned until the corresponding native completion is proven or quarantined.
unsafe impl Send for CompletionFrame {}
enum KeyPolicy {
    DerivationBase(Box<crate::crypto::derivation::PreparedDerivationBase>),
    Symmetric {
        spec: SymmetricKeySpec,
        publication: Publication,
    },
    VerificationPublic {
        prepared: crate::crypto::PreparedVerification,
    },
    Pair(Box<PairFrame>),
}

enum PublicationQuota {
    Bound(crate::registry::Reservation<crate::managed::NativeIdentity>),
}

// Candidate preparation has no native effect. All storage conversions,
// credit splits and creation-ticket preparation precede the access probe.
struct InitialCandidate {
    owner: input::Candidate,
    publication: Option<publication::Publication>,
    permit: Option<crate::registry::Reservation<crate::managed::NativeIdentity>>,
    generation: Option<generation::preparation::Prepared>,
    destinations: Option<CreationDestinations>,
    family: Option<pair::initial::Prepared>,
    initial: initial::InitialResources,
    cancel: crate::advanced::preparation::Shell,
    registry: super::ledger::PreparedOperation,
}
struct InitialAttempt<'a> {
    access: Option<crate::session::SessionAccess<'a>>,
    policy: Option<KeyPolicy>,
    generation: Option<Generation>,
    references: Option<crate::session::ManagedReferences>,
    readers: [Option<crate::registry::ReadPermit>; 2],
    candidate: InitialCandidate,
    reservation: Option<managed::Reservation>,
}
struct GuardedAdmission<'a> {
    access: Option<crate::session::SessionAccess<'a>>,
    pending_marker: Option<crate::error::PreparedCompletionStorage>,
    body: Option<Admission>,
    shell: Option<crate::advanced::preparation::Shell>,
    operation: Option<Operation>,
    registry: Option<super::ledger::PreparedOperation>,
    // Keep the final strong owner after its registry entry is retired on error.
    // The access field above must leave before this anchor can destroy the body.
    installed: Option<Arc<super::ledger::OperationCell>>,
}

enum InitialResource {
    Selection(usize),
    Creation,
}

pub(super) struct Admission {
    publication: Option<publication::Publication>,
    stage: Stage,
    // Monotone history of dispatch, independent of the current stage. A local
    // refusal before the first C may retire this owner; later errors may not
    // erase search state, returned handles or creation/recovery obligations.
    dispatched: bool,
    pending: bool,
    generation: Option<Generation>,
    failure: Option<Error>,
    // The three heap leaves are charged and allocated before possession. A
    // refused Final can then report both causes without allocating after C.
    search_diagnostic: Option<crate::error::CleanupDiagnostic>,
    return_diagnostic: Option<crate::error::CompletionStorage>,
    // Generation must hand back its objects even if terminal ledger retirement
    // fails. Reserve the separate error chain before any native creation.
    retirement_diagnostic: Option<crate::error::CleanupDiagnostic>,
    // Poll borrows this prepaid envelope into its public-call owner before
    // driving. Unused envelopes return here across cooperative/pending results.
    pub(super) resource_diagnostics: Option<super::progress::FailureDiagnostics>,
    frames: Frames,
    completion: CompletionFrame,
    // Destination credit outlives the frame receiving its template storage.
    destinations: Option<CreationDestinations>,
    found: Vec<CK_OBJECT_HANDLE>,
    read_plans: ReadPlans,
    attributes: Option<RequiredAttributes>,
    history_observations: Option<crate::BaseProtection>,
    mechanism_report: Option<crate::MechanismObservationReport>,
    object_report: Option<crate::ObjectObservationReport>,
    search_report: Option<crate::ObjectSearchReport>,
    observation_authentication: u64,
    close_epoch: u64,
    permit: PublicationQuota,
    _destination_activity: [Option<crate::registry::ReadPermit>; 2],
    _metadata: Credit,
}

mod api;
mod completion;
mod observation;
mod policy;
mod preparation;
mod progression;
mod rejoin;
mod validation;
use completion::search_final_failure;
use preparation::start_admission;
use validation::check_initial_functions;
