// SPDX-License-Identifier: Apache-2.0
//! Native creation, retained effects and targeted owned cleanup.
use super::{managed, AdvancedSession, OperationTicket, Stage, SymmetricKeySpec};
use crate::attributes::OwnedTemplate;
use crate::error::check;
use crate::module::{SessionEntry, State};
use crate::native_return::{FailureScope, MutationCall};
use crate::symmetric::memory::Credit;
use crate::{Error, Result};
use fe11_sys::{
    CKF_GENERATE, CKF_GENERATE_KEY_PAIR, CKR_OK, CKR_OPERATION_ACTIVE, CKR_SESSION_CLOSED,
    CKR_SESSION_HANDLE_INVALID, CK_ASYNC_DATA, CK_FLAGS, CK_INVALID_HANDLE, CK_MECHANISM,
    CK_MECHANISM_TYPE, CK_OBJECT_HANDLE, CK_RV, CK_ULONG,
};
use std::sync::atomic::Ordering;
pub(super) mod preparation;

// Exact native arity, without an absent private template on a single key.
enum Templates {
    Single {
        template: OwnedTemplate,
        count: CK_ULONG,
        output: Box<[CK_OBJECT_HANDLE; 1]>,
    },
    Pair {
        public: OwnedTemplate,
        private: OwnedTemplate,
        public_count: CK_ULONG,
        private_count: CK_ULONG,
        outputs: Box<[CK_OBJECT_HANDLE; 2]>,
    },
}
impl Templates {
    fn pair(&self) -> bool {
        matches!(self, Self::Pair { .. })
    }
    fn unchanged(&self) -> bool {
        match self {
            Self::Single { template, .. } => template.unchanged(),
            Self::Pair {
                public, private, ..
            } => public.unchanged() && private.unchanged(),
        }
    }
    fn outputs(&self) -> &[CK_OBJECT_HANDLE] {
        match self {
            Self::Single { output, .. } => &output[..],
            Self::Pair { outputs, .. } => &outputs[..],
        }
    }
    fn accept_outputs(&mut self, object: CK_OBJECT_HANDLE, additional: CK_OBJECT_HANDLE) {
        match self {
            Self::Single { output, .. } => output[0] = object,
            Self::Pair { outputs, .. } => **outputs = [object, additional],
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum StorageUse {
    Prepared,
    InUse,
    Completed,
    Uncertain,
}
// Stable allocation is fallible and covered by the owner's credit before dispatch.
fn scalar_storage<T>(values: impl ExactSizeIterator<Item = T>) -> Result<Vec<T>> {
    let mut owned = Vec::new();
    owned.try_reserve_exact(values.len()).map_err(|_| {
        Error::Rejected(crate::RejectionReason::KeyAdmission(
            crate::KeyAdmissionRejection::GenerationStableAllocation,
        ))
    })?;
    owned.extend(values);
    Ok(owned)
}
fn stable_values<T, const N: usize>(owned: Vec<T>) -> Result<Box<[T; N]>> {
    if owned.len() != N {
        return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
            crate::KeyAdmissionRejection::GenerationFixedAllocationLength,
        )));
    }
    Ok(owned
        .into_boxed_slice()
        .try_into()
        .unwrap_or_else(|_| unreachable!("generation fixed allocation length")))
}
pub(super) struct Generation {
    templates: Templates,
    mechanism: Box<[CK_MECHANISM; 1]>,
    kind: CK_MECHANISM_TYPE,
    cleanup_private: bool,
    prepared: managed::PreparedCreation,
    creation: Option<managed::CreationTicket>,
    _ownership: GenerationOwnership,
    storage: StorageUse,
    pub(super) created: bool,
    effect_possible: bool,
    pub(super) cleanup_attempted: bool,
    diagnostics: GenerationDiagnostics,
    _credit: Credit,
}

/// Fixed error leaves are admitted with the native creation owner. Their
/// metadata credit remains in Generation after a leaf moves into a returned
/// error; the public starter/poll root retains that operation through projection.
struct GenerationDiagnostics {
    // Input corruption and registration refusal are exclusive terminal paths.
    publication_failure: Option<crate::error::CompletionStorage>,
    completion_uncertain: Option<crate::error::CompletionStorage>,
    objects_remaining: Option<crate::error::CompletionStorage>,
    cleanup: GenerationCleanup,
}

enum GenerationCleanup {
    Prepared(crate::error::CleanupDiagnostic),
    Active(crate::error::CleanupDiagnostic),
    Consumed,
}

impl GenerationDiagnostics {
    fn allocation_bytes() -> usize {
        3 * crate::error::CompletionStorage::allocation_bytes()
            + crate::error::CleanupDiagnostic::allocation_bytes()
    }

    fn allocate() -> Result<Self> {
        Ok(Self {
            publication_failure: Some(crate::error::CompletionStorage::allocate()?),
            completion_uncertain: Some(crate::error::CompletionStorage::allocate()?),
            objects_remaining: Some(crate::error::CompletionStorage::allocate()?),
            cleanup: GenerationCleanup::Prepared(
                crate::error::CleanupDiagnostic::prepare_sequence()?,
            ),
        })
    }

    fn prepare_cleanup(&mut self, cause: Error) -> Result<crate::error::CleanupDiagnostic> {
        // Preserve Error::prepare_cleanup's refusal to flatten an earlier
        // compound cleanup failure or issue another cleanup for that cause.
        if matches!(cause.without_object_marker(), Error::CleanupFailed { .. }) {
            return Err(cause);
        }
        let GenerationCleanup::Prepared(mut diagnostic) =
            std::mem::replace(&mut self.cleanup, GenerationCleanup::Consumed)
        else {
            unreachable!("one cleanup attempt per generation")
        };
        diagnostic.replace_operation(cause);
        Ok(diagnostic)
    }

    fn finish_cleanup(&mut self, failure: Option<Error>) -> Error {
        let GenerationCleanup::Active(diagnostic) =
            std::mem::replace(&mut self.cleanup, GenerationCleanup::Consumed)
        else {
            unreachable!("installed generation cleanup diagnostic")
        };
        diagnostic.finish(failure)
    }
}
// A Generation exists only after destination possession. Field order releases
// the writer exclusions before the durable reservation they protect.
struct GenerationOwnership {
    _objects: Vec<crate::registry::WritePermit>,
    _reservation: managed::DurableReservation,
}

// SAFETY: mechanism, outputs, templates and descriptors have stable owned
// storage. The installed operation retains them across all native completions.
unsafe impl Send for Generation {}
impl Generation {
    fn call(&self) -> MutationCall {
        if self.templates.pair() {
            MutationCall::GeneratePair
        } else {
            MutationCall::GenerateKey
        }
    }
    pub(super) fn function(&self) -> &'static str {
        self.call().function()
    }
    pub(super) fn category(&self) -> CK_FLAGS {
        if self.templates.pair() {
            CKF_GENERATE_KEY_PAIR
        } else {
            CKF_GENERATE
        }
    }
    pub(super) fn handles(&self) -> &[CK_OBJECT_HANDLE] {
        self.templates.outputs()
    }
    pub(super) fn private_handle(&self) -> CK_OBJECT_HANDLE {
        self.templates
            .outputs()
            .get(1)
            .copied()
            .unwrap_or(CK_INVALID_HANDLE)
    }
    fn cleanup_handle(&self) -> CK_OBJECT_HANDLE {
        if self.cleanup_private {
            self.templates
                .outputs()
                .get(1)
                .copied()
                .unwrap_or(CK_INVALID_HANDLE)
        } else {
            self.templates.outputs()[0]
        }
    }
    pub(super) fn dispatch(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        stage: Stage,
    ) -> Result<CK_RV> {
        if stage == Stage::Generate {
            if self.storage != StorageUse::Prepared {
                return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::DuplicateNativeGeneration,
                )));
            }
            let function = self.function();
            match &mut self.templates {
                Templates::Pair {
                    public,
                    private,
                    public_count,
                    private_count,
                    outputs,
                } => {
                    let generate = crate::native::functions::resolve(
                        s.native.table.C_GenerateKeyPair,
                        "C_GenerateKeyPair",
                    )?;
                    let creation = self.creation.insert(self.prepared.begin()?);
                    creation.prepare_dispatch(s, || s.native.record(function))?;
                    self.storage = StorageUse::InUse;
                    self.effect_possible = true;
                    let [public_output, private_output] = &mut **outputs;
                    // SAFETY: templates and scalar outputs belong to this stable
                    // owner; counts are prepared before creation is armed.
                    Ok(unsafe {
                        generate(
                            entry.handle,
                            &mut self.mechanism[0],
                            public.as_mut_ptr(),
                            *public_count,
                            private.as_mut_ptr(),
                            *private_count,
                            public_output,
                            private_output,
                        )
                    })
                }
                Templates::Single {
                    template,
                    count,
                    output,
                } => {
                    let generate = crate::native::functions::resolve(
                        s.native.table.C_GenerateKey,
                        "C_GenerateKey",
                    )?;
                    let creation = self.creation.insert(self.prepared.begin()?);
                    creation.prepare_dispatch(s, || s.native.record(function))?;
                    self.storage = StorageUse::InUse;
                    self.effect_possible = true;
                    // SAFETY: the selected template and output remain owned
                    // through the same creation receipt and possible pending call.
                    Ok(unsafe {
                        generate(
                            entry.handle,
                            &mut self.mechanism[0],
                            template.as_mut_ptr(),
                            *count,
                            &mut output[0],
                        )
                    })
                }
            }
        } else if stage == Stage::Destroy {
            self.creation
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::CreationTicketAbsentForCleanup,
                )))?
                .check_cleanup_epoch()?;
            let destroy = s.native.table.C_DestroyObject.ok_or(Error::Unsupported(
                crate::UnsupportedReason::NativeFunction {
                    function: "C_DestroyObject",
                },
            ))?;
            s.native.record("C_DestroyObject")?;
            // SAFETY: only this successful creation's current cleanup handle.
            Ok(unsafe { destroy(entry.handle, self.cleanup_handle()) })
        } else {
            Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::CreationDispatchStage,
            )))
        }
    }
    pub(super) fn accept_async(&mut self, result: &CK_ASYNC_DATA) -> Result<()> {
        let (object, additional) =
            super::super::asynchronous::completed_objects(result, self.templates.pair())?;
        // The asynchronous outputs are CK_ASYNC_DATA handles, not a promise
        // that the scalar locations of the original Generate call were written.
        self.templates.accept_outputs(object, additional);
        Ok(())
    }
    pub(super) fn accept_joined(
        &mut self,
        result: super::super::asynchronous::JoinedResult,
    ) -> Result<CK_RV> {
        let (rv, objects) = result.project_objects(self.function(), self.templates.pair())?;
        if let Some((object, additional)) = objects {
            self.templates.accept_outputs(object, additional);
        }
        Ok(rv)
    }
    pub(super) fn generated(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        rv: CK_RV,
    ) -> Result<CK_OBJECT_HANDLE> {
        // Admission's shared return barrier has already verified the complete
        // input graph, for direct, AsyncComplete and rejoin returns alike. This
        // decision concerns object effects, not whether memory could be read.
        self.storage = if rv == CKR_OK || self.call().non_creation(rv) {
            StorageUse::Completed
        } else {
            StorageUse::Uncertain
        };
        mutation_result(s, entry, self.call(), rv)?;
        self.creation
            .as_ref()
            .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::CreationTicketAbsent,
            )))?
            .handles_prepared(s, self.templates.outputs(), |cause| {
                self.diagnostics
                    .publication_failure
                    .take()
                    .expect("one generation publication failure")
                    .mark_remaining(cause)
            })?;
        self.created = true;
        Ok(self.templates.outputs()[0])
    }
    fn inputs_unchanged(&self) -> bool {
        self.mechanism[0].mechanism == self.kind
            && self.mechanism[0].pParameter.is_null()
            && self.mechanism[0].ulParameterLen == 0
            && self.templates.unchanged()
    }
    /// A direct return or completed control returns this graph independently of whether the
    /// target created an object. Inspect only immutable inputs here; refusal
    /// handles are never consumed and no non-creation proof is manufactured.
    pub(super) fn inspect_returned_inputs(&mut self) -> Result<()> {
        if self.inputs_unchanged() {
            return Ok(());
        }
        self.storage = StorageUse::Uncertain;
        Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
            crate::KeyAdmissionRejection::GenerationInputChanged,
        )))
    }
    /// An invalid asynchronous completion ends this admission without releasing
    /// its native operands. One leaf covers either Join or ordinary completion;
    /// the caller moves to Failed before publishing this uncertainty marker.
    pub(super) fn completion_failure(&mut self, cause: Error) -> Error {
        if self.effect_possible {
            self.diagnostics
                .completion_uncertain
                .take()
                .expect("one terminal generation completion refusal")
                .mark_remaining(cause)
        } else {
            cause
        }
    }
    pub(super) fn storage_retained(&self) -> bool {
        matches!(self.storage, StorageUse::InUse | StorageUse::Uncertain)
    }
    /// Creation may outlive native operand access. Keep its effects visible
    /// until a non-creation return or successful destruction proves otherwise.
    pub(super) fn effect_possible(&self) -> bool {
        self.effect_possible
    }
    pub(super) fn refused(&mut self, s: &State, rv: CK_RV) {
        if self.storage != StorageUse::Completed {
            return;
        }
        if self.call().non_creation(rv) {
            self.effect_possible = false;
        }
        if let Some(ticket) = &self.creation {
            ticket.refused(s, self.call(), rv);
        }
    }
    pub(super) fn begin_cleanup(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        cause: Error,
    ) -> std::result::Result<(), Error> {
        self.cleanup_attempted = true;
        let unsafe_session = matches!(
            cause.without_object_marker(),
            Error::Native { code, .. }
                if *code == CKR_SESSION_HANDLE_INVALID as u64
                    || *code == CKR_SESSION_CLOSED as u64
                    || *code == CKR_OPERATION_ACTIVE as u64
        );
        if !self.created
            || s.native.is_uncertain()
            || entry.poisoned.load(Ordering::Acquire)
            || entry.snapshot.check().is_err()
            || unsafe_session
        {
            return Err(if self.effect_possible {
                self.diagnostics
                    .objects_remaining
                    .take()
                    .expect("one generation cleanup refusal")
                    .mark_remaining(cause)
            } else {
                cause
            });
        }
        let cleanup = self.diagnostics.prepare_cleanup(cause)?;
        // Native dispatch checks cleanup availability before creating objects.
        // Keep this defensive check at cleanup too: an absent entry must retain
        // the original failure and possible object, never panic or replay C.
        if s.native.table.C_DestroyObject.is_none() {
            return Err(cleanup.finish(Some(Error::Unsupported(
                crate::UnsupportedReason::NativeFunction {
                    function: "C_DestroyObject",
                },
            ))));
        }
        self.diagnostics.cleanup = GenerationCleanup::Active(cleanup);
        self.cleanup_private = self.templates.pair();
        Ok(())
    }
    // None means the private half was destroyed and the public half still owns
    // its next distinct cleanup call. A native failure never retries a handle.
    pub(super) fn cleaned(&mut self, s: &State, entry: &SessionEntry, rv: CK_RV) -> Option<Error> {
        let result = mutation_result(s, entry, MutationCall::Destroy, rv).and_then(|_| {
            self.creation
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::KeyAdmission(
                    crate::KeyAdmissionRejection::CreationTicketAbsent,
                )))?
                .destroyed(s, self.cleanup_handle())
        });
        if result.is_ok() {
            if self.cleanup_private {
                self.cleanup_private = false;
                return None;
            }
            self.created = false;
            self.effect_possible = false;
        }
        Some(self.diagnostics.finish_cleanup(result.err()))
    }
    pub(super) fn cleanup_dispatch_failed(&mut self, s: &State, cause: Error) -> Error {
        s.native.mark_uncertain();
        self.diagnostics.finish_cleanup(Some(cause))
    }
}
fn mutation_result(_s: &State, entry: &SessionEntry, call: MutationCall, rv: CK_RV) -> Result<()> {
    let scope = call.scope(rv);
    if scope == FailureScope::Session {
        entry.poisoned.store(true, Ordering::Release);
    }
    // Admission's dispatch barrier or JoinedCall already withdrew the native
    // context before validating any descriptor. Preserve this owner's poison
    // flag, without applying token/authentication retirement a second time.
    // A creation refusal neither changes the token's login role nor proves
    // that existing private objects disappeared. Keep its exact native result.
    check(rv, call.function(), !call.definite_object_refusal(rv))
}
impl AdvancedSession {
    /// Generate a native symmetric key with the exact selected attributes.
    /// Poll returns the created object independently of any observation error.
    pub fn generate_symmetric_key(&self, spec: SymmetricKeySpec) -> Result<OperationTicket> {
        self.start_symmetric_generation(spec)
    }
    /// Generate an AES key and read only the explicitly selected observations.
    pub fn generate_aes_key(&self, spec: SymmetricKeySpec) -> Result<OperationTicket> {
        if !matches!(
            spec.algorithm,
            crate::SymmetricAlgorithm::Aes128
                | crate::SymmetricAlgorithm::Aes192
                | crate::SymmetricAlgorithm::Aes256
        ) {
            return Err(Error::Rejected(crate::RejectionReason::KeyAdmission(
                crate::KeyAdmissionRejection::AesKeyRequired,
            )));
        }
        self.start_symmetric_generation(spec)
    }
    fn start_symmetric_generation(&self, spec: SymmetricKeySpec) -> Result<OperationTicket> {
        spec.validate()?;

        self.start_key_admission(
            super::input::Input::symmetric(
                spec,
                super::symmetric_publication::Publication::Ordinary,
            ),
            true,
        )
    }
}
