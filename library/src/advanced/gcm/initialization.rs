// SPDX-License-Identifier: Apache-2.0
//! Stable Init ownership independent of the first submitted AEAD message.
use super::{
    input, storage_sum, AeadMessageOperation, AeadOutcome, AeadStep, CipherKind, InitBinding,
    InitReference, InitializationSeed, MessageKey, MessageRoute, NativeParameters, Outputs,
    PreparedAead, Selection,
};
use crate::advanced::{NativeActivity, Operation, OperationBody, OperationTicket};
use crate::symmetric::memory::{Buffer, Credit, UnboundBuffer};
use crate::{Error, MessageInitLayout, Result, Session};
use fe11_sys::{CK_ASYNC_DATA, CK_MECHANISM};
use std::mem::size_of;

impl InitBinding {
    /// The descriptor is checked against its current message, or its explicit
    /// seed before any message is submitted. Never infer a message from index 0.
    pub(super) fn reference<'a>(
        &'a self,
        frames: &'a [super::Frame],
    ) -> Result<(&'a Selection, usize, Option<&'a Buffer>)> {
        match self {
            Self::Declared(_) => Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::DeclaredInitHasNoStandardSeed,
            ))),
            Self::WithoutParameters => Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadInitHasNoParameters,
            ))),
            Self::Shared {
                prepared_message: InitReference::Message(index),
                ..
            } => {
                let frame = frames.get(*index).ok_or(Error::Rejected(
                    crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::AeadPreparedMessageIndex,
                    ),
                ))?;
                Ok((&frame.origin, frame.expected, frame.expected_tag.as_ref()))
            }
            Self::Shared {
                prepared_message: InitReference::Seed,
                seed,
                ..
            } => {
                let seed =
                    seed.as_ref()
                        .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                            crate::AeadMessagesRejection::AeadInitSeedAbsent,
                        )))?;
                Ok((
                    &seed.origin,
                    seed.declared_length,
                    seed.expected_tag.as_ref(),
                ))
            }
        }
    }
}

/// Borrowed application selection. The declared length feeds CCM's ulDataLen;
/// it does not reserve input bytes or prescribe future submission boundaries.
#[derive(Clone, Copy)]
pub(super) struct Parameters<'a> {
    pub origin: &'a Selection,
    pub declared_length: usize,
    pub expected_tag: Option<&'a [u8]>,
}

struct SeedStorage {
    nonce: UnboundBuffer,
    tag: UnboundBuffer,
    expected_tag: Option<UnboundBuffer>,
}
impl SeedStorage {
    fn allocate(parameters: Parameters<'_>) -> Result<Self> {
        Ok(Self {
            nonce: UnboundBuffer::allocate(parameters.origin.iv().len())?,
            tag: UnboundBuffer::allocate(parameters.origin.tag_bytes()?)?,
            expected_tag: parameters
                .expected_tag
                .map(|bytes| UnboundBuffer::allocate(bytes.len()))
                .transpose()?,
        })
    }
    fn allocated_bytes(&self) -> Result<usize> {
        storage_sum(&[
            self.nonce.allocated(),
            self.tag.allocated(),
            self.expected_tag
                .as_ref()
                .map_or(0, UnboundBuffer::allocated),
        ])
    }
    fn bind(self, parameters: Parameters<'_>, prepaid: &mut Credit) -> Result<InitBinding> {
        let mut nonce = self.nonce.bind(prepaid)?;
        let mut tag = self.tag.bind(prepaid)?;
        nonce.as_mut().copy_from_slice(parameters.origin.iv());
        let expected_tag = self
            .expected_tag
            .map(|storage| -> Result<_> {
                let bytes = parameters.expected_tag.expect("validated Init input tag");
                let mut expected = storage.bind(prepaid)?;
                expected.as_mut().copy_from_slice(bytes);
                tag.as_mut().copy_from_slice(bytes);
                Ok(expected)
            })
            .transpose()?;
        let metadata = prepaid.split(seed_metadata(parameters)?)?;
        let params = Box::new(NativeParameters::new(
            parameters.origin,
            parameters.declared_length,
            nonce.as_mut().as_mut_ptr(),
            tag.as_mut().as_mut_ptr(),
        )?);
        Ok(InitBinding::Shared {
            params,
            nonce,
            tag,
            prepared_message: InitReference::Seed,
            seed: Some(InitializationSeed {
                origin: parameters.origin.clone(),
                declared_length: parameters.declared_length,
                expected_tag,
            }),
            _metadata: metadata,
        })
    }
}

fn owner_bytes(declared: bool) -> Result<usize> {
    storage_sum(&[
        size_of::<AeadMessageOperation>(),
        crate::error::CleanupDiagnostic::allocation_bytes(),
        crate::error::CompletionStorage::allocation_bytes(),
        input::DIAGNOSTIC_BYTES,
        if declared {
            crate::error::CompletionStorage::allocation_bytes()
        } else {
            0
        },
        size_of::<CK_MECHANISM>(),
        size_of::<CK_ASYNC_DATA>(),
    ])
}
fn seed_metadata(parameters: Parameters<'_>) -> Result<usize> {
    storage_sum(&[
        size_of::<NativeParameters>(),
        parameters.origin.retained_bytes(),
    ])
}

pub(super) fn start(
    session: &Session,
    key: MessageKey<'_>,
    kind: CipherKind,
    decrypt: bool,
    route: MessageRoute,
    initial: Option<Parameters<'_>>,
    capture: bool,
) -> Result<OperationTicket> {
    start_inner(session, key, kind, decrypt, route, initial, capture, None)
}

pub(super) fn start_declared(
    session: &Session,
    key: MessageKey<'_>,
    contract: &super::extension::GcmMessageExtension,
    parameters: crate::ExtensionParameters<'_>,
    capture: bool,
) -> Result<OperationTicket> {
    contract.check(session)?;
    start_inner(
        session,
        key,
        CipherKind::Gcm,
        contract.decrypt,
        contract.route,
        None,
        capture,
        Some((contract, &parameters)),
    )
}

fn start_inner(
    session: &Session,
    key: MessageKey<'_>,
    kind: CipherKind,
    decrypt: bool,
    route: MessageRoute,
    initial: Option<Parameters<'_>>,
    capture: bool,
    declared: Option<(
        &super::extension::GcmMessageExtension,
        &crate::ExtensionParameters<'_>,
    )>,
) -> Result<OperationTicket> {
    use crate::mechanism_extension::{GraphStorage, OwnedGraph};
    if let Some(parameters) = initial {
        if kind.stream() || parameters.origin.kind() != kind {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadInitSelectionRepresentation,
            )));
        }
        parameters
            .origin
            .validate(0, parameters.declared_length, decrypt)?;
        if !decrypt && parameters.expected_tag.is_some()
            || parameters
                .expected_tag
                .is_some_and(|tag| parameters.origin.tag_bytes().ok() != Some(tag.len()))
        {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadInitTagRepresentation,
            )));
        }
    }
    let progress = session
        .advanced_preflight(|state| super::check_message_key(state, key, kind, decrypt, route))?;
    let seed_metadata = initial.map(seed_metadata).transpose()?.unwrap_or(0);
    let seed_bytes = initial
        .map(|parameters| {
            storage_sum(&[
                parameters.origin.iv().len(),
                parameters.origin.tag_bytes()?,
                parameters.expected_tag.map_or(0, <[u8]>::len),
            ])
        })
        .transpose()?
        .unwrap_or(0);
    let graph_bytes = declared
        .map(|(_, parameters)| OwnedGraph::allocation_bytes(parameters))
        .transpose()?
        .unwrap_or(0);
    let owner = owner_bytes(declared.is_some())?;
    let known = storage_sum(&[
        owner,
        seed_metadata,
        seed_bytes,
        graph_bytes,
        crate::advanced::preparation::Shell::allocation_bytes(),
        if capture {
            crate::advanced::validation::Capture::allocation_bytes(1)?
        } else {
            0
        },
    ])?;
    let readers = crate::advanced::keys::KeyReaders::prepare(
        session,
        [Some(match key {
            MessageKey::Aes(key) => &key.managed,
            MessageKey::Native(key) => key,
        })],
    )?;
    let mut total = known;
    let ((prepared, shell, validation), access, mut readers) =
        readers.prepare_with(session, &progress, || loop {
            let mut prepaid =
                crate::advanced::preparation::reserve_new_with_progress(session, total, &progress)?;
            let cleanup_diagnostic = crate::error::CleanupDiagnostic::prepare_sequence()?;
            let return_diagnostic = crate::error::CompletionStorage::allocate()?;
            let completion_diagnostic = declared
                .is_some()
                .then(crate::error::CompletionStorage::allocate)
                .transpose()?;
            let seed = initial.map(SeedStorage::allocate).transpose()?;
            let graph = declared
                .map(|(_, parameters)| GraphStorage::allocate(parameters))
                .transpose()?;
            let report = capture
                .then(|| crate::advanced::validation::CaptureStorage::allocate(1))
                .transpose()?;
            let actual = storage_sum(&[
                owner,
                seed_metadata,
                graph
                    .as_ref()
                    .map(GraphStorage::allocated_bytes)
                    .transpose()?
                    .unwrap_or(0),
                crate::advanced::preparation::Shell::allocation_bytes(),
                seed.as_ref()
                    .map(SeedStorage::allocated_bytes)
                    .transpose()?
                    .unwrap_or(0),
                report
                    .as_ref()
                    .map(crate::advanced::validation::CaptureStorage::allocated_bytes)
                    .transpose()?
                    .unwrap_or(0),
            ])?;
            if actual > total {
                drop(graph);
                drop(seed);
                drop(report);
                drop(cleanup_diagnostic);
                drop(return_diagnostic);
                drop(completion_diagnostic);
                drop(prepaid);
                total = actual;
                continue;
            }
            prepaid.release(total - actual);
            let mut init = match (graph, declared, seed, initial) {
                (Some(graph), Some((contract, _)), None, None) => {
                    InitBinding::Declared(super::extension::DeclaredInit::new(
                        contract.clone(),
                        graph.bind(&mut prepaid)?,
                        completion_diagnostic.expect("declared Init diagnostic prepared"),
                    ))
                }
                (None, None, Some(seed), Some(parameters)) => {
                    seed.bind(parameters, &mut prepaid)?
                }
                (None, None, None, None) => InitBinding::WithoutParameters,
                _ => unreachable!("same Init selection during preparation"),
            };
            let mut mechanism = Box::new(CK_MECHANISM {
                mechanism: kind.mechanism(),
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            });
            if let InitBinding::Shared { params, .. } = &mut init {
                mechanism.pParameter = params.pointer_mut();
                mechanism.ulParameterLen = params.size();
            }
            if let InitBinding::Declared(declared) = &init {
                declared.bind(&mut mechanism);
            }
            // This standard-layout field is ignored by DeclaredGcmMessages and
            // cannot be serialized: declared Init is rejected by capture paths.
            let layout = if initial.is_some() {
                MessageInitLayout::InitWithOwnedMessageParameters
            } else {
                MessageInitLayout::InitWithoutParameters
            };
            let prepared = PreparedAead {
                input: Some(input::Input::new()),
                kind,
                route,
                decrypt,
                outcome: AeadOutcome::Nominal,
                step: AeadStep::Init,
                activity: NativeActivity::Inactive,
                mechanism,
                init,
                frames: Vec::new(),
                outputs: Some(Outputs {
                    entries: Vec::new(),
                    init: layout,
                    _credit: prepaid.split(0)?,
                }),
                restart_at: 0,
                completion: Box::new(crate::native::output::async_data()),
                name: [0; 32],
                cleanup_diagnostic: Some(cleanup_diagnostic),
                return_diagnostic: Some(return_diagnostic),
                _metadata: prepaid.split(owner)?,
            };
            let validation = report.map(|report| report.bind(&mut prepaid)).transpose()?;
            let shell = crate::advanced::preparation::Shell::from_prepaid(&mut prepaid)?;
            return Ok((prepared, shell, validation));
        })?;
    let key = if let Some((contract, _)) = declared {
        contract.check(session)?;
        super::check_message_key(&access, key, kind, decrypt, route)?;
        let MessageKey::Native(key) = key else {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::DeclaredGcmNativeKeyReference,
            )));
        };
        crate::advanced::keys::KeyLease::for_native_cipher(
            session,
            key,
            contract.mechanism,
            &mut readers,
        )?
    } else {
        super::message_key(session, &access, key, kind, decrypt, route, &mut readers)?
    };
    let (lease, cancel) = shell.bind(&access.lease_admission()?)?;
    let (id, _) = access.operations.install(
        &session.entry,
        Operation::new(
            OperationBody::AeadMessages(prepared.bind(key)),
            lease,
            cancel,
        )
        .with_validation(validation),
    )?;
    // Return the sole ticket before any Init call. An error on the first poll
    // therefore cannot strand a native operation without its caller's handle.
    Ok(OperationTicket {
        owner: session.inner.clone(),
        uid: session.uid,
        id,
        validation_report: None,
        state_provenance: None,
    })
}

use super::*;

impl InitBinding {
    pub(super) fn layout(&self) -> Result<MessageInitLayout> {
        match self {
            Self::WithoutParameters => Ok(MessageInitLayout::InitWithoutParameters),
            Self::Shared { .. } => Ok(MessageInitLayout::InitWithOwnedMessageParameters),
            Self::Declared(_) => Err(Error::Unsupported(crate::UnsupportedReason::AeadMessages(
                crate::AeadMessagesUnsupported::DeclaredGcmMessageStateCapture,
            ))),
        }
    }
}

impl PreparedAead {
    pub(in crate::advanced) fn bind(self, key: KeyLease) -> AeadMessageOperation {
        AeadMessageOperation {
            key,
            observer: ticket::Observer::Ticket,
            input: self.input,
            retired_fragment: None,
            retired_output: None,
            retired_queued: queued_input::Retired::default(),
            kind: self.kind,
            route: self.route,
            decrypt: self.decrypt,
            outcome: self.outcome,
            step: self.step,
            activity: self.activity,
            mechanism: self.mechanism,
            init: self.init,
            frames: self.frames,
            outputs: self.outputs,
            restart_at: self.restart_at,
            completion: self.completion,
            name: self.name,
            cleanup_diagnostic: self.cleanup_diagnostic,
            return_diagnostic: self.return_diagnostic,
            _metadata: self._metadata,
        }
    }
}

impl PreparedAead {
    pub(super) fn restore_row(&mut self, index: usize, m: &record::Message<'_>) -> Result<()> {
        let frame = self.frames.get_mut(index).ok_or(Error::Rejected(
            crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadSnapshotShapeChanged,
            ),
        ))?;
        let out = self
            .outputs
            .as_mut()
            .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadMessageOutputsAbsent,
            )))?
            .entries
            .get_mut(index)
            .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadSnapshotShapeChanged,
            )))?;
        reconstruction::output(
            &mut out.bytes,
            m.result,
            m.state == record::MessageState::Finished,
        )?;
        frame.used = m.produced;
        let tag =
            m.tag_or_signature
                .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::ReconstructionTag,
                )))?;
        if tag.len() != out.tag.capacity() {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::ReconstructionTagWidth,
            )));
        }
        out.tag.as_mut().copy_from_slice(tag);
        if let Some(nonce) = m.params.nonce {
            if nonce.len() != out.nonce.capacity() {
                return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::ReconstructionNonceWidth,
                )));
            }
            out.nonce.as_mut().copy_from_slice(nonce);
            if m.origin == record::NonceOrigin::Backend && m.state != record::MessageState::Planned
            {
                observe_generated_nonce(&mut frame.observed_nonce, nonce)?;
            }
        }
        Ok(())
    }

    pub(super) fn finish_record(
        mut self,
        d: record::Descriptor,
        pending: bool,
        next: usize,
        next_fragment: Option<usize>,
    ) -> Result<Self> {
        let body = &mut self;
        body.restart_at = d.carried_messages;
        body.activity = if pending {
            NativeActivity::Pending
        } else {
            NativeActivity::Active
        };
        body.step = match d.phase.name() {
            "C_MessageEncryptInit" | "C_MessageDecryptInit" => AeadStep::Init,
            "C_EncryptMessage" | "C_DecryptMessage" => AeadStep::Single(next),
            "C_EncryptMessageBegin" | "C_DecryptMessageBegin" => AeadStep::Begin(next),
            "C_EncryptMessageNext" | "C_DecryptMessageNext" => AeadStep::Next(
                next,
                next_fragment.ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::ReconstructionGcmPhase,
                )))?,
            ),
            "C_MessageEncryptFinal" | "C_MessageDecryptFinal" => AeadStep::Finish,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::ReconstructionGcmPhase,
                )))
            }
        };
        if let InitBinding::Shared {
            params,
            nonce,
            tag,
            prepared_message,
            ..
        } = &mut body.init
        {
            let index = if matches!(body.step, AeadStep::Next(_, _) | AeadStep::Single(_)) {
                Some(next)
            } else if body.step == AeadStep::Finish {
                body.frames.len().checked_sub(1)
            } else {
                None
            };
            if let Some(index) = index {
                params.set_data_length(body.frames[index].expected)?;
                *prepared_message = InitReference::Message(index);
                let output = &body.outputs.as_ref().unwrap().entries[index];
                nonce.as_mut().copy_from_slice(output.nonce.as_slice());
                tag.as_mut().copy_from_slice(output.tag.as_slice());
            }
        }
        if body.step == AeadStep::Init && body.restart_at < body.frames.len() {
            prepare_message_storage(
                body.kind,
                &body.mechanism,
                &mut body.init,
                &body.frames,
                body.restart_at,
            )?;
        }
        Ok(self)
    }

    pub(in crate::advanced) fn into_fresh(mut self) -> Self {
        // This owner will issue a new Init; no native activity has started.
        self.activity = NativeActivity::Inactive;
        self
    }
}

impl crate::symmetric::memory::RetainedStorage for InitializationSeed {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        self.expected_tag.retain_credits(retained)?;
        Ok(())
    }
}

impl crate::symmetric::memory::RetainedStorage for InitBinding {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        match self {
            Self::WithoutParameters => Ok(()),
            Self::Declared(frame) => frame.retain_credits(retained),
            Self::Shared {
                nonce,
                tag,
                seed,
                _metadata,
                ..
            } => {
                nonce.retain_credits(retained)?;
                tag.retain_credits(retained)?;
                seed.retain_credits(retained)?;
                _metadata.retain_credits(retained)
            }
        }
    }
}
