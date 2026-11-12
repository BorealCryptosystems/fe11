// SPDX-License-Identifier: Apache-2.0
//! Owned native state IO. Typed continuation/key authorization is a separate layer.

use super::{asynchronous, spend, AdvancedSessionMode};

use crate::{
    bounds,
    error::check,
    module::{SessionEntry, State},
    symmetric::memory::{Buffer, Credit},
    Error, Result,
};
use fe11_sys::{
    CKF_RW_SESSION, CKR_OK, CKR_PENDING, CKS_RO_PUBLIC_SESSION, CKS_RO_USER_FUNCTIONS,
    CKS_RW_PUBLIC_SESSION, CKS_RW_SO_FUNCTIONS, CKS_RW_USER_FUNCTIONS, CK_ASYNC_DATA,
    CK_OBJECT_HANDLE, CK_RV, CK_SESSION_INFO, CK_SLOT_ID, CK_STATE, CK_ULONG,
    CK_UNAVAILABLE_INFORMATION,
};
use std::sync::atomic::Ordering;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Info,
    Size,
    Sized { length: usize },
    Bytes,
    Restore,
    Done,
    Failed,
}
#[derive(Clone, Copy)]
enum Direction {
    Inspect,
    Capture {
        maximum: usize,
    },
    Restore {
        expected: CK_STATE,
        encryption: CK_OBJECT_HANDLE,
        authentication: CK_OBJECT_HANDLE,
    },
}
// Phase is a read-only dispatch view. Only Flow below owns progression and
// buffers; an inspection can never own a restore input or a capture output.
enum InspectionPhase {
    Info,
    Done,
    Failed,
}
enum RestorePhase {
    Info,
    Restore,
    Done,
    Failed,
}
enum RestoreInput {
    Prepared,
    Attached(Buffer),
    Consumed,
}
enum CaptureOutput {
    Available(Buffer),
    Consumed,
}
enum CapturePhase {
    Info,
    Size,
    Sized { length: usize },
    Bytes(Buffer),
    Done(CaptureOutput),
    Failed { retained: Option<Buffer> },
}
enum Flow {
    Inspect(InspectionPhase),
    Capture {
        maximum: usize,
        phase: CapturePhase,
        captured: bool,
    },
    Restore {
        expected: CK_STATE,
        encryption: CK_OBJECT_HANDLE,
        authentication: CK_OBJECT_HANDLE,
        phase: RestorePhase,
        input: RestoreInput,
    },
}
impl Flow {
    fn direction(&self) -> Direction {
        match self {
            Self::Inspect(_) => Direction::Inspect,
            Self::Capture { maximum, .. } => Direction::Capture { maximum: *maximum },
            Self::Restore {
                expected,
                encryption,
                authentication,
                ..
            } => Direction::Restore {
                expected: *expected,
                encryption: *encryption,
                authentication: *authentication,
            },
        }
    }
    fn phase(&self) -> Phase {
        match self {
            Self::Inspect(InspectionPhase::Info)
            | Self::Capture {
                phase: CapturePhase::Info,
                ..
            }
            | Self::Restore {
                phase: RestorePhase::Info,
                ..
            } => Phase::Info,
            Self::Capture {
                phase: CapturePhase::Size,
                ..
            } => Phase::Size,
            Self::Capture {
                phase: CapturePhase::Sized { length },
                ..
            } => Phase::Sized { length: *length },
            Self::Capture {
                phase: CapturePhase::Bytes(_),
                ..
            } => Phase::Bytes,
            Self::Restore {
                phase: RestorePhase::Restore,
                ..
            } => Phase::Restore,
            Self::Inspect(InspectionPhase::Done)
            | Self::Capture {
                phase: CapturePhase::Done(_),
                ..
            }
            | Self::Restore {
                phase: RestorePhase::Done,
                ..
            } => Phase::Done,
            Self::Inspect(InspectionPhase::Failed)
            | Self::Capture {
                phase: CapturePhase::Failed { .. },
                ..
            }
            | Self::Restore {
                phase: RestorePhase::Failed,
                ..
            } => Phase::Failed,
        }
    }
    fn bytes(&self) -> Option<&Buffer> {
        match self {
            Self::Capture {
                phase:
                    CapturePhase::Bytes(bytes)
                    | CapturePhase::Done(CaptureOutput::Available(bytes))
                    | CapturePhase::Failed {
                        retained: Some(bytes),
                    },
                ..
            }
            | Self::Restore {
                input: RestoreInput::Attached(bytes),
                ..
            } => Some(bytes),
            _ => None,
        }
    }
    fn bytes_mut(&mut self) -> Option<&mut Buffer> {
        match self {
            Self::Capture {
                phase:
                    CapturePhase::Bytes(bytes)
                    | CapturePhase::Done(CaptureOutput::Available(bytes))
                    | CapturePhase::Failed {
                        retained: Some(bytes),
                    },
                ..
            }
            | Self::Restore {
                input: RestoreInput::Attached(bytes),
                ..
            } => Some(bytes),
            _ => None,
        }
    }
    fn take_bytes(&mut self) -> Option<Buffer> {
        match self {
            Self::Capture {
                phase: CapturePhase::Done(output),
                ..
            } => match std::mem::replace(output, CaptureOutput::Consumed) {
                CaptureOutput::Available(bytes) => Some(bytes),
                CaptureOutput::Consumed => None,
            },
            Self::Restore { input, .. } => match std::mem::replace(input, RestoreInput::Consumed) {
                RestoreInput::Attached(bytes) => Some(bytes),
                _ => None,
            },
            _ => None,
        }
    }
    // No allocation or native call. Validate the requested family/buffer
    // relation before moving an owner, including failure paths with retention.
    fn transition(&mut self, next: Phase) -> Result<()> {
        match self {
            Self::Inspect(phase) => {
                *phase = match next {
                    Phase::Info => InspectionPhase::Info,
                    Phase::Done => InspectionPhase::Done,
                    Phase::Failed => InspectionPhase::Failed,
                    _ => {
                        return Err(Error::Rejected(crate::RejectionReason::OperationState(
                            crate::OperationStateRejection::StateIoNotActive,
                        )))
                    }
                };
            }
            Self::Restore { phase, .. } => {
                *phase = match next {
                    Phase::Info => RestorePhase::Info,
                    Phase::Restore => RestorePhase::Restore,
                    Phase::Done => RestorePhase::Done,
                    Phase::Failed => RestorePhase::Failed,
                    _ => {
                        return Err(Error::Rejected(crate::RejectionReason::OperationState(
                            crate::OperationStateRejection::StateIoNotActive,
                        )))
                    }
                };
            }
            Self::Capture { phase, .. } => {
                let owns_buffer = matches!(
                    phase,
                    CapturePhase::Bytes(_)
                        | CapturePhase::Done(CaptureOutput::Available(_))
                        | CapturePhase::Failed { retained: Some(_) }
                );
                match next {
                    Phase::Bytes | Phase::Done if !owns_buffer => {
                        return Err(Error::Rejected(crate::RejectionReason::OperationState(
                            crate::OperationStateRejection::StateOutputAbsent,
                        )))
                    }
                    Phase::Info | Phase::Size | Phase::Sized { .. } if owns_buffer => {
                        return Err(Error::Rejected(crate::RejectionReason::OperationState(
                            crate::OperationStateRejection::StateIoNotActive,
                        )))
                    }
                    Phase::Restore => {
                        return Err(Error::Rejected(crate::RejectionReason::OperationState(
                            crate::OperationStateRejection::StateIoNotActive,
                        )))
                    }
                    _ => {}
                }
                let old = std::mem::replace(phase, CapturePhase::Info);
                let bytes = match old {
                    CapturePhase::Bytes(bytes)
                    | CapturePhase::Done(CaptureOutput::Available(bytes)) => Some(bytes),
                    CapturePhase::Failed { retained } => retained,
                    _ => None,
                };
                *phase = match next {
                    Phase::Info => CapturePhase::Info,
                    Phase::Size => CapturePhase::Size,
                    Phase::Sized { length } => CapturePhase::Sized { length },
                    Phase::Bytes => {
                        CapturePhase::Bytes(bytes.expect("buffer checked before transition"))
                    }
                    Phase::Done => CapturePhase::Done(CaptureOutput::Available(
                        bytes.expect("buffer checked before transition"),
                    )),
                    Phase::Failed => CapturePhase::Failed { retained: bytes },
                    Phase::Restore => unreachable!("capture cannot restore"),
                };
            }
        }
        Ok(())
    }
}

pub(super) struct StateIo {
    flow: Flow,
    // Independent native retention: a rejected projection can be Failed while
    // native output is still pending. Only completion/close releases that fact.
    pending: bool,
    info: Box<CK_SESSION_INFO>,
    length: Box<CK_ULONG>,
    completion: Box<CK_ASYNC_DATA>,
    name: [u8; 32],
    source_info_slot: Option<CK_SLOT_ID>,
    return_diagnostic: Option<crate::error::CompletionStorage>,
    _credit: Credit,
}
// SAFETY: native pointers refer only to stable owned boxes/Buffer allocations.
// This frame must be installed in Operation before dispatch and kept until
// completion or successful CloseSession. No state bytes are inspected pending.
unsafe impl Send for StateIo {}
// A transfer may inspect a session while a different StateIo owns the user's
// capture/restore. This type cannot contain such a capture/restore direction.
pub(super) struct Inspection(StateIo);
impl Inspection {
    pub(super) fn new_prepaid(prepaid: &mut Credit) -> Result<Self> {
        Ok(Self(StateIo::new_prepaid(
            prepaid,
            Direction::Inspect,
            None,
        )?))
    }

    pub(super) fn pending(&self) -> bool {
        self.0.pending()
    }
    pub(super) fn complete(&self) -> bool {
        self.0.complete()
    }
    pub(super) fn inspected_state(&self) -> Result<CK_STATE> {
        self.0.inspected_state()
    }
    pub(super) fn drive(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        observe: bool,
        remaining: &mut usize,
    ) -> Result<()> {
        self.0.drive(s, entry, observe, remaining)
    }
}
impl StateIo {
    pub(super) fn allocation_bytes() -> usize {
        std::mem::size_of::<Self>()
            + std::mem::size_of::<CK_SESSION_INFO>()
            + std::mem::size_of::<CK_ULONG>()
            + std::mem::size_of::<CK_ASYNC_DATA>()
            + crate::error::CompletionStorage::allocation_bytes()
    }
    fn new_prepaid(
        prepaid: &mut Credit,
        direction: Direction,
        bytes: Option<Buffer>,
    ) -> Result<Self> {
        let credit = prepaid.split(Self::allocation_bytes())?;
        let length = bytes
            .as_ref()
            .map_or(Ok(0), |b| bounds::ck_length(b.as_slice().len()))?;
        let flow = match (direction, bytes) {
            (Direction::Inspect, None) => Flow::Inspect(InspectionPhase::Info),
            (Direction::Capture { maximum }, bytes) => Flow::Capture {
                maximum,
                phase: match bytes {
                    Some(bytes) => CapturePhase::Bytes(bytes),
                    None => CapturePhase::Info,
                },
                captured: false,
            },
            (
                Direction::Restore {
                    expected,
                    encryption,
                    authentication,
                },
                bytes,
            ) => Flow::Restore {
                expected,
                encryption,
                authentication,
                phase: RestorePhase::Info,
                input: match bytes {
                    Some(bytes) => RestoreInput::Attached(bytes),
                    None => RestoreInput::Prepared,
                },
            },
            (Direction::Inspect, Some(_)) => {
                return Err(Error::Rejected(crate::RejectionReason::OperationState(
                    crate::OperationStateRejection::StateIoNotActive,
                )))
            }
        };
        Ok(Self {
            flow,
            pending: false,
            info: Box::new(CK_SESSION_INFO {
                slotID: 0,
                state: CK_UNAVAILABLE_INFORMATION,
                flags: 0,
                ulDeviceError: 0,
            }),
            length: Box::new(length),
            completion: Box::new(crate::native::output::async_data()),
            name: [0; 32],
            source_info_slot: None,
            return_diagnostic: Some(crate::error::CompletionStorage::allocate()?),
            _credit: credit,
        })
    }

    pub(super) fn inspected_state(&self) -> Result<CK_STATE> {
        if !self.complete() || !matches!(self.flow.direction(), Direction::Inspect) {
            return Err(Error::Rejected(crate::RejectionReason::OperationState(
                crate::OperationStateRejection::SessionInspectionIncomplete,
            )));
        }
        Ok(self.info.state)
    }

    pub(super) fn validate_capture_maximum(maximum: usize) -> Result<()> {
        if maximum == 0 || maximum > isize::MAX as usize {
            return Err(Error::Rejected(crate::RejectionReason::OperationState(
                crate::OperationStateRejection::OperationStateCeiling,
            )));
        }
        bounds::ck_length(maximum)?;
        Ok(())
    }
    pub(super) fn capture_prepaid(prepaid: &mut Credit, maximum: usize) -> Result<Self> {
        Self::validate_capture_maximum(maximum)?;
        Self::new_prepaid(prepaid, Direction::Capture { maximum }, None)
    }

    /// Prepare stable storage without binding any destination handle. The caller
    /// supplies already admitted aggregate credit before acquiring native access.
    pub(super) fn prepare_restore_prepaid(
        prepaid: &mut Credit,
        length: usize,
        expected: CK_STATE,
    ) -> Result<Self> {
        if !session_state(expected) {
            return Err(Error::Rejected(crate::RejectionReason::OperationState(
                crate::OperationStateRejection::OperationStateSession,
            )));
        }
        let length = bounds::ck_length(length)?;
        let mut result = Self::new_prepaid(
            prepaid,
            Direction::Restore {
                expected,
                encryption: fe11_sys::CK_INVALID_HANDLE,
                authentication: fe11_sys::CK_INVALID_HANDLE,
            },
            None,
        )?;
        *result.length = length;
        Ok(result)
    }
    pub(super) fn bind_restore_keys(
        &mut self,
        encryption_key: CK_OBJECT_HANDLE,
        authentication_key: CK_OBJECT_HANDLE,
    ) -> Result<()> {
        let Flow::Restore {
            encryption,
            authentication,
            phase: RestorePhase::Info,
            input: RestoreInput::Prepared,
            ..
        } = &mut self.flow
        else {
            return Err(Error::Rejected(crate::RejectionReason::OperationState(
                crate::OperationStateRejection::StateIoNotActive,
            )));
        };
        *encryption = encryption_key;
        *authentication = authentication_key;
        Ok(())
    }
    pub(super) fn attach_restore(&mut self, bytes: Buffer) {
        let Flow::Restore { input, .. } = &mut self.flow else {
            unreachable!("prepare_restore creates a restoration owner")
        };
        assert!(
            matches!(input, RestoreInput::Prepared),
            "restore input attached exactly once"
        );
        *input = RestoreInput::Attached(bytes);
    }
    pub(super) fn restore_input_length(&self) -> Result<usize> {
        if !matches!(self.flow.direction(), Direction::Restore { .. })
            || !matches!(self.flow.phase(), Phase::Info | Phase::Restore)
        {
            return Err(Error::Rejected(crate::RejectionReason::OperationState(
                crate::OperationStateRejection::RestorationTransferPhase,
            )));
        }
        // This length is passed by value, never as a native output pointer.
        usize::try_from(*self.length).map_err(|_| {
            Error::Rejected(crate::RejectionReason::OperationState(
                crate::OperationStateRejection::RestorationInputLength,
            ))
        })
    }
    pub(super) fn restore_input(&self) -> Result<&[u8]> {
        if self.pending {
            return Err(Error::Rejected(crate::RejectionReason::OperationState(
                crate::OperationStateRejection::RestorationInputStillNativeOwned,
            )));
        }
        let length = self.restore_input_length()?;
        let bytes = self
            .flow
            .bytes()
            .ok_or(Error::Rejected(crate::RejectionReason::OperationState(
                crate::OperationStateRejection::RestorationInputAbsent,
            )))?
            .as_slice();
        if bytes.len() != length {
            return Err(Error::Rejected(crate::RejectionReason::OperationState(
                crate::OperationStateRejection::RestorationInputLength,
            )));
        }
        Ok(bytes)
    }
    pub(super) fn restore_source_slot(&self, slot: CK_SLOT_ID) -> CK_SLOT_ID {
        self.source_info_slot.unwrap_or(slot)
    }
    /// Apply transfer phase after stable input and exact destination keys have
    /// been bound. No C has seen this new owner; pending denotes the source call.
    pub(super) fn mark_joined_restore(
        &mut self,
        function: &'static str,
        source_slot: CK_SLOT_ID,
    ) -> Result<()> {
        self.flow.transition(match function {
            "C_GetSessionInfo" => Phase::Info,
            "C_SetOperationState" => Phase::Restore,
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::OperationState(
                    crate::OperationStateRejection::RestorationTransferFunction,
                )))
            }
        })?;
        self.source_info_slot = Some(source_slot);
        self.pending = true;
        self.name[..function.len()].copy_from_slice(function.as_bytes());
        Ok(())
    }
    // Only successful GetID permits the original pending input to be read or released.
    pub(super) fn detached_restore_release(&mut self) {
        self.pending = false;
    }
    pub(super) fn take_refused_restore(&mut self) -> Result<Buffer> {
        if self.pending
            || self.complete()
            || !matches!(self.flow.direction(), Direction::Restore { .. })
        {
            return Err(Error::Rejected(crate::RejectionReason::OperationState(
                crate::OperationStateRejection::RestorationStateNotRecoverable,
            )));
        }
        self.flow
            .take_bytes()
            .ok_or(Error::Rejected(crate::RejectionReason::OperationState(
                crate::OperationStateRejection::RestorationStateAbsent,
            )))
    }
    // Capture admission depends on phase, independently of whether the module yields.
    // It reads only local progression; no pending native output is inspected.
    pub(super) fn check_detachment(&self) -> Result<()> {
        if matches!(self.flow.direction(), Direction::Capture { .. })
            && matches!(
                self.flow.phase(),
                Phase::Info | Phase::Size | Phase::Sized { .. }
            )
        {
            return Err(Error::Rejected(crate::RejectionReason::OperationState(
                crate::OperationStateRejection::PreparatoryStateCaptureDetachmentDeferred,
            )));
        }
        Ok(())
    }
    pub(super) fn capture_metadata(&self) -> Result<(CK_STATE, usize)> {
        if !matches!(self.flow.direction(), Direction::Capture { .. })
            || self.flow.phase() != Phase::Bytes
            || self.captured()
        {
            return Err(Error::Rejected(crate::RejectionReason::OperationState(
                crate::OperationStateRejection::FinalStateCaptureRequired,
            )));
        }
        // info was completed before the size query; length/output may currently
        // belong to the native call. Read allocation capacity only, never them.
        if !session_state(self.info.state) {
            return Err(Error::Rejected(crate::RejectionReason::OperationState(
                crate::OperationStateRejection::CaptureSessionState,
            )));
        }
        Ok((
            self.info.state,
            self.flow
                .bytes()
                .ok_or(Error::Rejected(crate::RejectionReason::OperationState(
                    crate::OperationStateRejection::StateOutputAbsent,
                )))?
                .capacity(),
        ))
    }

    pub(super) fn joined_capture_prepaid(
        prepaid: &mut Credit,
        state: CK_STATE,
        bytes: Buffer,
    ) -> Result<Self> {
        if !session_state(state) {
            return Err(Error::Rejected(crate::RejectionReason::OperationState(
                crate::OperationStateRejection::CaptureSessionState,
            )));
        }
        bounds::ck_length(bytes.capacity())?;
        let io = Self::new_prepaid(
            prepaid,
            Direction::Capture {
                maximum: bytes.capacity(),
            },
            Some(bytes),
        )?;
        Self::finish_joined_capture(io, state)
    }
    fn finish_joined_capture(mut io: Self, state: CK_STATE) -> Result<Self> {
        // The capture constructor already owns the joined output in Bytes.
        io.info.state = state;
        io.pending = true;
        let name = b"C_GetOperationState";
        io.name[..name.len()].copy_from_slice(name);
        Ok(io)
    }
    // Called only after GetID OK, which releases the original native buffers.
    pub(super) fn detached_capture_release(&mut self) {
        self.pending = false;
    }
    pub(super) fn buffer_needed(&self) -> Option<usize> {
        match self.flow.phase() {
            Phase::Sized { length } => Some(length),
            _ => None,
        }
    }
    pub(super) fn attach_capture_buffer(&mut self, bytes: Buffer) -> Result<()> {
        let Some(length) = self.buffer_needed() else {
            return Err(Error::Rejected(crate::RejectionReason::OperationState(
                crate::OperationStateRejection::StateCapturePreparationChanged,
            )));
        };
        if self.pending || bytes.capacity() != length || self.flow.bytes().is_some() {
            return Err(Error::Rejected(crate::RejectionReason::OperationState(
                crate::OperationStateRejection::StateCapturePreparationChanged,
            )));
        }
        let Flow::Capture { phase, .. } = &mut self.flow else {
            unreachable!("only capture has a sized output")
        };
        *phase = CapturePhase::Bytes(bytes);
        Ok(())
    }

    pub(super) fn pending(&self) -> bool {
        self.pending
    }
    pub(super) fn captured(&self) -> bool {
        matches!(self.flow, Flow::Capture { captured: true, .. })
    }
    pub(super) fn complete(&self) -> bool {
        self.flow.phase() == Phase::Done
    }
    pub(super) fn take_capture(&mut self) -> Result<(CK_STATE, Buffer)> {
        if !self.complete() || !matches!(self.flow.direction(), Direction::Capture { .. }) {
            return Err(Error::Rejected(crate::RejectionReason::OperationState(
                crate::OperationStateRejection::StateCaptureIncomplete,
            )));
        }
        Ok((
            self.info.state,
            self.flow.take_bytes().ok_or(Error::Rejected(
                crate::RejectionReason::OperationState(
                    crate::OperationStateRejection::StateAlreadyConsumed,
                ),
            ))?,
        ))
    }
    pub(super) fn function(&self) -> Result<&'static str> {
        match self.flow.phase() {
            Phase::Info => Ok("C_GetSessionInfo"),
            Phase::Size | Phase::Bytes => Ok("C_GetOperationState"),
            Phase::Restore => Ok("C_SetOperationState"),
            _ => Err(Error::Rejected(crate::RejectionReason::OperationState(
                crate::OperationStateRejection::StateIoNotActive,
            ))),
        }
    }
    pub(super) fn joined_capacity(&self) -> Result<Option<usize>> {
        if !self.pending {
            return Err(Error::Rejected(
                crate::RejectionReason::AsynchronousExecution(
                    crate::AsynchronousExecutionRejection::StateControlNotPending,
                ),
            ));
        }
        Ok(match self.flow.phase() {
            Phase::Info => Some(std::mem::size_of::<CK_SESSION_INFO>()),
            Phase::Size | Phase::Restore => None,
            Phase::Bytes => Some(
                self.flow
                    .bytes()
                    .ok_or(Error::Rejected(crate::RejectionReason::OperationState(
                        crate::OperationStateRejection::StateOutputAbsent,
                    )))?
                    .capacity(),
            ),
            _ => {
                return Err(Error::Rejected(crate::RejectionReason::OperationState(
                    crate::OperationStateRejection::StateIoNotActive,
                )))
            }
        })
    }
    pub(super) fn accept_joined(
        &mut self,
        s: &State,
        entry: &SessionEntry,
        result: asynchronous::JoinedResult,
    ) -> Result<()> {
        self.joined_capacity()?;
        let name = self.function()?;
        crate::native_return::protocol::PendingInspection::forwarded(result.observed)
            .inspect(|| Ok(()))
            .resolve(|_, cause| cause)?;
        // JoinedCall observed native context once. Preserve the separate local
        // policy of Info/Restore refusals; a refused state read keeps its source.
        let scope = if name == "C_GetOperationState" {
            crate::native_return::state_read_scope(result.return_value)
        } else {
            crate::native_return::failure_scope(result.return_value)
        };
        if scope == crate::native_return::FailureScope::Session {
            entry.poisoned.store(true, Ordering::Release);
            if crate::native_return::native_context_scope(result.return_value)
                == crate::native_return::FailureScope::None
            {
                s.apply_failure_scope(&entry.snapshot, scope);
            }
        }
        // A successful native capture happened even if its local projection
        // subsequently rejects a length; encryption must still be frozen.
        self.note_capture(result.return_value);
        let projection = (|| -> Result<CK_RV> {
            Ok(match self.flow.phase() {
                Phase::Info => {
                    let (rv, info) = result.project_info()?;
                    if let Some(info) = info {
                        *self.info = info;
                    }
                    rv
                }
                Phase::Size => {
                    let Direction::Capture { maximum } = self.flow.direction() else {
                        return Err(Error::Rejected(crate::RejectionReason::OperationState(
                            crate::OperationStateRejection::StateSizeDirection,
                        )));
                    };
                    let (rv, length) = result.project_state_size(maximum)?;
                    if let Some(length) = length {
                        *self.length = bounds::ck_length(length)?;
                    }
                    rv
                }
                Phase::Bytes => {
                    let output = self.flow.bytes_mut().ok_or(Error::Rejected(
                        crate::RejectionReason::OperationState(
                            crate::OperationStateRejection::StateOutputAbsent,
                        ),
                    ))?;
                    let (rv, length) = result.project(name, Some(output.as_mut()))?;
                    if let Some(length) = length {
                        *self.length = bounds::ck_length(length)?;
                    }
                    rv
                }
                Phase::Restore => result.project(name, None)?.0,
                _ => {
                    return Err(Error::Rejected(crate::RejectionReason::OperationState(
                        crate::OperationStateRejection::StateIoNotActive,
                    )))
                }
            })
        })();
        let rv = match projection {
            Ok(rv) => rv,
            Err(error) => {
                self.flow.transition(Phase::Failed)?;
                s.native.mark_uncertain();
                return Err(error);
            }
        };
        self.pending = false;
        self.finish_terminal(entry, rv, name)
    }
}
// Pure correlation of a completed observation; never dereferences native memory.
fn validate_info(info: &CK_SESSION_INFO, slot: CK_SLOT_ID, read_write: bool) -> Result<()> {
    if info.slotID != slot
        || !session_state(info.state)
        || (info.flags & CKF_RW_SESSION != 0) != read_write
    {
        return Err(Error::Rejected(crate::RejectionReason::OperationState(
            crate::OperationStateRejection::OperationStateSessionIdentity,
        )));
    }
    Ok(())
}

fn session_state(state: CK_STATE) -> bool {
    matches!(
        state,
        CKS_RO_PUBLIC_SESSION
            | CKS_RO_USER_FUNCTIONS
            | CKS_RW_PUBLIC_SESSION
            | CKS_RW_USER_FUNCTIONS
            | CKS_RW_SO_FUNCTIONS
    )
}

mod progression;

mod resolved_call;
