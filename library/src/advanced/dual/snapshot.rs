// SPDX-License-Identifier: Apache-2.0
//! Dual-operation snapshots preserve both primitive owners and native residue.
use super::{
    authentication::Authentication, DualOperation, DualStep, DualStorage, Mode, PreparedDual,
};
use crate::advanced::{capture_layout::Layouts, continuation, keys::KeyLease, MessageRoute};
use crate::{
    module::SessionEntry,
    symmetric::{
        cipher::snapshot::Snapshot as Parameters,
        memory::{Buffer, Credit},
    },
    Error, Result,
};
use fe11_sys::{CK_ASYNC_DATA, CK_MECHANISM, CK_ULONG};
use std::mem::size_of;
mod record_plan;
pub(in crate::advanced) use record_plan::RecordPlan;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::advanced) struct Shape {
    mode: Mode,
    authentication: Authentication,
    parts: usize,
    fragments: usize,
    input: usize,
    auth_capacity: usize,
    metadata: usize,
    total: usize,
}
pub(in crate::advanced) struct PreparedSnapshot {
    shape: Shape,
    body: PreparedDual,
}
impl DualOperation {
    pub(in crate::advanced) fn snapshot_shape(&self, entry: &SessionEntry) -> Result<Shape> {
        if self.pending
            || !self.valid
            || matches!(
                self.step,
                DualStep::AuthInit | DualStep::Done | DualStep::Failed
            )
        {
            return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualNotCapturable,
            )));
        }
        self.check_keys(entry)?;
        self.layout
            .fragments(&self.inputs, MessageRoute::Multipart)?;
        let output = self.output.as_ref().ok_or(Error::Rejected(
            crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualOutputAbsent,
            ),
        ))?;
        let native_bytes = self.cipher.snapshot_native_bytes()?;
        let metadata = self
            .inputs
            .len()
            .checked_mul(size_of::<Buffer>())
            .and_then(|n| {
                n.checked_add(
                    size_of::<DualOperation>()
                        + crate::error::CompletionStorage::allocation_bytes()
                        + 2 * size_of::<CK_MECHANISM>()
                        + size_of::<CK_ASYNC_DATA>()
                        + 2 * size_of::<CK_ULONG>(),
                )
            })
            .and_then(|n| n.checked_add(native_bytes))
            .ok_or(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualMetadataOverflow,
            )))?;
        let lengths = self
            .inputs
            .len()
            .checked_add(self.layout.lengths().len())
            .ok_or(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualSnapshotAccounting,
            )))?;
        let mut total = metadata
            .checked_add(self.cipher.snapshot_bytes()?)
            .and_then(|n| n.checked_add(output.capacity()))
            .and_then(|n| n.checked_add(self.auth.capacity()))
            .and_then(|n| {
                self.layout
                    .lengths()
                    .len()
                    .checked_mul(size_of::<usize>())
                    .and_then(|v| n.checked_add(v))
            })
            .and_then(|n| {
                Layouts::allocation_bytes(1, lengths)
                    .ok()
                    .and_then(|v| n.checked_add(v))
            })
            .ok_or(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualSnapshotAccounting,
            )))?;
        for input in &self.inputs {
            total = total.checked_add(input.capacity()).ok_or(Error::Rejected(
                crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::DualSnapshotAccounting,
                ),
            ))?;
        }
        total = total
            .checked_add(crate::advanced::capture_parts::Storage::temporary_bytes(
                self.inputs.len(),
            )?)
            .ok_or(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualSnapshotAccounting,
            )))?;
        Ok(Shape {
            mode: self.mode,
            authentication: self.authentication.selection(),
            parts: self.inputs.len(),
            fragments: self.layout.lengths().len(),
            input: self.input_length,
            auth_capacity: self.auth.capacity(),
            metadata,
            total,
        })
    }
    pub(in crate::advanced) fn describe_snapshot(
        &self,
        layout: &mut Layouts,
        prepaid: &mut Credit,
    ) -> Result<Parameters> {
        self.layout
            .fragments(&self.inputs, MessageRoute::Multipart)?;
        layout.push(
            &self.inputs,
            &self.layout,
            self.output
                .as_ref()
                .ok_or(Error::Rejected(crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::DualOutputAbsent,
                )))?
                .capacity(),
        )?;
        layout.complete()?;
        self.cipher.prepare_snapshot_parameters(prepaid)
    }
}
impl Shape {
    pub(super) fn for_request(
        mode: Mode,
        authentication: Authentication,
        cipher: &crate::DualCipher<'_>,
        parts: &[&[u8]],
        input: usize,
        expected: Option<&[u8]>,
    ) -> Result<Self> {
        let storage =
            DualStorage::for_request(mode, authentication, cipher, parts, input, expected)?;
        let count = parts.len().max(1);
        let temporary = crate::advanced::capture_parts::Storage::temporary_bytes(count)?;
        Ok(Self {
            mode,
            authentication,
            parts: count,
            fragments: parts.len(),
            input,
            auth_capacity: authentication.length(),
            metadata: storage.metadata,
            total: storage.total.checked_add(temporary).ok_or(Error::Rejected(
                crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::DualSnapshotAccounting,
                ),
            ))?,
        })
    }
    pub(super) fn allocate_request(
        self,
        cipher: &crate::DualCipher<'_>,
        parts: &[&[u8]],
        prepaid: &mut Credit,
    ) -> Result<Storage> {
        if parts.len() != self.fragments {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::DualSnapshotShapeChanged,
            )));
        }
        let parameters = Parameters::for_dual(cipher, prepaid)?.allocate()?;
        let output = self.input.checked_add(32).ok_or(Error::Rejected(
            crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualOutputOverflow,
            ),
        ))?;
        let buffers = if parts.is_empty() {
            crate::advanced::capture_parts::Storage::allocate_lengths(
                std::iter::once(0),
                std::iter::empty(),
                output,
            )?
        } else {
            crate::advanced::capture_parts::Storage::allocate_lengths(
                parts.iter().map(|part| part.len()),
                parts.iter().map(|part| part.len()),
                output,
            )?
        };
        Ok(Storage {
            shape: self,
            parts: buffers,
            parameters,
            extra: crate::symmetric::memory::UnboundBuffer::allocate(self.auth_capacity)?,
            completion_diagnostic: crate::error::CompletionStorage::allocate()?,
            metadata_credit: None,
        })
    }
    pub(in crate::advanced) fn allocation_bytes(self) -> usize {
        self.total
    }
    pub(in crate::advanced) fn layout_bytes(self) -> Result<usize> {
        Layouts::allocation_bytes(
            1,
            self.parts
                .checked_add(self.fragments)
                .ok_or(Error::Rejected(crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::DualSnapshotAccounting,
                )))?,
        )
    }
    pub(in crate::advanced) fn allocate_layout(
        self,
    ) -> Result<crate::advanced::capture_layout::Storage> {
        Layouts::allocate(
            1,
            self.parts
                .checked_add(self.fragments)
                .ok_or(Error::Rejected(crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::DualSnapshotAccounting,
                )))?,
        )
    }
    pub(in crate::advanced) fn allocate(
        self,
        layout: &Layouts,
        parameters: Parameters,
    ) -> Result<Storage> {
        let (sizes, fragments, output) = layout.row(0)?;
        if layout.len() != 1 || sizes.len() != self.parts || fragments.len() != self.fragments {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::DualSnapshotShapeChanged,
            )));
        }
        Ok(Storage {
            shape: self,
            parts: crate::advanced::capture_parts::Storage::allocate(sizes, fragments, output)?,
            parameters: parameters.allocate()?,
            extra: crate::symmetric::memory::UnboundBuffer::allocate(self.auth_capacity)?,
            completion_diagnostic: crate::error::CompletionStorage::allocate()?,
            metadata_credit: None,
        })
    }
}
impl PreparedSnapshot {
    pub(super) fn fill_request(
        mut self,
        cipher: &crate::DualCipher<'_>,
        parts: &[&[u8]],
        expected: Option<&[u8]>,
    ) -> Result<PreparedDual> {
        self.body.cipher.fill_dual_request(cipher)?;
        if !parts.is_empty() {
            if self.body.inputs.len() != parts.len() {
                return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                    crate::CheckpointCaptureRejection::DualSnapshotShapeChanged,
                )));
            }
            for (target, source) in self.body.inputs.iter_mut().zip(parts) {
                if target.as_slice().len() != source.len() {
                    return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                        crate::CheckpointCaptureRejection::DualSnapshotShapeChanged,
                    )));
                }
                target.as_mut().copy_from_slice(source);
            }
        }
        if let Some(expected) = expected {
            if self.body.auth.as_slice().len() != expected.len() {
                return Err(Error::Rejected(crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::DualFullMacLength,
                )));
            }
            self.body.auth.as_mut().copy_from_slice(expected);
        }
        *self.body.auth_length = crate::bounds::ck_length(self.shape.auth_capacity)?;
        Ok(self.body)
    }
    pub(in crate::advanced) fn copy_from(
        mut self,
        source: &DualOperation,
        entry: &SessionEntry,
    ) -> Result<DualOperation> {
        if self.shape != source.snapshot_shape(entry)? {
            return Err(Error::Rejected(crate::RejectionReason::CheckpointCapture(
                crate::CheckpointCaptureRejection::DualSnapshotShapeChanged,
            )));
        }
        for (target, original) in self.body.inputs.iter_mut().zip(&source.inputs) {
            continuation::copy(target, original)?;
        }
        self.body.cipher.fill_snapshot(&source.cipher)?;
        continuation::copy(
            self.body.output.as_mut().expect("prepared output"),
            source.output.as_ref().ok_or(Error::Rejected(
                crate::RejectionReason::CombinedOperations(
                    crate::CombinedOperationsRejection::DualOutputAbsent,
                ),
            ))?,
        )?;
        continuation::copy(&mut self.body.auth, &source.auth)?;
        self.body.step = source.step;
        self.body.used = source.used;
        self.body.residual_start = source.residual_start;
        self.body.residual_length = source.residual_length;
        self.body.active_flags = source.active_flags;
        *self.body.length = *source.length;
        *self.body.auth_length = *source.auth_length;
        self.body.bind(
            source.cipher_key.duplicate()?,
            source
                .authentication
                .key()
                .map(KeyLease::duplicate)
                .transpose()?,
        )
    }
}

pub(in crate::advanced) struct Storage {
    shape: Shape,
    parts: crate::advanced::capture_parts::Storage,
    parameters: crate::symmetric::cipher::snapshot::Storage,
    extra: crate::symmetric::memory::UnboundBuffer,
    completion_diagnostic: crate::error::CompletionStorage,
    // A failed partial binding must destroy the tables and leaves above before
    // their charge, even after some buffers have been moved to local owners.
    metadata_credit: Option<Credit>,
}
impl Storage {
    fn metadata_bytes(&self) -> Result<usize> {
        let planned = self
            .shape
            .parts
            .checked_mul(size_of::<Buffer>())
            .ok_or(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualSnapshotAccounting,
            )))?;
        let actual = self.parts.input_metadata_bytes()?;
        self.shape
            .metadata
            .checked_sub(planned)
            .and_then(|n| n.checked_add(actual))
            .ok_or(Error::Rejected(crate::RejectionReason::CombinedOperations(
                crate::CombinedOperationsRejection::DualSnapshotAccounting,
            )))
    }
    pub(in crate::advanced) fn allocated_bytes(&self) -> Result<usize> {
        [
            self.metadata_bytes()?,
            self.parts.allocated_bytes()?,
            self.parameters.allocated_bytes()?,
            self.extra.allocated(),
        ]
        .into_iter()
        .try_fold(0usize, |n, v| n.checked_add(v))
        .ok_or(Error::Rejected(crate::RejectionReason::CombinedOperations(
            crate::CombinedOperationsRejection::DualSnapshotAccounting,
        )))
    }
    pub(in crate::advanced) fn bind(mut self, prepaid: &mut Credit) -> Result<PreparedSnapshot> {
        self.metadata_credit = Some(prepaid.split(self.metadata_bytes()?)?);
        let parts = self.parts.bind(prepaid)?;
        let cipher = self.parameters.bind(prepaid)?;
        let shape = self.shape;
        Ok(PreparedSnapshot {
            shape,
            body: PreparedDual {
                mode: shape.mode,
                authentication: shape.authentication,
                step: DualStep::AuthInit,
                pending: false,
                valid: true,
                cipher,
                auth_mechanism: Box::new(CK_MECHANISM {
                    mechanism: shape.authentication.mechanism(),
                    pParameter: std::ptr::null_mut(),
                    ulParameterLen: 0,
                }),
                inputs: parts.inputs,
                layout: parts.layout,
                output: Some(parts.output),
                auth: self.extra.bind(prepaid)?,
                length: Box::new(0),
                auth_length: Box::new(0),
                used: 0,
                input_length: shape.input,
                residual_start: 0,
                residual_length: 0,
                completion: Box::new(crate::native::output::async_data()),
                name: [0; 32],
                active_flags: 0,
                completion_diagnostic: Some(self.completion_diagnostic),
                _credit: self
                    .metadata_credit
                    .take()
                    .expect("bound dual metadata credit"),
            },
        })
    }
}


