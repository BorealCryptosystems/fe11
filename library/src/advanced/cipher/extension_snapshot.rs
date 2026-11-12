// SPDX-License-Identifier: Apache-2.0
//! Graph packets bridge guarded copying and allocation outside source possession.
use super::extension::{Frame, Metadata, Source};
use crate::mechanism_extension::graph::{recipe, snapshot::SnapshotRecipe};
use crate::symmetric::memory::Buffer;
use crate::{Error, MechanismExtension, Result};

pub(in crate::advanced) struct Packet {
    bytes: Buffer,
    declaration: Option<(Metadata, MechanismExtension)>,
}
impl Packet {
    pub(in crate::advanced) fn new(bytes: Buffer) -> Self {
        Self {
            bytes,
            declaration: None,
        }
    }
    pub(in crate::advanced) fn capacity(&self) -> usize {
        self.bytes.capacity()
    }
    pub(super) fn copy_from(&mut self, source: &Frame) -> Result<()> {
        source.validate_for_call()?;
        let mut offset = 0usize;
        source.graph()?.write_snapshot(&mut |bytes| {
            let end = offset.checked_add(bytes.len()).ok_or(Error::Rejected(
                crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherGraphSnapshotSize,
                ),
            ))?;
            self.bytes
                .as_mut()
                .get_mut(offset..end)
                .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                    crate::CipherContinuationRejection::CipherGraphSnapshotSize,
                )))?
                .copy_from_slice(bytes);
            offset = end;
            Ok(())
        })?;
        self.bytes.set_length(offset)?;
        self.declaration = Some((source.source()?.metadata(), source.contract()?.clone()));
        Ok(())
    }
    pub(in crate::advanced) fn parameters(
        &self,
    ) -> Result<super::parameters::snapshot::Snapshot<'_>> {
        let (metadata, _) = self.declaration.as_ref().ok_or(Error::Rejected(
            crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherGraphPacketUninitialized,
            ),
        ))?;
        Ok(super::parameters::snapshot::Snapshot::Extension(
            Source::Archived {
                metadata: *metadata,
                parameters: recipe::Input::Snapshot(SnapshotRecipe::decode(self.bytes.as_slice())?),
            },
        ))
    }
    pub(in crate::advanced) fn contract(&self) -> Result<MechanismExtension> {
        self.declaration
            .as_ref()
            .map(|(_, contract)| contract.clone())
            .ok_or(Error::Rejected(crate::RejectionReason::CipherContinuation(
                crate::CipherContinuationRejection::CipherGraphPacketUninitialized,
            )))
    }
}
