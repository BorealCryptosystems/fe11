// SPDX-License-Identifier: Apache-2.0
//! A pointer-free digest graph does not itself grant a destination ABI contract.
use super::{signature::Graph, Limits, Reader, Writer};
use crate::Result;

#[derive(Clone, Copy)]
pub(in crate::advanced) struct DigestExtension<'a> {
    pub graph: Graph<'a>,
    pub edition: (u8, u8),
    pub caller_asserted: bool,
}
impl<'a> DigestExtension<'a> {
    pub(in crate::advanced) fn write(self, writer: &mut Writer<'_>) -> Result<()> {
        self.graph.write(writer)?;
        writer.u8(self.edition.0)?;
        writer.u8(self.edition.1)?;
        writer.u8(u8::from(self.caller_asserted))?;
        Ok(())
    }
    pub(in crate::advanced) fn read(reader: &mut Reader<'a>, limits: Limits) -> Result<Self> {
        let bytes = reader.bytes(limits.bytes)?;
        reader.inspect_graph(bytes)?;
        Ok(Self {
            graph: Graph::Encoded(bytes),
            edition: (reader.u8()?, reader.u8()?),
            caller_asserted: reader.boolean(crate::RejectionReason::OperationRecord(
                crate::OperationRecordRejection::DigestExtensionProvenance,
            ))?,
        })
    }
}
