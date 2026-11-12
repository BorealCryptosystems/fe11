// SPDX-License-Identifier: Apache-2.0
//! Immutable prefix inside an otherwise provider-generated nonce block.
use crate::{NativeTransportParameters, Result};

/// Only location and length are stored here. The graph already owns the exact
/// input witness and its credit; no borrowed input crosses the native call.
#[derive(Clone, Copy)]
pub(crate) struct FixedPrefix {
    pub(super) block: usize,
    pub(super) bits: u64,
}

impl FixedPrefix {
    pub(crate) fn unchanged(&self, graph: &crate::mechanism_extension::graph::OwnedGraph) -> bool {
        graph.fixed_prefix_unchanged(self.block, self.bits)
    }
}

pub(crate) fn from_transport(
    parameters: &NativeTransportParameters<'_>,
    preceding_blocks: usize,
) -> Result<Option<FixedPrefix>> {
    let (bits, generator) = match parameters {
        NativeTransportParameters::GcmWrap {
            fixed_bits,
            generator,
            ..
        }
        | NativeTransportParameters::CcmWrap {
            fixed_bits,
            generator,
            ..
        } => (*fixed_bits, *generator),
        _ => return Ok(None),
    };
    if generator == fe11_sys::CKG_NO_GENERATE as u64 || bits == 0 {
        return Ok(None);
    }
    // The closed wrap encoder places IV/nonce in the first block after its
    // root. KIP inserts parent blocks and a mechanism header before that root.
    let block = preceding_blocks.checked_add(1).ok_or_else(|| {
        crate::Error::Rejected(crate::RejectionReason::MechanismExtensions(
            crate::MechanismExtensionsRejection::NestedMechanismGraphAccounting,
        ))
    })?;
    Ok(Some(FixedPrefix { block, bits }))
}
