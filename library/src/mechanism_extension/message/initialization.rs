// SPDX-License-Identifier: Apache-2.0
//! One owned initialization graph and the key identities encoded in its scalars.
//!
//! Construct before native use; moving this owner does not move graph blocks.
//! The enclosing native frame must keep the mechanism descriptor itself stable
//! while lent to C, and must establish memory return before inspection or copy.
use crate::mechanism_extension::{
    parameter_keys::{ReboundRecipe, RetainedParameterKeys},
    OwnedGraph,
};
use crate::{NativeObjectRef, Result};
use fe11_sys::{CK_MECHANISM, CK_MECHANISM_TYPE, CK_ULONG, CK_VOID_PTR};

pub(crate) struct Initialization {
    mechanism: CK_MECHANISM,
    parameters: OwnedGraph,
    keys: RetainedParameterKeys,
}

impl Initialization {
    pub(crate) fn new(
        kind: CK_MECHANISM_TYPE,
        mut parameters: OwnedGraph,
        keys: RetainedParameterKeys,
    ) -> Self {
        let (pointer, length) = parameters.projection();
        Self {
            mechanism: CK_MECHANISM {
                mechanism: kind,
                pParameter: pointer,
                ulParameterLen: length,
            },
            parameters,
            keys,
        }
    }

    pub(crate) fn descriptor(&mut self) -> &mut CK_MECHANISM {
        &mut self.mechanism
    }

    pub(crate) fn expected(&self) -> (CK_MECHANISM_TYPE, CK_VOID_PTR, CK_ULONG) {
        (
            self.mechanism.mechanism,
            self.mechanism.pParameter,
            self.mechanism.ulParameterLen,
        )
    }

    pub(crate) fn kind(&self) -> CK_MECHANISM_TYPE {
        self.mechanism.mechanism
    }

    /// Inspect only after the enclosing owner establishes native memory return.
    /// Graph serialization clears pointer fields; retained key locations remain
    /// descriptive and must be rebound explicitly before destination use.
    pub(crate) fn snapshot_parts(&self) -> (&OwnedGraph, &RetainedParameterKeys) {
        (&self.parameters, &self.keys)
    }

    pub(crate) fn unchanged(&self, expected: (CK_MECHANISM_TYPE, CK_VOID_PTR, CK_ULONG)) -> bool {
        self.expected() == expected
            && self.parameters.unchanged()
            && self.keys.unchanged(&self.parameters)
    }

    pub(crate) fn finish(&mut self) -> Result<()> {
        self.parameters.finish()
    }

    pub(crate) fn output(&self, index: usize) -> Option<&[u8]> {
        self.parameters.output(index)
    }

    /// Private-copy preparation, not permission to restore native state. The
    /// enclosing transaction must admit/check all destination object roles and
    /// recheck its source revision before installing the prepared candidate.
    pub(crate) fn rebind<'a>(
        &'a self,
        expected: (CK_MECHANISM_TYPE, CK_VOID_PTR, CK_ULONG),
        destinations: &[&'a NativeObjectRef],
    ) -> Result<ReboundRecipe<'a>> {
        if !self.unchanged(expected) {
            return Err(crate::Error::Rejected(
                crate::RejectionReason::MechanismExtensions(
                    crate::MechanismExtensionsRejection::ChangedMessageInitialization,
                ),
            ));
        }
        self.keys.rebind(&self.parameters, destinations)
    }
}

impl crate::symmetric::memory::RetainedStorage for Initialization {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        self.parameters.retain_credits(retained)?;
        Ok(())
    }
}
