// SPDX-License-Identifier: Apache-2.0
//! Transfer of an inspected classic Init to a resident operation owner.
use super::{CallPhase, CallScope, Disposition, FrameReturn};
use crate::{Error, Result};

/// The caller derives this from the same resolved dispatch as the native call.
/// A VerifySignatureInit or a recovery Init cannot furnish this discriminant.
pub(crate) enum ClassicInit {
    Sign,
    Verify,
}
impl ClassicInit {
    fn function(&self) -> &'static str {
        match self {
            Self::Sign => "C_SignInit",
            Self::Verify => "C_VerifyInit",
        }
    }
}

/// Dropping this proof has no effect: the frame remains armed. Only an actual
/// resident exchange permits disarming it; this does not terminate the newly
/// initialized sequence. The proof is private and deliberately not Clone.
pub(crate) struct AcceptedInitTransfer<'a> {
    returned: FrameReturn<'a>,
}
impl<'a> FrameReturn<'a> {
    /// Inspection must already have accepted the complete parameter graph.
    /// Reject independent uncertainty even when this particular Init returned OK.
    pub(crate) fn accepted_init(
        self,
        kind: ClassicInit,
        function: &'static str,
        native: &crate::native::Native,
    ) -> Result<AcceptedInitTransfer<'a>> {
        if self.scope != CallScope::Session
            || self.disposition.get() != Disposition::Active
            || self.call.get() != CallPhase::Returned(fe11_sys::CKR_OK)
            || kind.function() != function
            || native.is_uncertain()
        {
            return Err(Error::Rejected(crate::RejectionReason::NativeExecution(
                crate::NativeExecutionRejection::NativeFrameCompletionUnproven,
            )));
        }
        Ok(AcceptedInitTransfer { returned: self })
    }
}
impl AcceptedInitTransfer<'_> {
    /// The caller holds the resident owner's lock and session possession.
    /// `candidate` is the inspected frame payload; `resident` is the previous
    /// operation of exactly the same native family. Its loan ended when this
    /// Init succeeded. Metadata publication has already been prepared.
    ///
    /// The exchange keeps the new loan anchored throughout. The callback only
    /// swaps prepared metadata; it must not allocate, lock, notify or fail.
    /// If it nevertheless unwinds, the frame still retains the previous body
    /// and the poisoned resident mutex retains the new one.
    pub(crate) fn replace_into<T>(
        self,
        candidate: &mut T,
        resident: &mut T,
        commit_metadata: impl FnOnce(),
    ) {
        std::mem::swap(candidate, resident);
        commit_metadata();
        self.returned.disposition.set(Disposition::Owned);
    }
}
