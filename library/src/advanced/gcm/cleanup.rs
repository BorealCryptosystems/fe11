// SPDX-License-Identifier: Apache-2.0
//! Move an AEAD message sequence into its explicit native cleanup phase.
//! Cleanup preserves the operation owner until native inactivity is established.

use super::*;

impl AeadMessageOperation {
    pub(super) fn begin_cleanup(
        &mut self,
        error: Error,
        rejection: Option<GcmRejection>,
    ) -> Result<()> {
        // Allocate the complete error shape before Final, including a possible
        // cleanup failure. This transition never dispatches another message.
        if matches!(error.without_object_marker(), Error::CleanupFailed { .. }) {
            return Err(error);
        }
        let mut diagnostic = self
            .cleanup_diagnostic
            .take()
            .expect("one terminal AEAD cleanup");
        diagnostic.replace_operation(error);
        self.outcome = AeadOutcome::Closing {
            diagnostic,
            rejection,
        };
        self.step = AeadStep::Finish;
        Ok(())
    }
}
