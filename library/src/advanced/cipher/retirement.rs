// SPDX-License-Identifier: Apache-2.0
//! Cipher transitions into prepared retirement nodes; no allocation under guards.
use super::{CipherOperation, Stage};
pub(in crate::advanced) use crate::advanced::fragment_retirement::ReturnedOperands;
pub(super) use crate::advanced::fragment_retirement::{Pool, Storage};
use crate::Result;

impl CipherOperation {
    pub(in crate::advanced) fn take_returned_operands(&mut self) -> ReturnedOperands {
        std::mem::take(&mut self.returned)
    }

    pub(super) fn check_retirement(&self, stage: Stage) -> Result<()> {
        let count = match stage {
            Stage::Single | Stage::Final => self.frame.inputs.len(),
            Stage::Update { .. } => 1,
            _ => return Ok(()),
        };
        self.frame
            .retirement
            .check(count, self.frame.expected.capacity())
    }

    pub(super) fn retire_first_input(&mut self) {
        let input = self.frame.inputs.pop_front();
        self.frame.retirement.input(input, &mut self.returned);
        if self.frame.inputs.is_empty() {
            self.frame
                .retirement
                .shadow(|| self.frame.expected.take(), &mut self.returned);
        }
    }

    pub(super) fn retire_terminal_inputs(&mut self) {
        // Keep the established terminal layout (including Single's empty slot)
        // while transferring only its backing storage and byte reservation.
        for input in &mut self.frame.inputs {
            self.frame
                .retirement
                .input(input.take(), &mut self.returned);
        }
        self.frame
            .retirement
            .shadow(|| self.frame.expected.take(), &mut self.returned);
    }
}
