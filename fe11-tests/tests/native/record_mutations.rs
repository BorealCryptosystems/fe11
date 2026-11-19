// SPDX-License-Identifier: Apache-2.0
//! Explicit bounded edits for one logical wire-field relationship.
//! Offsets refer to the positive frame, never to successively shifted buffers.
use super::super::{arguments::hex, outcome::Failure};

pub(super) fn verify(specification: &str, positive: &[u8], negative: &[u8]) -> Result<(), Failure> {
    let mut cursor = 0;
    let mut rebuilt = Vec::new();
    let mut count = 0;
    for edit in specification.split(';') {
        let fields: Vec<_> = edit.split(':').collect();
        if fields.len() != 3 || count == 8 {
            return Err(Failure::Input("record_mutation_fields"));
        }
        let start = fields[0]
            .parse::<usize>()
            .map_err(|_| Failure::Input("record_mutation_start"))?;
        let remove = fields[1]
            .parse::<usize>()
            .map_err(|_| Failure::Input("record_mutation_remove"))?;
        let end = start
            .checked_add(remove)
            .ok_or(Failure::Input("record_mutation_overflow"))?;
        if start < cursor || end > positive.len() {
            return Err(Failure::Input("record_mutation_range"));
        }
        let insert = hex(fields[2], 2048).map_err(Failure::Input)?;
        rebuilt.extend_from_slice(&positive[cursor..start]);
        rebuilt.extend_from_slice(&insert);
        if rebuilt.len() > 2048 {
            return Err(Failure::Input("record_mutation_size"));
        }
        cursor = end;
        count += 1;
    }
    rebuilt.extend_from_slice(&positive[cursor..]);
    if count == 0 || rebuilt.len() > 2048 || rebuilt != negative || positive == negative {
        return Err(Failure::Input("record_mutation_identity"));
    }
    Ok(())
}
