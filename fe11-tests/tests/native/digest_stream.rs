// SPDX-License-Identifier: Apache-2.0
//! Published large-message digests with bounded, reused input storage.
use super::{
    arguments::hex,
    configuration::Configuration,
    digest_owner::Owner,
    digest_vector::Outcome,
    outcome::Failure,
    report::{Observation, Phase, Producer, Report},
};
use fe11::{Module, NativeDigestAlgorithm};
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

struct Vector {
    algorithm: NativeDigestAlgorithm,
    advanced: bool,
    pattern: Vec<u8>,
    total: u64,
    chunk: usize,
    expected: Vec<u8>,
}

fn read(path: &Path) -> std::result::Result<Vector, Failure> {
    // Six lines: mechanism, owner, pattern hex, total bytes, chunk bytes, digest.
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("vector_open"))?
        .take(8193)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Input("vector_read"))?;
    if bytes.len() > 8192 {
        return Err(Failure::Input("vector_size"));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("vector_encoding"))?;
    let fields: Vec<_> = text.split_terminator('\n').collect();
    if fields.len() != 6 {
        return Err(Failure::Input("vector_fields"));
    }
    let mechanism = fields[0]
        .parse()
        .map_err(|_| Failure::Input("mechanism_number"))?;
    let algorithm = NativeDigestAlgorithm::from_mechanism(mechanism)
        .ok_or(Failure::Input("parameterless_digest_selector"))?;
    let advanced = match fields[1] {
        "session-stream" => false,
        "advanced-stream" => true,
        _ => return Err(Failure::Input("digest_route")),
    };
    let pattern = hex(fields[2], 2048).map_err(Failure::Input)?;
    let total: u64 = fields[3]
        .parse()
        .map_err(|_| Failure::Input("stream_length"))?;
    let chunk: usize = fields[4]
        .parse()
        .map_err(|_| Failure::Input("chunk_length"))?;
    let expected = hex(fields[5], 64).map_err(Failure::Input)?;
    // These are the frozen fixture dimensions, not product API limits.
    if pattern.is_empty()
        || total == 0
        || total > 8_589_934_592
        || chunk != 65536
        || expected.is_empty()
    {
        return Err(Failure::Input("stream_dimensions"));
    }
    Ok(Vector {
        algorithm,
        advanced,
        pattern,
        total,
        chunk,
        expected,
    })
}

pub fn run<W: Write>(
    module: &Module,
    config: &Configuration,
    path: &Path,
    report: &mut Report<W>,
) -> io::Result<Outcome> {
    let mut owner = None;
    let mut processed = 0u64;
    let mut updates = 0u64;
    let body = (|| -> std::result::Result<(), Failure> {
        let vector = read(path)?;
        owner = Some(Owner::open(module, config, vector.advanced)?);
        let selected = owner.as_ref().ok_or(Failure::Input("digest_owner"))?;
        let mut ticket = selected.begin(vector.algorithm)?;
        let mut input = vec![0u8; vector.chunk];
        let mut pattern_offset = 0;
        while processed < vector.total {
            let length = usize::try_from((vector.total - processed).min(vector.chunk as u64))
                .map_err(|_| Failure::Input("chunk_length"))?;
            for byte in &mut input[..length] {
                *byte = vector.pattern[pattern_offset];
                pattern_offset += 1;
                if pattern_offset == vector.pattern.len() {
                    pattern_offset = 0;
                }
            }
            // Reuse only after the synchronous update returned ownership.
            selected.update(&mut ticket, &input[..length])?;
            processed = processed
                .checked_add(length as u64)
                .ok_or(Failure::Input("stream_count_overflow"))?;
            updates = updates
                .checked_add(1)
                .ok_or(Failure::Input("stream_count_overflow"))?;
        }
        let actual = selected.finish(&mut ticket)?;
        if processed != vector.total
            || actual.algorithm() != vector.algorithm
            || actual.as_bytes() != vector.expected
        {
            return Err(Failure::Oracle("published_stream_digest_and_length"));
        }
        drop(actual);
        Ok(())
    })();
    // Counts describe completed update calls even when a later call failed.
    let cleanup = owner.as_ref().map_or_else(Vec::new, Owner::close);
    report.observation(
        Phase::Body,
        "stream_bytes_completed",
        Producer::Supervisor,
        Observation::Number(processed),
    )?;
    report.observation(
        Phase::Body,
        "stream_updates_completed",
        Producer::Supervisor,
        Observation::Number(updates),
    )?;
    Ok(Outcome { body, cleanup })
}
