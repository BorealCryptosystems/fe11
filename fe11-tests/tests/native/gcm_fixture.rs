// SPDX-License-Identifier: Apache-2.0
//! Classic GCM known answers with exact IV, AAD and appended tag bytes.
use super::{arguments::hex, outcome::Failure};
use fe11::ClassicAeadParameters;
use std::{fs::File, io::Read, path::Path};

pub struct Vector {
    pub advanced: bool,
    pub encrypt: bool,
    pub valid: bool,
    pub reuse_after_refusal: bool,
    pub shorter_than_tag: bool,
    pub tag_bits: u64,
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
    pub aad: Vec<u8>,
    pub input: Vec<u8>,
    pub expected: Vec<u8>,
    pub lengths: Vec<usize>,
}

impl Vector {
    pub fn parameters(&self) -> ClassicAeadParameters<'_> {
        ClassicAeadParameters::Gcm {
            iv: &self.iv,
            aad: &self.aad,
            tag_bits: self.tag_bits,
        }
    }

    pub fn read(path: &Path) -> Result<Self, Failure> {
        Self::read_fields(path, false).map(|(vector, _)| vector)
    }

    pub fn read_graph(path: &Path) -> Result<(Self, String), Failure> {
        let (vector, graph) = Self::read_fields(path, true)?;
        Ok((vector, graph.ok_or(Failure::Input("gcm_graph_absent"))?))
    }

    fn read_fields(path: &Path, graph: bool) -> Result<(Self, Option<String>), Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("vector_open"))?
            .take(1048577)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("vector_read"))?;
        if bytes.len() > 1048576 {
            return Err(Failure::Input("vector_size"));
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Failure::Input("vector_encoding"))?;
        let f: Vec<_> = text.split_terminator('\n').collect();
        let expected_fields = if graph { 11 } else { 10 };
        if f.len() != expected_fields
            || !matches!(f[0], "session" | "advanced")
            || !matches!(f[1], "encrypt" | "decrypt")
            || !matches!(
                f[2],
                "valid" | "invalid" | "invalid-then-valid" | "shorter-than-tag"
            )
        {
            return Err(Failure::Input("gcm_fields"));
        }
        let tag_bits = f[3].parse().map_err(|_| Failure::Input("gcm_tag_bits"))?;
        let lengths: Vec<usize> = f[9]
            .split(',')
            .map(|n| n.parse().map_err(|_| Failure::Input("part_length")))
            .collect::<Result<_, _>>()?;
        let v = Self {
            advanced: f[0] == "advanced",
            encrypt: f[1] == "encrypt",
            valid: f[2] == "valid",
            reuse_after_refusal: f[2] == "invalid-then-valid",
            shorter_than_tag: f[2] == "shorter-than-tag",
            tag_bits,
            key: hex(f[4], 32).map_err(Failure::Input)?,
            iv: hex(f[5], 256).map_err(Failure::Input)?,
            aad: hex(f[6], 65536).map_err(Failure::Input)?,
            input: hex(f[7], 262144).map_err(Failure::Input)?,
            expected: hex(f[8], 262144).map_err(Failure::Input)?,
            lengths,
        };
        if !matches!(v.key.len(), 16 | 24 | 32)
            || v.iv.is_empty()
            || v.tag_bits > 128
            || v.tag_bits % 8 != 0
            || v.lengths.is_empty()
            || v.lengths.len() > 1024
            || v.lengths
                .iter()
                .try_fold(0usize, |sum, n| sum.checked_add(*n))
                != Some(v.input.len())
            || (v.encrypt && !v.valid)
            || (v.shorter_than_tag && v.input.len() >= (v.tag_bits / 8) as usize)
            || (v.reuse_after_refusal && v.input.is_empty())
        {
            return Err(Failure::Input("gcm_dimensions"));
        }
        let selector = if graph {
            if !matches!(
                f[10],
                "shared-disjoint" | "shared-alias" | "empty-null" | "empty-end"
            ) {
                return Err(Failure::Input("gcm_graph_selector"));
            }
            Some(f[10].to_owned())
        } else {
            None
        };
        Ok((v, selector))
    }
}
