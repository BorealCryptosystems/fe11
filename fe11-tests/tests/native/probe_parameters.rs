// SPDX-License-Identifier: Apache-2.0
//! Published domain parameters; provenance is retained beside the public vectors.
use super::{arguments::hex, outcome::Failure};

pub(super) struct Parameters {
    pub prime: Vec<u8>,
    pub subprime: Vec<u8>,
    pub base: Vec<u8>,
}

pub(super) fn domain(dsa: bool) -> Result<Parameters, Failure> {
    let (p, q, g) = if dsa {
        (
            include_str!("../vectors/parameters/dsa1024-p.hex"),
            include_str!("../vectors/parameters/dsa1024-q.hex"),
            include_str!("../vectors/parameters/dsa1024-g.hex"),
        )
    } else {
        (
            include_str!("../vectors/parameters/ffdhe2048-p.hex"),
            include_str!("../vectors/parameters/ffdhe2048-q.hex"),
            include_str!("../vectors/parameters/ffdhe2048-g.hex"),
        )
    };
    let decode = |value: &str| {
        hex(
            value
                .strip_suffix('\n')
                .ok_or(Failure::Input("probe_parameter_framing"))?,
            512,
        )
        .map_err(Failure::Input)
    };
    Ok(Parameters {
        prime: decode(p)?,
        subprime: decode(q)?,
        base: decode(g)?,
    })
}
