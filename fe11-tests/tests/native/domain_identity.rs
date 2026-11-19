// SPDX-License-Identifier: Apache-2.0
//! Domain objects feed the matching finite-field key operations.
#[path = "dh_import_identity.rs"]
mod dh;
#[path = "dsa_import_identity.rs"]
mod dsa;
use super::{arguments::Arguments, report::Report};
use fe11::Module;
use std::io::{self, Write};

pub fn execute<W: Write>(module: Module, args: &Arguments, report: Report<W>) -> io::Result<bool> {
    match args.mode.as_str() {
        "dsa-import-identity" => dsa::execute(module, &args.config, &args.vector, report),
        "dh-import-identity" | "dh-public-import" => dh::execute(
            module, &args.config, &args.vector, args.mode == "dh-public-import", report,
        ),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "domain identity route",
        )),
    }
}
