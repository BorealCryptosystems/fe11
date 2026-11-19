// SPDX-License-Identifier: Apache-2.0
//! Fixed public digest witnesses; attribution is in vectors/digest/manifest.json.
use super::{
    arguments::hex,
    native_support::{required, status},
    outcome::Failure,
    probe_session::ProbeSession,
};
use fe11_sys::*;
use std::ptr;

pub(super) fn run(owner: &mut ProbeSession, name: &str) -> Result<(), Failure> {
    let text = match name {
        "digest-md5" => include_str!("../vectors/digest/03520e0cbcd3a62a5c0cec83d51c0ad22a5f97de18100841b683b2ecb563f5f6.txt"),
        "digest-sha224" => include_str!("../vectors/digest/867d01214fe3e94a282bb6b393325a702da70784ddeef832624293d06e5dead8.txt"),
        "digest-sha256" => include_str!("../vectors/digest/307642a5a3c7d71e683fb04c672165c336f2b379b2873af4334b22ee0ad762ed.txt"),
        "digest-sha384" => include_str!("../vectors/digest/de1da9c5df29323767376a35ac43c27b40fbc2ee21b332e4d23b960795749c85.txt"),
        "digest-sha3-224" => include_str!("../vectors/digest/32b89199b45612ab0d2a9f5e3ed59dbb05ddb96d80a494b978d9b0d92df1b812.txt"),
        "digest-sha3-256" => include_str!("../vectors/digest/cf49542f1e7d35e116cd682208e24d958d2571768aeb820804a9fe7b2f954287.txt"),
        "digest-sha3-384" => include_str!("../vectors/digest/aa74f39e474fccec5a65793b6054af27fb7f45dba3182b1ee294e2d9da622f4a.txt"),
        "digest-sha3-512" => include_str!("../vectors/digest/58cfba7836000d9c90233104607701f381721cfd7f7ef85a2f6880b495f6258b.txt"),
        "digest-sha512" => include_str!("../vectors/digest/45b969bea2bff6a01633f6a50899f5d0476667a7ef6c004fb1edcc0f59823c6f.txt"),
        "digest-sha-1" => include_str!("../vectors/digest/df0d940e0e0e2f4d4c4e4ef81166c72a4a7ddcc4de840d07d5af2fa2d6ad47f3.txt"),
        _ => return Err(Failure::Input("probe_digest_algorithm")),
    };
    let fields: Vec<_> = text.split_terminator('\n').collect();
    if fields.len() != 5 || fields[1] != "session-single" {
        return Err(Failure::Input("probe_digest_fixture"));
    }
    let number = fields[0]
        .parse()
        .map_err(|_| Failure::Input("probe_digest_mechanism"))?;
    let mut message = hex(fields[3], 16 * 1024 * 1024).map_err(Failure::Input)?;
    let expected = hex(fields[4], 64).map_err(Failure::Input)?;
    if expected.is_empty() {
        return Err(Failure::Input("probe_digest_answer"));
    }
    let mut mechanism = CK_MECHANISM {
        mechanism: number,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };
    let session = owner.handle()?;
    let initialize = required(owner.functions()?.C_DigestInit)?;
    let digest = required(owner.functions()?.C_Digest)?;
    let mut output = vec![0u8; expected.len()];
    let mut length = output.len() as CK_ULONG;
    // SAFETY: parameterless synchronous digest, owned input and exact known
    // output capacity. An empty Vec supplies a non-NULL pointer with zero length.
    status("C_DigestInit", unsafe {
        initialize(session, &mut mechanism)
    })?;
    status("C_Digest", unsafe {
        digest(
            session,
            message.as_mut_ptr(),
            message.len() as CK_ULONG,
            output.as_mut_ptr(),
            &mut length,
        )
    })?;
    if length as usize != expected.len() || output != expected {
        return Err(Failure::Oracle("probe_digest_known_answer"));
    }
    Ok(())
}
