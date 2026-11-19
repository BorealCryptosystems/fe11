// SPDX-License-Identifier: Apache-2.0
//! Two bounded binary frames, accepted atomically before any module is opened.
//!
//! The supervisor sends the security-officer PIN first, then the user PIN. Each
//! frame is a big-endian u32 byte length followed by exactly that many bytes.
//! EOF is required after the second frame. There is no text decoding or trimming.
use std::io::{self, Read};
use zeroize::Zeroizing;

pub const MAXIMUM_PIN_BYTES: usize = 4096;

/// Deliberately has neither Debug nor Clone: credentials never enter diagnostics.
pub struct Credentials {
    pub officer: Zeroizing<Vec<u8>>,
    pub user: Zeroizing<Vec<u8>>,
}

/// Only a fixed category crosses the diagnostic boundary, never input bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputError {
    InvalidBound,
    TruncatedFrame,
    LengthExceedsBound,
    Allocation,
    TrailingBytes,
    Io,
}

fn exact(input: &mut impl Read, output: &mut [u8]) -> Result<(), InputError> {
    input.read_exact(output).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            InputError::TruncatedFrame
        } else {
            InputError::Io
        }
    })
}

fn frame(input: &mut impl Read, maximum: usize) -> Result<Zeroizing<Vec<u8>>, InputError> {
    let mut encoded = [0_u8; 4];
    exact(input, &mut encoded)?;
    let length =
        usize::try_from(u32::from_be_bytes(encoded)).map_err(|_| InputError::LengthExceedsBound)?;
    // Check before allocation, including lengths of zero and u32::MAX.
    if length > maximum {
        return Err(InputError::LengthExceedsBound);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(length)
        .map_err(|_| InputError::Allocation)?;
    bytes.resize(length, 0);
    exact(input, bytes.as_mut_slice())?;
    Ok(bytes)
}

pub fn read(input: &mut impl Read, maximum: usize) -> Result<Credentials, InputError> {
    if maximum > MAXIMUM_PIN_BYTES {
        return Err(InputError::InvalidBound);
    }
    let officer = frame(input, maximum)?;
    let user = frame(input, maximum)?;
    let mut trailing = [0_u8; 1];
    loop {
        match input.read(&mut trailing) {
            Ok(0) => return Ok(Credentials { officer, user }),
            Ok(_) => return Err(InputError::TrailingBytes),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(InputError::Io),
        }
    }
}
