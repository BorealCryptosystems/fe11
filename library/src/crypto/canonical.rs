// SPDX-License-Identifier: Apache-2.0
//! Compare the standard DER encoder's output without allocating a second document.
use der::{Encode, Writer};

struct Comparison<'a> {
    remaining: &'a [u8],
    equal: bool,
}
impl Writer for Comparison<'_> {
    fn write(&mut self, bytes: &[u8]) -> der::Result<()> {
        if self.equal {
            match self.remaining.get(..bytes.len()) {
                Some(expected) if expected == bytes => {
                    self.remaining = &self.remaining[bytes.len()..];
                }
                _ => self.equal = false,
            }
        }
        Ok(())
    }
}
/// The encoder still owns all DER rules; this sink only compares its chunks.
/// A mismatch or an unconsumed input suffix is noncanonical. Encoder failures
/// remain failures, and comparison introduces neither a size policy nor a copy.
pub(super) fn matches(value: &impl Encode, encoded: &[u8]) -> der::Result<bool> {
    let mut comparison = Comparison {
        remaining: encoded,
        equal: true,
    };
    value.encode(&mut comparison)?;
    Ok(comparison.equal && comparison.remaining.is_empty())
}
