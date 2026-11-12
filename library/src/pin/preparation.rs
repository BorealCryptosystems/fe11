// SPDX-License-Identifier: Apache-2.0
//! Guard-free preparation for ordinary login and PIN administration.
use super::{PinFrame, PinWitness};
use crate::{bounds, symmetric::memory::Credit, Error, Result, SecretBytes};
use std::{
    mem::size_of,
    ops::{Deref, DerefMut},
};

fn accounting() -> Error {
    Error::Rejected(crate::RejectionReason::Authentication(
        crate::AuthenticationRejection::PinFrameAccounting,
    ))
}

/// The native owner and its transferred input capacities retain their credit
/// together, including on pending return or quarantine. Witnesses are separate:
/// they never enter native code and may leave after the comparison is abandoned.
pub(crate) struct Credited<T> {
    data: T,
    _credit: Credit,
}
impl<T> Deref for Credited<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.data
    }
}
impl<T> DerefMut for Credited<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.data
    }
}
pub(crate) struct Witnesses {
    pub(crate) pins: [PinWitness; 2],
    pub(crate) name: Option<SecretBytes>,
}
pub(crate) struct PreparedPins {
    witnesses: Witnesses,
    credit: Credit,
}
impl PreparedPins {
    /// Authentication or administration can succeed before a local publication or input
    /// integrity failure. Admit its one error leaf with the frame and witnesses,
    /// before taking any native guard; the public caller retains its credit.
    pub(crate) fn prepare_with_completion(
        frame_bytes: usize,
        pins: [Option<&PinFrame>; 2],
        name: Option<&Vec<u8>>,
        function: &'static str,
        reserve: impl FnMut(usize) -> Result<Credit>,
    ) -> Result<(Self, crate::error::PreparedCompletion)> {
        let bytes = frame_bytes
            .checked_add(crate::error::PreparedCompletionStorage::allocation_bytes())
            .ok_or_else(accounting)?;
        let mut pins = Self::prepare(bytes, pins, name, reserve)?;
        let diagnostic = crate::error::PreparedCompletion::prepare(function, &mut pins.credit)?;
        Ok((pins, diagnostic))
    }

    /// `frame_bytes` includes the concrete Credited<T> and its native frame.
    /// Caller-owned PIN/name capacity is measured separately and transferred
    /// only on bind; no native pointer or guarded operation exists during retry.
    pub(crate) fn prepare(
        frame_bytes: usize,
        pins: [Option<&PinFrame>; 2],
        name: Option<&Vec<u8>>,
        mut reserve: impl FnMut(usize) -> Result<Credit>,
    ) -> Result<Self> {
        let mut fixed = frame_bytes;
        let mut witness_bytes = 0usize;
        for pin in pins.into_iter().flatten() {
            let (capacity, length) = pin.storage_sizes();
            bounds::ck_length(length)?;
            fixed = fixed.checked_add(capacity).ok_or_else(accounting)?;
            // A zero-length Provided PIN still owns a SecretBytes witness.
            if matches!(&pin.request, super::PinRequest::Provided(_)) {
                witness_bytes = witness_bytes
                    .checked_add(length)
                    .and_then(|n| n.checked_add(size_of::<SecretBytes>()))
                    .ok_or_else(accounting)?;
            }
        }
        if let Some(name) = name {
            bounds::ck_length(name.len())?;
            fixed = fixed.checked_add(name.capacity()).ok_or_else(accounting)?;
            witness_bytes = witness_bytes
                .checked_add(name.len())
                .and_then(|n| n.checked_add(size_of::<SecretBytes>()))
                .ok_or_else(accounting)?;
        }
        let mut required = fixed.checked_add(witness_bytes).ok_or_else(accounting)?;
        loop {
            let mut credit = reserve(required)?;
            let mut witnesses = Witnesses {
                pins: [
                    pins[0]
                        .map(PinFrame::witness)
                        .transpose()?
                        .unwrap_or(PinWitness::Protected),
                    pins[1]
                        .map(PinFrame::witness)
                        .transpose()?
                        .unwrap_or(PinWitness::Protected),
                ],
                name: name
                    .map(|name| -> Result<SecretBytes> {
                        let mut copy = SecretBytes::new(name.len())?;
                        copy.as_mut_slice().copy_from_slice(name.as_slice());
                        Ok(copy)
                    })
                    .transpose()?,
            };
            let mut actual = fixed;
            for pin in &witnesses.pins {
                if let PinWitness::Provided(bytes) = pin {
                    actual = actual
                        .checked_add(bytes.allocated_bytes())
                        .and_then(|n| n.checked_add(size_of::<SecretBytes>()))
                        .ok_or_else(accounting)?;
                }
            }
            if let Some(bytes) = &witnesses.name {
                actual = actual
                    .checked_add(bytes.allocated_bytes())
                    .and_then(|n| n.checked_add(size_of::<SecretBytes>()))
                    .ok_or_else(accounting)?;
            }
            if actual > required {
                drop(witnesses);
                drop(credit);
                required = actual;
                continue;
            }
            credit.release(required - actual);
            for pin in &mut witnesses.pins {
                if let PinWitness::Provided(bytes) = std::mem::replace(pin, PinWitness::Protected) {
                    *pin = PinWitness::Provided(bytes.bind_prepaid(&mut credit)?);
                }
            }
            witnesses.name = witnesses
                .name
                .take()
                .map(|bytes| bytes.bind_prepaid(&mut credit))
                .transpose()?;
            return Ok(Self { witnesses, credit });
        }
    }
    pub(crate) fn bind<T>(self, data: T) -> (Credited<T>, Witnesses) {
        (
            Credited {
                data,
                _credit: self.credit,
            },
            self.witnesses,
        )
    }
}
