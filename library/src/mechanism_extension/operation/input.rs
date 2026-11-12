// SPDX-License-Identifier: Apache-2.0
//! Owned extension inputs: native lengths apply to calls, not whole streams.
use crate::{
    bounds,
    native::derivation::{InputBytes, InputBytesStorage},
    symmetric::memory::{Buffer, Credit, UnboundBuffer},
    Error, Result,
};
use crypto_bigint::subtle::ConstantTimeEq;
use fe11_sys::{CK_BYTE_PTR, CK_ULONG};

pub(super) fn checked_length(
    mut lengths: impl Iterator<Item = usize>,
    multipart: bool,
) -> Result<usize> {
    let total = lengths.try_fold(0usize, |total, length| {
        bounds::ck_length(length)?;
        total.checked_add(length).ok_or(Error::Rejected(
            crate::RejectionReason::MechanismExtensions(
                crate::MechanismExtensionsRejection::ExtensionInputLengthOverflow,
            ),
        ))
    })?;
    if !multipart {
        bounds::ck_length(total)?;
    }
    Ok(total)
}

pub(super) enum Storage {
    Single(InputBytesStorage),
    Multipart {
        value: UnboundBuffer,
        witness: UnboundBuffer,
    },
}
impl Storage {
    pub(super) fn allocate(length: usize, multipart: bool) -> Result<Self> {
        if multipart {
            // The caller has checked every fragment and its aggregate budget.
            // This aggregate is never passed as a native ulDataLen.
            Ok(Self::Multipart {
                value: UnboundBuffer::allocate(length)?,
                witness: UnboundBuffer::allocate(length)?,
            })
        } else {
            Ok(Self::Single(InputBytesStorage::allocate(length)?))
        }
    }

    pub(super) fn allocated_bytes(&self) -> Result<usize> {
        match self {
            Self::Single(storage) => storage.allocated_bytes(),
            Self::Multipart { value, witness } => value
                .allocated()
                .checked_add(witness.allocated())
                .ok_or(Error::Rejected(
                    crate::RejectionReason::MechanismExtensions(
                        crate::MechanismExtensionsRejection::ExtensionInputLengthOverflow,
                    ),
                )),
        }
    }

    pub(super) fn bind_parts(self, parts: &[&[u8]], prepaid: &mut Credit) -> Result<Input> {
        match self {
            Self::Single(storage) => Ok(Input::Single(storage.bind_parts(parts, prepaid)?)),
            Self::Multipart { value, witness } => {
                let length = checked_length(parts.iter().map(|part| part.len()), true)?;
                let mut value = value.bind(prepaid)?;
                let mut witness = witness.bind(prepaid)?;
                if value.capacity() != length || witness.capacity() != length {
                    return Err(Error::Rejected(crate::RejectionReason::NativeDerivation(
                        crate::NativeDerivationRejection::PreparedInputLengthChanged,
                    )));
                }
                let mut offset = 0;
                for part in parts {
                    let end = offset + part.len(); // bounded by checked_length above
                    value.as_mut()[offset..end].copy_from_slice(part);
                    witness.as_mut()[offset..end].copy_from_slice(part);
                    offset = end;
                }
                Ok(Input::Multipart { value, witness })
            }
        }
    }
}

pub(super) enum Input {
    Single(InputBytes),
    Multipart { value: Buffer, witness: Buffer },
}
impl Input {
    pub(super) fn single(&mut self) -> Option<(CK_BYTE_PTR, CK_ULONG)> {
        match self {
            Self::Single(input) => Some((input.pointer(), input.length())),
            Self::Multipart { .. } => None,
        }
    }

    pub(super) fn pointer(&mut self) -> CK_BYTE_PTR {
        match self {
            Self::Single(input) => input.pointer(),
            Self::Multipart { value, .. } => value.as_mut().as_mut_ptr(),
        }
    }

    pub(super) fn unchanged(&self) -> bool {
        match self {
            Self::Single(input) => input.unchanged(),
            Self::Multipart { value, witness } => {
                bool::from(value.as_slice().ct_eq(witness.as_slice()))
            }
        }
    }
}
