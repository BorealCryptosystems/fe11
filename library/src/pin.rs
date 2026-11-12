// SPDX-License-Identifier: Apache-2.0
//! Owned PIN choices. An empty provided PIN is distinct from a protected path.
use crate::{bounds, Result, SecretPin};
use fe11_sys::{CK_ULONG, CK_UTF8CHAR};
mod preparation;

pub(crate) use preparation::{Credited, PreparedPins};

/// Select the native PIN source explicitly.
pub enum PinRequest {
    /// Send these owned bytes, including a deliberately empty PIN.
    Provided(SecretPin),
    /// Ask the module to obtain the PIN through its protected authentication path.
    /// This passes NULL; native refusal does not trigger a provided-PIN retry.
    ProtectedPath,
}

impl From<SecretPin> for PinRequest {
    fn from(pin: SecretPin) -> Self {
        Self::Provided(pin)
    }
}

/// C_SetPIN's two PINs share one source choice; mixed modes are not constructed.
pub enum PinChange {
    /// Change from the provided old bytes to the provided new bytes.
    ProvidedPair {
        /// Current PIN, consumed and erased when the completed call releases it.
        old: SecretPin,
        /// New PIN, consumed and erased when the completed call releases it.
        new: SecretPin,
    },
    /// Let the module obtain both PINs through its protected path.
    ProtectedPair,
}

// The zero-length sentinel lives with the complete frame, not on the stack.
// No native pointer is exposed by the public request types.
pub(crate) struct PinFrame {
    request: PinRequest,
    empty: u8,
}

/// A private, erased integrity witness; never passed to the native module.
pub(crate) enum PinWitness {
    Protected,
    Provided(crate::SecretBytes),
}

impl PinWitness {
    pub(crate) fn unchanged(&self, frame: &PinFrame) -> bool {
        frame.empty == 0
            && match (self, &frame.request) {
                (Self::Protected, PinRequest::ProtectedPath) => true,
                (Self::Provided(expected), PinRequest::Provided(actual)) => {
                    expected.as_slice() == actual.0.as_slice()
                }
                _ => false,
            }
    }
}

impl PinFrame {
    pub(crate) fn new(request: PinRequest) -> Self {
        Self { request, empty: 0 }
    }

    /// Capacity transferred with this input and length of its private witness.
    /// Protected-path input owns neither allocation; provided empty input still
    /// retains its distinct variant and may own spare caller-supplied capacity.
    pub(crate) fn storage_sizes(&self) -> (usize, usize) {
        match &self.request {
            PinRequest::ProtectedPath => (0, 0),
            PinRequest::Provided(pin) => (pin.0.capacity(), pin.0.len()),
        }
    }

    pub(crate) fn witness(&self) -> Result<PinWitness> {
        match &self.request {
            PinRequest::ProtectedPath => Ok(PinWitness::Protected),
            PinRequest::Provided(pin) => {
                bounds::ck_length(pin.0.len())?;
                let mut expected = crate::SecretBytes::new(pin.0.len())?;
                expected.as_mut_slice().copy_from_slice(pin.0.as_slice());
                Ok(PinWitness::Provided(expected))
            }
        }
    }

    pub(crate) fn arguments(&mut self) -> Result<(*mut CK_UTF8CHAR, CK_ULONG)> {
        match &mut self.request {
            PinRequest::ProtectedPath => Ok((std::ptr::null_mut(), 0)),
            PinRequest::Provided(pin) => {
                let length = bounds::ck_length(pin.0.len())?;
                let pointer = if pin.0.is_empty() {
                    &mut self.empty
                } else {
                    pin.0.as_mut_ptr()
                };
                Ok((pointer, length))
            }
        }
    }
}

pub(crate) struct PinChangeFrame {
    pub old: PinFrame,
    pub new: PinFrame,
}

impl PinChangeFrame {
    pub(crate) fn new(change: PinChange) -> Self {
        let (old, new) = match change {
            PinChange::ProvidedPair { old, new } => {
                (PinRequest::Provided(old), PinRequest::Provided(new))
            }
            PinChange::ProtectedPair => (PinRequest::ProtectedPath, PinRequest::ProtectedPath),
        };
        Self {
            old: PinFrame::new(old),
            new: PinFrame::new(new),
        }
    }
}

pub(crate) struct LoginFrame {
    pub pin: PinFrame,
    pub user_name: Option<zeroize::Zeroizing<Vec<u8>>>,
    pub empty_name: u8,
}

impl LoginFrame {
    pub(crate) fn new(pin: PinRequest, user_name: Option<Vec<u8>>) -> Self {
        Self {
            pin: PinFrame::new(pin),
            user_name: user_name.map(zeroize::Zeroizing::new),
            empty_name: 0,
        }
    }

    pub(crate) fn name_witness(&self) -> Result<Option<crate::SecretBytes>> {
        self.user_name
            .as_ref()
            .map(|name| {
                bounds::ck_length(name.len())?;
                let mut expected = crate::SecretBytes::new(name.len())?;
                expected.as_mut_slice().copy_from_slice(name.as_slice());
                Ok(expected)
            })
            .transpose()
    }

    pub(crate) fn name_unchanged(&self, witness: &Option<crate::SecretBytes>) -> bool {
        self.empty_name == 0
            && match (&self.user_name, witness) {
                (None, None) => true,
                (Some(actual), Some(expected)) => actual.as_slice() == expected.as_slice(),
                _ => false,
            }
    }
}

pub(crate) struct TokenInitializationFrame {
    pub pin: PinFrame,
    pub label: [u8; 32],
    pub observation: fe11_sys::CK_TOKEN_INFO,
}
