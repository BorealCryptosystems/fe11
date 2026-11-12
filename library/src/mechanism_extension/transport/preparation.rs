// SPDX-License-Identifier: Apache-2.0
//! Empty extension graph and transport data, measured with the caller template.
use super::{CreationData, CreationInput, KeyCreation};
use crate::{
    attribute_values::InputTemplate,
    bounds,
    mechanism_extension::graph::GraphStorage,
    native::derivation::InputBytesStorage,
    symmetric::memory::{Credit, UnboundBuffer},
    Error, Result,
};
use fe11_sys::{CK_INVALID_HANDLE, CK_MECHANISM, CK_MECHANISM_TYPE};

enum CreationStorage<'a> {
    Unwrap {
        input: &'a [u8],
        storage: InputBytesStorage,
    },
    Decapsulate {
        input: &'a [u8],
        storage: InputBytesStorage,
    },
    Encapsulate(UnboundBuffer),
}
impl<'a> CreationStorage<'a> {
    fn allocate(input: CreationInput<'a>) -> Result<Self> {
        Ok(match input {
            CreationInput::Unwrap(input) => Self::Unwrap {
                input,
                storage: InputBytesStorage::allocate(input.len())?,
            },
            CreationInput::Decapsulate(input) => Self::Decapsulate {
                input,
                storage: InputBytesStorage::allocate(input.len())?,
            },
            CreationInput::Encapsulate { capacity } => {
                bounds::ck_length(capacity)?;
                Self::Encapsulate(UnboundBuffer::allocate(capacity)?)
            }
        })
    }
    fn allocated_bytes(&self) -> Result<usize> {
        match self {
            Self::Unwrap { storage, .. } | Self::Decapsulate { storage, .. } => {
                storage.allocated_bytes()
            }
            Self::Encapsulate(storage) => Ok(storage.allocated()),
        }
    }
    fn bind(self, prepaid: &mut Credit) -> Result<CreationData> {
        Ok(match self {
            Self::Unwrap { input, storage } => CreationData::Unwrap(storage.bind(input, prepaid)?),
            Self::Decapsulate { input, storage } => {
                CreationData::Decapsulate(storage.bind(input, prepaid)?)
            }
            Self::Encapsulate(storage) => {
                let bytes = storage.bind(prepaid)?;
                let length = bounds::ck_length(bytes.capacity())?;
                CreationData::Encapsulate { bytes, length }
            }
        })
    }
}

pub(crate) struct KeyCreationStorage<'a> {
    graph: GraphStorage<'a>,
    data: CreationStorage<'a>,
    mechanism: CK_MECHANISM_TYPE,
    mutates: bool,
}
impl<'a> KeyCreationStorage<'a> {
    pub(crate) fn allocate(
        request: crate::mechanism_extension::graph::recipe::Request<'a>,
        input: CreationInput<'a>,
    ) -> Result<Self> {
        Ok(Self {
            graph: GraphStorage::allocate_input(request.parameters)?,
            data: CreationStorage::allocate(input)?,
            mechanism: request.contract.mechanism,
            mutates: request.contract.mutates_key(),
        })
    }
    pub(crate) fn allocated_bytes(&self) -> Result<usize> {
        self.graph
            .allocated_bytes()?
            .checked_add(self.data.allocated_bytes()?)
            .and_then(|n| n.checked_add(KeyCreation::frame_bytes()))
            .ok_or(Error::Rejected(
                crate::RejectionReason::MechanismExtensions(
                    crate::MechanismExtensionsRejection::KeyTransportStorageAccounting,
                ),
            ))
    }
    pub(crate) fn bind(self, template: InputTemplate, prepaid: &mut Credit) -> Result<KeyCreation> {
        Ok(KeyCreation {
            mechanism: CK_MECHANISM {
                mechanism: self.mechanism,
                pParameter: std::ptr::null_mut(),
                ulParameterLen: 0,
            },
            graph: self.graph.bind(prepaid)?,
            template,
            data: self.data.bind(prepaid)?,
            handle: CK_INVALID_HANDLE,
            mutates: self.mutates,
            _credit: prepaid.split(KeyCreation::frame_bytes())?,
        })
    }
}
