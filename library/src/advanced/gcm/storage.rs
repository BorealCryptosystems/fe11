// SPDX-License-Identifier: Apache-2.0
//! Account AEAD owner, fragment, parameter and output allocations.
//! Host storage extents are distinct from the lengths offered by native calls.

use super::*;

pub(super) fn storage_sum(parts: &[usize]) -> Result<usize> {
    parts.iter().try_fold(0usize, |total, bytes| {
        total
            .checked_add(*bytes)
            .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadStorageOverflow,
            )))
    })
}

/// Allocation includes any confirmed prefix; only the remaining offer is C-sized.
pub(super) enum OutputStorage {
    Initial(usize),
    Restored {
        capacity: usize,
        offered: Option<usize>,
    },
}
impl OutputStorage {
    fn capacity(self) -> Result<usize> {
        let (capacity, offered) = match self {
            Self::Initial(capacity) => (capacity, Some(capacity)),
            Self::Restored { capacity, offered } => (capacity, offered),
        };
        if let Some(offered) = offered {
            if offered > capacity {
                return Err(Error::Rejected(crate::RejectionReason::MessageRecord(
                    crate::MessageRecordRejection::AeadCapacityPrefixExceedsStorage,
                )));
            }
            bounds::ck_length(offered)?;
        }
        Ok(capacity)
    }
}

impl AeadStoragePlan {
    pub(super) fn empty(rows: usize) -> Result<Self> {
        let owner = storage_sum(&[
            std::mem::size_of::<AeadMessageOperation>(),
            crate::error::CleanupDiagnostic::allocation_bytes(),
            crate::error::CompletionStorage::allocation_bytes(),
            std::mem::size_of::<CK_MECHANISM>(),
            std::mem::size_of::<CK_ASYNC_DATA>(),
        ])?;
        let results = rows
            .checked_mul(std::mem::size_of::<Output>())
            .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::AeadResultMetadataOverflow,
            )))?;
        Ok(Self {
            owner,
            results,
            shared_init: 0,
            total: storage_sum(&[owner, results])?,
        })
    }

    pub(super) fn push(
        &mut self,
        row: RowDimensions,
        route: MessageRoute,
        output: OutputStorage,
    ) -> Result<()> {
        if route == MessageRoute::Single {
            bounds::ck_length(row.data)?;
        }
        let output_capacity = output.capacity()?;
        let owner = storage_sum(&[
            std::mem::size_of::<Frame>(),
            std::mem::size_of::<NativeParameters>(),
            std::mem::size_of::<CK_ULONG>(),
            row.retained,
            row.parts
                .checked_mul(std::mem::size_of::<Buffer>())
                .ok_or(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadInputMetadataOverflow,
                )))?,
        ])?;
        self.owner = storage_sum(&[self.owner, owner])?;
        self.total = storage_sum(&[
            self.total,
            owner,
            row.data,
            output_capacity,
            row.aad,
            row.nonce,
            row.tag,
            row.expected_tag,
            row.generated,
            queued_input::Storage::required_bytes(row.parts)?,
            super::super::continuation::InputLayout::allocation_bytes(row.fragments)?,
        ])?;
        Ok(())
    }

    pub(super) fn shared(&mut self, nonce: usize, tag: usize) -> Result<()> {
        self.shared_init = std::mem::size_of::<NativeParameters>();
        self.total = storage_sum(&[self.total, self.shared_init, nonce, tag])?;
        Ok(())
    }

    pub(super) fn for_requests(
        requests: &Requests<'_>,
        route: MessageRoute,
        init: MessageInitLayout,
    ) -> Result<Self> {
        requests.validate_init(init)?;
        let mut plan = Self::empty(requests.len())?;
        for index in 0..requests.len() {
            let request = requests.get(index);
            plan.push(
                RowDimensions {
                    parts: if route == MessageRoute::Single {
                        1
                    } else {
                        request.parts.len().max(1)
                    },
                    fragments: request.parts.len(),
                    data: request.data_len()?,
                    aad: request.aad.len(),
                    nonce: request.nonce.iv().len(),
                    tag: request.nonce.tag_bytes()?,
                    expected_tag: request.tag.map_or(0, <[u8]>::len),
                    retained: request.nonce.retained_bytes(),
                    generated: if !requests.decrypt() && request.nonce.generated() {
                        request.nonce.iv().len()
                    } else {
                        0
                    },
                },
                route,
                OutputStorage::Initial(request.data_len()?.max(1)),
            )?;
        }
        if init == MessageInitLayout::InitWithOwnedMessageParameters {
            let first = requests.get(0);
            plan.shared(first.nonce.iv().len(), first.nonce.tag_bytes()?)?;
        }
        Ok(plan)
    }
}

impl InputAccounting {
    pub(super) fn validate(
        self,
        requests: &Requests<'_>,
        limits: crate::InputLimits,
        ceiling: crate::CryptoLimits,
    ) -> Result<()> {
        match self {
            InputAccounting::Batch => requests.validate(limits, ceiling)?,
            InputAccounting::LegacySingle => {
                if requests.len() != 1 {
                    return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::SingleAeadRequestCount,
                    )));
                }
                let request = requests.get(0);
                let data =
                    crate::symmetric::input_size(ceiling, limits, request.parts, request.aad, 0)?;
                request
                    .nonce
                    .validate(request.aad.len(), data, requests.decrypt())?;
                if requests.decrypt()
                    && request.tag.map_or(true, |tag| {
                        request.nonce.tag_bytes().ok() != Some(tag.len())
                    })
                {
                    return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                        crate::AeadMessagesRejection::AeadMessageDecryptParameters,
                    )));
                }
            }
        }
        Ok(())
    }
}

pub(super) fn validate_binding_storage(
    kind: CipherKind,
    mechanism: &CK_MECHANISM,
    init: &InitBinding,
    frames: &[Frame],
) -> Result<()> {
    if let InitBinding::Declared(declared) = init {
        return if kind == CipherKind::Gcm && declared.unchanged(mechanism) {
            Ok(())
        } else {
            Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::DeclaredGcmInitDescriptorMutation,
            )))
        };
    }
    if mechanism.mechanism != kind.mechanism() {
        return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
            crate::AeadMessagesRejection::AeadMechanismMutation,
        )));
    }
    match init {
        InitBinding::Declared(_) => {
            return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                crate::AeadMessagesRejection::DeclaredGcmInitDispatch,
            )))
        }
        InitBinding::WithoutParameters => {
            if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
                return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadInitDescriptorMutation,
                )));
            }
        }
        InitBinding::Shared {
            params, nonce, tag, ..
        } => {
            let (origin, declared_length, _) = init.reference(frames)?;
            if mechanism.pParameter != params.pointer()
                || mechanism.ulParameterLen != params.size()
                || !params.unchanged(
                    origin,
                    declared_length,
                    nonce.as_slice().as_ptr().cast_mut(),
                    tag.as_slice().as_ptr().cast_mut(),
                )?
            {
                return Err(Error::Rejected(crate::RejectionReason::AeadMessages(
                    crate::AeadMessagesRejection::AeadSharedInitDescriptorMutation,
                )));
            }
        }
    }
    Ok(())
}

pub(super) fn prepare_message_storage(
    kind: CipherKind,
    mechanism: &CK_MECHANISM,
    init: &mut InitBinding,
    frames: &[Frame],
    i: usize,
) -> Result<()> {
    validate_binding_storage(kind, mechanism, init, frames)?;
    if let InitBinding::Shared { .. } = init {
        let (origin, _, _) = init.reference(frames)?;
        origin.fixed_scalars(&frames[i].origin)?;
    }
    if let InitBinding::Shared {
        params,
        nonce,
        tag,
        prepared_message,
        ..
    } = init
    {
        let frame = &frames[i];
        params.set_data_length(frame.expected)?;
        *prepared_message = InitReference::Message(i);
        nonce.as_mut().copy_from_slice(frame.origin.iv());
        if let Some(expected) = &frame.expected_tag {
            tag.as_mut().copy_from_slice(expected.as_slice());
        } else {
            tag.as_mut().fill(0);
        }
    }
    Ok(())
}

impl crate::symmetric::memory::RetainedStorage for Output {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        self.bytes.retain_credits(retained)?;
        self.nonce.retain_credits(retained)?;
        self.tag.retain_credits(retained)?;
        Ok(())
    }
}

impl crate::symmetric::memory::RetainedStorage for Outputs {
    fn retain_credits(
        &self,
        retained: &mut crate::symmetric::memory::RetainedBytes,
    ) -> crate::Result<()> {
        self.entries.retain_credits(retained)?;
        self._credit.retain_credits(retained)?;
        Ok(())
    }
}
