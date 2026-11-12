// SPDX-License-Identifier: Apache-2.0
//! Empty private buffers are allocated together before any value is read.
use super::*;
use crate::symmetric::memory::UnboundBuffer;

enum EmptyComponents {
    Seed(UnboundBuffer),
    Value(UnboundBuffer),
    Both {
        seed: UnboundBuffer,
        value: UnboundBuffer,
    },
}
pub(in crate::crypto::pqc_material) struct Storage {
    algorithm: PqcPrivateKeyAlgorithm,
    components: EmptyComponents,
    diagnostic: crate::error::CompletionStorage,
}
impl Storage {
    pub(in crate::crypto::pqc_material) fn requested(
        algorithm: PqcPrivateKeyAlgorithm,
        encoding: PqcPrivateEncoding,
    ) -> Result<usize> {
        let bytes = match encoding {
            PqcPrivateEncoding::Seed => algorithm.seed_length(),
            PqcPrivateEncoding::Value => algorithm.value_length(),
            PqcPrivateEncoding::SeedAndValue => algorithm
                .seed_length()
                .checked_add(algorithm.value_length())
                .ok_or(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                    crate::PostQuantumKeysRejection::PqcExportStorageSize,
                )))?,
        };
        bytes
            .checked_add(ExportCall::allocation_bytes())
            .ok_or(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcExportStorageSize,
            )))
    }
    pub(in crate::crypto::pqc_material) fn allocate(
        algorithm: PqcPrivateKeyAlgorithm,
        encoding: PqcPrivateEncoding,
    ) -> Result<Self> {
        let components = match encoding {
            PqcPrivateEncoding::Seed => {
                EmptyComponents::Seed(UnboundBuffer::allocate(algorithm.seed_length())?)
            }
            PqcPrivateEncoding::Value => {
                EmptyComponents::Value(UnboundBuffer::allocate(algorithm.value_length())?)
            }
            PqcPrivateEncoding::SeedAndValue => EmptyComponents::Both {
                seed: UnboundBuffer::allocate(algorithm.seed_length())?,
                value: UnboundBuffer::allocate(algorithm.value_length())?,
            },
        };
        Ok(Self {
            algorithm,
            components,
            diagnostic: crate::error::CompletionStorage::allocate()?,
        })
    }
    pub(in crate::crypto::pqc_material) fn allocated_bytes(&self) -> Result<usize> {
        let bytes = match &self.components {
            EmptyComponents::Seed(buffer) | EmptyComponents::Value(buffer) => buffer.allocated(),
            EmptyComponents::Both { seed, value } => seed
                .allocated()
                .checked_add(value.allocated())
                .ok_or(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                    crate::PostQuantumKeysRejection::PqcExportStorageSize,
                )))?,
        };
        bytes
            .checked_add(ExportCall::allocation_bytes())
            .ok_or(Error::Rejected(crate::RejectionReason::PostQuantumKeys(
                crate::PostQuantumKeysRejection::PqcExportStorageSize,
            )))
    }
    pub(in crate::crypto::pqc_material) fn bind(
        self,
        credit: &mut Credit,
        protection: crate::session::observation_protection::ObservationProtection,
    ) -> Result<ExportCall> {
        let components = match self.components {
            EmptyComponents::Seed(seed) => Components::Seed(seed.bind(credit)?),
            EmptyComponents::Value(value) => Components::Value(value.bind(credit)?),
            EmptyComponents::Both { seed, value } => Components::SeedAndValue {
                seed: seed.bind(credit)?,
                value: value.bind(credit)?,
            },
        };
        let mut output = PqcPrivateExport {
            property_reports: None,
            algorithm: self.algorithm,
            components,
        };
        let (descriptors, count) = output.descriptors()?;
        // Snapshot descriptor values only. Both arrays refer to the same stable
        // buffers owned by output; neither array owns or frees those buffers.
        let expected = std::array::from_fn(|index| {
            let descriptor = &descriptors[index];
            CK_ATTRIBUTE {
                r#type: descriptor.r#type,
                pValue: descriptor.pValue,
                ulValueLen: descriptor.ulValueLen,
            }
        });
        Ok(ExportCall {
            output,
            descriptors,
            expected,
            count,
            diagnostic: Some(self.diagnostic),
            _protection: protection,
            _credit: credit.split(ExportCall::allocation_bytes())?,
        })
    }
}
