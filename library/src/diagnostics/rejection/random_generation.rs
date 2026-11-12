// SPDX-License-Identifier: Apache-2.0
//! RandomGeneration causes, separate from native result/effect information.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
/// Causes belonging to random generation.
#[doc = include_str!("../../../docs/diagnostics/rejection-random_generation.md")]
pub enum RandomGenerationRejection {
    /// C_GenerateRandom unavailable. [Detection, owner and recovery](#cause-CGenerateRandomUnavailable).
    CGenerateRandomUnavailable,
    /// C_SeedRandom unavailable. [Detection, owner and recovery](#cause-CSeedRandomUnavailable).
    CSeedRandomUnavailable,
    /// C_WaitForSlotEvent unavailable. [Detection, owner and recovery](#cause-CWaitForSlotEventUnavailable).
    CWaitForSlotEventUnavailable,
    /// Native seed input changed. [Detection, owner and recovery](#cause-NativeSeedInputChanged).
    NativeSeedInputChanged,
    /// Random output accounting. [Detection, owner and recovery](#cause-RandomOutputAccounting).
    RandomOutputAccounting,
    /// Secret buffer accounting. [Detection, owner and recovery](#cause-SecretBufferAccounting).
    SecretBufferAccounting,
    /// Secret buffer allocation. [Detection, owner and recovery](#cause-SecretBufferAllocation).
    SecretBufferAllocation,
    /// Secret buffer already credited. [Detection, owner and recovery](#cause-SecretBufferAlreadyCredited).
    SecretBufferAlreadyCredited,
    /// Secret length exceeds capacity. [Detection, owner and recovery](#cause-SecretLengthExceedsCapacity).
    SecretLengthExceedsCapacity,
    /// Seed ownership accounting. [Detection, owner and recovery](#cause-SeedOwnershipAccounting).
    SeedOwnershipAccounting,
    /// Slot event generation allocation. [Detection, owner and recovery](#cause-SlotEventGenerationAllocation).
    SlotEventGenerationAllocation,
}

impl std::fmt::Display for RandomGenerationRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CGenerateRandomUnavailable => f.write_str("C_GenerateRandom unavailable"),
            Self::CSeedRandomUnavailable => f.write_str("C_SeedRandom unavailable"),
            Self::CWaitForSlotEventUnavailable => f.write_str("C_WaitForSlotEvent unavailable"),
            Self::NativeSeedInputChanged => f.write_str("native seed input changed"),
            Self::RandomOutputAccounting => f.write_str("random output accounting"),
            Self::SecretBufferAccounting => f.write_str("secret buffer accounting"),
            Self::SecretBufferAllocation => f.write_str("secret buffer allocation"),
            Self::SecretBufferAlreadyCredited => f.write_str("secret buffer already credited"),
            Self::SecretLengthExceedsCapacity => f.write_str("secret length exceeds capacity"),
            Self::SeedOwnershipAccounting => f.write_str("seed ownership accounting"),
            Self::SlotEventGenerationAllocation => f.write_str("slot event generation allocation"),
        }
    }
}
