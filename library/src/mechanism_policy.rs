// SPDX-License-Identifier: Apache-2.0

use crate::{Error, Result};
use fe11_sys::{CKA_ALLOWED_MECHANISMS, CK_MECHANISM_TYPE};

/// Native creation request only; it is not evidence or a local permission gate.
#[derive(Clone, Copy, Debug)]
pub enum MechanismRequest<'a> {
    /// Do not supply CKA_ALLOWED_MECHANISMS in the native creation template.
    Omitted,
    /// Supply the exact sequence, including an explicitly empty list.
    Explicit {
        /// Public PKCS#11 mechanism numbers; order and repetitions are retained.
        mechanisms: &'a [u64],
        /// Chosen budget for the encoded native array, checked before allocation.
        maximum_bytes: usize,
    },
}

/// Independent native creation request and optional attribute observation.
#[derive(Clone, Debug)]
pub struct MechanismAttributes<'a> {
    /// Exact native creation request.
    pub request: MechanismRequest<'a>,
    /// Explicit read choice, independent of the native creation request.
    pub admission: crate::MechanismObservationPlan,
}

enum PreparedMechanismRequest {
    Omitted,
    Explicit(Vec<CK_MECHANISM_TYPE>),
}

pub(crate) struct PreparedMechanismAttributes {
    request: PreparedMechanismRequest,
    pub(crate) admission: crate::MechanismObservationPlan,
}

impl MechanismAttributes<'_> {
    /// Emit borrowed numbers directly into the admitted template. Measurement
    /// does not allocate; materialization owns one native-width aligned array.
    pub(crate) fn apply_borrowed(
        &self,
        template: &mut impl crate::attributes::TemplateSink,
    ) -> Result<()> {
        self.validate()?;
        if let MechanismRequest::Explicit { mechanisms, .. } = self.request {
            template.mechanism_numbers(CKA_ALLOWED_MECHANISMS, mechanisms)?;
        }
        Ok(())
    }
    /// Validate the borrowed native request before any resource admission.
    pub(crate) fn validate(&self) -> Result<()> {
        if let MechanismRequest::Explicit {
            mechanisms,
            maximum_bytes,
        } = self.request
        {
            let bytes = mechanisms
                .len()
                .checked_mul(std::mem::size_of::<CK_MECHANISM_TYPE>())
                .ok_or(Error::Rejected(crate::RejectionReason::Mechanisms(
                    crate::MechanismsRejection::MechanismRequestByteCount,
                )))?;
            crate::bounds::ck_length(bytes)?;
            if bytes > maximum_bytes {
                return Err(Error::Rejected(crate::RejectionReason::Mechanisms(
                    crate::MechanismsRejection::MechanismRequestBudget,
                )));
            }
            for value in mechanisms {
                CK_MECHANISM_TYPE::try_from(*value).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::Mechanisms(
                        crate::MechanismsRejection::MechanismRequestWidth,
                    ))
                })?;
            }
        }
        Ok(())
    }

    /// Size the exact native request without copying it. An explicit empty
    /// list stays distinct from omission even though both have zero payload.
    pub(crate) fn requested_bytes(&self) -> Result<usize> {
        self.validate()?;
        match self.request {
            MechanismRequest::Omitted => Ok(0),
            MechanismRequest::Explicit { mechanisms, .. } => mechanisms
                .len()
                .checked_mul(std::mem::size_of::<CK_MECHANISM_TYPE>())
                .ok_or(Error::Rejected(crate::RejectionReason::Mechanisms(
                    crate::MechanismsRejection::MechanismRequestByteCount,
                ))),
        }
    }

    pub(crate) fn prepare(&self) -> Result<PreparedMechanismAttributes> {
        let request = match self.request {
            MechanismRequest::Omitted => PreparedMechanismRequest::Omitted,
            MechanismRequest::Explicit {
                mechanisms,
                maximum_bytes,
            } => {
                let bytes = mechanisms
                    .len()
                    .checked_mul(std::mem::size_of::<CK_MECHANISM_TYPE>())
                    .ok_or(Error::Rejected(crate::RejectionReason::Mechanisms(
                        crate::MechanismsRejection::MechanismRequestByteCount,
                    )))?;
                crate::bounds::ck_length(bytes)?;
                if bytes > maximum_bytes {
                    return Err(Error::Rejected(crate::RejectionReason::Mechanisms(
                        crate::MechanismsRejection::MechanismRequestBudget,
                    )));
                }
                let mut native = Vec::new();
                native.try_reserve_exact(mechanisms.len()).map_err(|_| {
                    Error::Rejected(crate::RejectionReason::Mechanisms(
                        crate::MechanismsRejection::MechanismRequestAllocation,
                    ))
                })?;
                for value in mechanisms {
                    native.push(CK_MECHANISM_TYPE::try_from(*value).map_err(|_| {
                        Error::Rejected(crate::RejectionReason::Mechanisms(
                            crate::MechanismsRejection::MechanismRequestWidth,
                        ))
                    })?);
                }
                PreparedMechanismRequest::Explicit(native)
            }
        };
        Ok(PreparedMechanismAttributes {
            request,
            admission: self.admission.clone(),
        })
    }
}

impl PreparedMechanismAttributes {
    /// Additional owned native request storage; the read choice is inline.
    pub(crate) fn retained_request_bytes(&self) -> Result<usize> {
        match &self.request {
            PreparedMechanismRequest::Omitted => Ok(0),
            PreparedMechanismRequest::Explicit(values) => values
                .capacity()
                .checked_mul(std::mem::size_of::<CK_MECHANISM_TYPE>())
                .ok_or(Error::Rejected(crate::RejectionReason::Mechanisms(
                    crate::MechanismsRejection::RetainedMechanismRequestSize,
                ))),
        }
    }
    pub(crate) fn apply(&self, template: &mut impl crate::attributes::TemplateSink) -> Result<()> {
        if let PreparedMechanismRequest::Explicit(values) = &self.request {
            template.mechanisms(CKA_ALLOWED_MECHANISMS, values)?;
        }
        Ok(())
    }
}
