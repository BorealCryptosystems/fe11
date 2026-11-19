// SPDX-License-Identifier: Apache-2.0
//! Generated PQC pair identity, public encoding and context-bound usability.
use super::super::{outcome::Failure, pqc_parameters::Parameters};
use fe11::*;

fn mechanism<'a>(parameters: &Parameters, context: &'a [u8]) -> NativeSignatureParameters<'a> {
    NativeSignatureParameters::PqcPure {
        family: parameters.family,
        parameters: Some(NativePqcContext {
            hedging: PqcHedging::DeterministicRequired,
            context: Some(context),
        }),
    }
}

fn invalid(result: fe11::Result<()>) -> std::result::Result<(), Failure> {
    match result {
        Err(Error::Native {
            function: "C_Verify",
            code: 192,
            ..
        }) => Ok(()),
        Err(error) => Err(error.into()),
        Ok(()) => Err(Failure::Oracle("generated_pqc_negative_accepted")),
    }
}

pub(super) fn check(
    session: &Session,
    public: &NativeObjectRef,
    private: &NativeObjectRef,
    parameters: &Parameters,
) -> std::result::Result<(), Failure> {
    for object in [public, private] {
        let read = session.read_flat_attribute(
            object,
            StandardAttribute::PARAMETER_SET,
            FlatAttributeReadPlan::Buffer { capacity: 8 },
        )?;
        if read.calls != (AttributeReadCalls::Direct { code: 0 })
            || read.unsigned()? != parameters.set
        {
            return Err(Failure::Oracle("generated_pqc_parameter_identity"));
        }
    }
    let read = session.read_flat_attribute(
        public,
        StandardAttribute::VALUE,
        FlatAttributeReadPlan::Buffer {
            capacity: parameters.public_bytes,
        },
    )?;
    if read.calls != (AttributeReadCalls::Direct { code: 0 }) {
        return Err(Failure::Oracle("generated_pqc_public_status"));
    }
    match read.value {
        FlatAttributeValue::Available(value)
            if value.as_bytes().len() == parameters.public_bytes =>
        {
            ()
        }
        _ => return Err(Failure::Oracle("generated_pqc_public_width")),
    }
    let message = b"abc";
    let parts = [message.as_slice()];
    let limits = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: message.len(),
    };
    // Context is an octet string, including embedded zero/high bytes. These
    // three boundaries use one retained generated pair, without comparing the
    // random key or its signature to an unrelated published signing vector.
    for length in [0usize, 1, 255] {
        let context: Vec<u8> = (0..length).map(|i| (i as u8).wrapping_mul(129)).collect();
        let signature = session.sign_native(
            private,
            mechanism(parameters, &context),
            MessageRoute::Single,
            &parts,
            limits,
            parameters.signature_bytes,
            None,
        )?;
        if signature.as_bytes().len() != parameters.signature_bytes {
            return Err(Failure::Oracle("generated_pqc_signature_width"));
        }
        session.verify_native(
            public,
            mechanism(parameters, &context),
            MessageRoute::Single,
            &parts,
            signature.as_bytes(),
            limits,
            None,
        )?;
        let mut changed = signature.as_bytes().to_vec();
        *changed
            .last_mut()
            .ok_or(Failure::Oracle("generated_pqc_signature_empty"))? ^= 1;
        invalid(session.verify_native(
            public,
            mechanism(parameters, &context),
            MessageRoute::Single,
            &parts,
            &changed,
            limits,
            None,
        ))?;
        let mut wrong_context = context.clone();
        if let Some(last) = wrong_context.last_mut() {
            *last ^= 1;
        } else {
            wrong_context.push(1);
        }
        invalid(session.verify_native(
            public,
            mechanism(parameters, &wrong_context),
            MessageRoute::Single,
            &parts,
            signature.as_bytes(),
            limits,
            None,
        ))?;
    }
    Ok(())
}
