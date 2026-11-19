// SPDX-License-Identifier: Apache-2.0
//! Explicit replacement of retained digest and AEAD output storage.
use super::outcome::Failure;
use fe11::*;

pub fn selected(action: &str, gcm: bool) -> Option<usize> {
    let size = if gcm { 16 } else { 32 };
    match action {
        "poll_sufficient" => Some(size),
        _ => action
            .strip_prefix("provide_")?
            .parse()
            .ok()
            .filter(|n| [0, size - 1, size, size + 1].contains(n)),
    }
}

pub fn start_digest(module: &Module, owner: &AdvancedSession) -> Result<OperationTicket> {
    // SAFETY: SHA-256 is a parameterless PKCS#11 digest. It has no key,
    // writable parameter, embedded pointer or auxiliary output.
    let contract = unsafe {
        module.declare_mechanism_extension(
            fe11_sys::CKM_SHA256 as u64,
            (2, 40),
            ExtensionOperation::DigestMultipart,
            false,
        )?
    };
    // SAFETY: the empty graph represents exactly the native NULL/0 parameter.
    let request = unsafe {
        ExtensionRequest::new(
            &contract,
            ExtensionParameters {
                blocks: &[],
                pointers: &[],
                root: None,
                outputs: &[],
            },
        )
    };
    // The typed digest chooses its full output size. The extension entry point
    // exposes the short initial buffer needed to exercise this public control.
    owner.begin_extension_digest_stream(request, 31)
}

fn required(
    result: Result<OperationProgress>,
    gcm: bool,
    capacity: usize,
) -> std::result::Result<(), Failure> {
    match result {
        Ok(OperationProgress::CipherBufferRequired(r))
            if gcm
                && r.function == "C_Encrypt"
                && r.required == 16
                && r.previous_capacity == capacity
                && r.code == fe11_sys::CKR_BUFFER_TOO_SMALL as u64 =>
        {
            Ok(())
        }
        Err(Error::OutputBufferTooSmall {
            function: "C_DigestFinal",
            code,
            required: 32,
            capacity: actual,
        }) if !gcm && actual == capacity && code == fe11_sys::CKR_BUFFER_TOO_SMALL as u64 => Ok(()),
        Err(error) => Err(error.into()),
        _ => Err(Failure::Oracle("batch_capacity_exact_requirement")),
    }
}

fn replace(
    module: &Module,
    owner: &AdvancedSession,
    ticket: &OperationTicket,
    gcm: bool,
    capacity: usize,
) -> std::result::Result<(), Failure> {
    let before = module.call_counts()?;
    if gcm {
        owner.resize_cipher_output(ticket, capacity)?;
    } else {
        owner.provide_digest_output_capacity(ticket, capacity)?;
    }
    if module.call_counts()? != before {
        return Err(Failure::Oracle("batch_capacity_selection_dispatched"));
    }
    Ok(())
}

fn retry(
    module: &Module,
    owner: &AdvancedSession,
    ticket: &mut OperationTicket,
    gcm: bool,
) -> std::result::Result<Result<OperationProgress>, Failure> {
    let before = module.call_counts()?;
    let result = owner.poll(ticket);
    let after = module.call_counts()?;
    let name = if gcm { "C_Encrypt" } else { "C_DigestFinal" };
    let mut expected = before;
    *expected.entry(name).or_default() += 1;
    if after != expected {
        return Err(Failure::Oracle("batch_capacity_retry_replayed_input"));
    }
    Ok(result)
}

pub fn exercise(
    module: &Module,
    owner: &AdvancedSession,
    ticket: &mut OperationTicket,
    gcm: bool,
    capacity: usize,
) -> std::result::Result<OperationProgress, Failure> {
    let size = if gcm { 16 } else { 32 };
    if gcm {
        required(retry(module, owner, ticket, true)?, true, size - 1)?;
    } else {
        let before = module.call_counts()?;
        owner.digest_update(
            ticket,
            b"abc",
            InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: 3,
            },
        )?;
        let mut expected = before;
        *expected.entry("C_DigestUpdate").or_default() += 1;
        if module.call_counts()? != expected {
            return Err(Failure::Oracle("batch_capacity_digest_input_count"));
        }
        let before = module.call_counts()?;
        required(owner.finish_extension_digest_stream(ticket), false, 31)?;
        let mut expected = before;
        *expected.entry("C_DigestFinal").or_default() += 1;
        if module.call_counts()? != expected || ticket.digest_output_requirement()? != Some(32) {
            return Err(Failure::Oracle("batch_capacity_digest_initial_final"));
        }
    }
    replace(module, owner, ticket, gcm, capacity)?;
    let result = retry(module, owner, ticket, gcm)?;
    if capacity < size {
        required(result, gcm, capacity)?;
        replace(module, owner, ticket, gcm, size)?;
        Ok(retry(module, owner, ticket, gcm)??)
    } else {
        Ok(result?)
    }
}
