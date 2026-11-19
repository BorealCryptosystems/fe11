// SPDX-License-Identifier: Apache-2.0
//! Owned public evidence remains verifiable after its module owner is closed.
use super::super::{
    arguments::hex,
    configuration::{Budgets, Configuration},
    outcome::Failure,
};
use fe11::*;
use std::{fs::File, io::Read, path::Path};

struct Evidence {
    key: PqcPublicKey,
    other_key: PqcPublicKey,
    signature: PqcSignature,
    parameters: PqcSignatureParameters,
    message: Vec<u8>,
}

impl Evidence {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut data = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("engine_retained_open"))?
            .take(262_145)
            .read_to_end(&mut data)
            .map_err(|_| Failure::Input("engine_retained_read"))?;
        if data.len() > 262_144 {
            return Err(Failure::Input("engine_retained_size"));
        }
        let text =
            std::str::from_utf8(&data).map_err(|_| Failure::Input("engine_retained_encoding"))?;
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if fields.len() != 7 || fields[0] != "retained" {
            return Err(Failure::Input("engine_retained_fields"));
        }
        let algorithm = PqcAlgorithm::ALL
            .into_iter()
            .find(|a| a.name() == fields[1])
            .ok_or(Failure::Input("engine_retained_algorithm"))?;
        let public = hex(fields[2], algorithm.public_key_length()).map_err(Failure::Input)?;
        let other = hex(fields[6], algorithm.public_key_length()).map_err(Failure::Input)?;
        if public == other {
            return Err(Failure::Input("engine_retained_distinct_keys"));
        }
        let context = hex(fields[3], 255).map_err(Failure::Input)?;
        let signature = hex(fields[5], algorithm.signature_length()).map_err(Failure::Input)?;
        // These constructors own their inputs. Only the original message buffer
        // is retained directly; the text and temporary encodings can now drop.
        Ok(Self {
            key: PqcPublicKey::from_raw(algorithm, &public)?,
            other_key: PqcPublicKey::from_raw(algorithm, &other)?,
            signature: PqcSignature::from_bytes(algorithm, &signature)?,
            parameters: PqcSignatureParameters::pure(&context, PqcHedging::Preferred)?,
            message: hex(fields[4], 65_536).map_err(Failure::Input)?,
        })
    }

    fn verify(
        &self,
        engine: &VerifyEngine,
        key: &PqcPublicKey,
        message: &[u8],
        parameters: &PqcSignatureParameters,
        expected: Verification,
    ) -> std::result::Result<(), Failure> {
        let actual = key.verify(
            engine,
            message,
            &self.signature,
            parameters,
            InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: message.len(),
            },
        )?;
        if actual != expected {
            return Err(Failure::Oracle("retained_verification_binding"));
        }
        Ok(())
    }
}

pub(super) fn check(
    config: &Configuration,
    path: &Path,
    engine: VerifyEngine,
    cleanup: &mut Vec<Failure>,
) -> std::result::Result<(), Failure> {
    let evidence = Evidence::read(path)?;
    // Move the initial engine into Module. The retained clone below must keep
    // its originating image alive without a second loader or native session.
    let module = config
        .builder(&Budgets::ordinary())
        .verify_engine(Some(engine))
        .open()?;
    let prepared = (|| -> std::result::Result<VerifyEngine, Failure> {
        let retained = module
            .verify_engine()
            .ok_or(Failure::Oracle("retained_engine_absent"))?
            .clone();
        let before = module.call_counts()?;
        evidence.verify(
            &retained,
            &evidence.key,
            &evidence.message,
            &evidence.parameters,
            Verification::Valid,
        )?;
        if module.call_counts()? != before {
            return Err(Failure::Oracle("retained_engine_native_dispatch"));
        }
        Ok(retained)
    })();
    if let Err(error) = module.close() {
        cleanup.push(error.into());
        return Err(Failure::Oracle("retained_engine_module_close"));
    }
    // close borrows Module; dropping it is separately necessary to release its
    // verification-engine lease before exercising the retained clone.
    drop(module);
    let retained = prepared?;
    evidence.verify(
        &retained,
        &evidence.key,
        &evidence.message,
        &evidence.parameters,
        Verification::Valid,
    )?;
    let mut changed = evidence.message.clone();
    if let Some(first) = changed.first_mut() {
        *first ^= 1;
    } else {
        changed.push(1);
    }
    evidence.verify(
        &retained,
        &evidence.key,
        &changed,
        &evidence.parameters,
        Verification::Invalid,
    )?;
    evidence.verify(
        &retained,
        &evidence.other_key,
        &evidence.message,
        &evidence.parameters,
        Verification::Invalid,
    )?;
    let mut context = evidence.parameters.context().to_vec();
    if let Some(first) = context.first_mut() {
        *first ^= 1;
    } else {
        context.push(1);
    }
    let parameters = PqcSignatureParameters::pure(&context, PqcHedging::Preferred)?;
    evidence.verify(
        &retained,
        &evidence.key,
        &evidence.message,
        &parameters,
        Verification::Invalid,
    )?;
    evidence.verify(
        &retained,
        &evidence.key,
        &evidence.message,
        &evidence.parameters,
        Verification::Valid,
    )
}
