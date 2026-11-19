// SPDX-License-Identifier: Apache-2.0
//! Distinct input guards precede native initialization and preserve idle owners.
use super::{
    arguments::hex, configuration::Configuration, generation_transition_spec, module_controls,
    object_owner::Owner, outcome::Failure, report::Report,
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

fn read(path: &Path) -> std::result::Result<String, Failure> {
    let mut input = Vec::new();
    File::open(path)
        .map_err(|_| Failure::Input("aead_guard_open"))?
        .take(65)
        .read_to_end(&mut input)
        .map_err(|_| Failure::Input("aead_guard_read"))?;
    match input.as_slice() {
        b"stream_length\n" => Ok("stream_length".into()),
        b"message_count\n" => Ok("message_count".into()),
        b"batch_ceiling\n" => Ok("batch_ceiling".into()),
        b"dual_context\n" => Ok("dual_context".into()),
        b"extension_route\n" => Ok("extension_route".into()),
        _ => Err(Failure::Input("aead_guard_action")),
    }
}

fn idle(owner: &Owner) -> std::result::Result<(), Failure> {
    let limits = InputLimits {
        maximum_parts: 1,
        maximum_total_bytes: 3,
    };
    let expected = hex(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        32,
    )
    .map_err(Failure::Input)?;
    match owner {
        Owner::Session(session) => {
            if session
                .digest(HashAlgorithm::Sha256, b"abc", limits)?
                .as_bytes()
                != expected
            {
                return Err(Failure::Oracle("aead_guard_idle_digest"));
            }
        }
        Owner::Advanced(session) => {
            let mut ticket =
                session.digest_native(NativeDigestAlgorithm::Sha256, &[b"abc"], limits)?;
            // Bound synchronous protocol transitions, not execution time.
            for _ in 0..8 {
                match session.poll(&mut ticket)? {
                    OperationProgress::Ready => (),
                    OperationProgress::NativeDigest(value) => {
                        return if value.as_bytes() == expected {
                            Ok(())
                        } else {
                            Err(Failure::Oracle("aead_guard_idle_digest"))
                        };
                    }
                    _ => return Err(Failure::Oracle("aead_guard_idle_progress")),
                }
            }
            return Err(Failure::Oracle("aead_guard_idle_incomplete"));
        }
    }
    Ok(())
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    report: Report<W>,
) -> io::Result<bool> {
    let mut owner = None;
    let mut objects = None;
    let setup = (|| -> std::result::Result<(String, SymmetricKey), Failure> {
        let action = read(path)?;
        owner = Some(Owner::open(&module, config, false)?);
        let Some(Owner::Session(session)) = &owner else {
            return Err(Failure::Input("aead_guard_owner"));
        };
        let mut spec = generation_transition_spec::key(&config.label);
        spec.persistent = false;
        let created = session.generate_aes_key(spec)?;
        objects = Some(created.objects);
        if created.remainder.is_some()
            || objects.as_ref().map_or(0, |set| set.as_slice().len()) != 1
        {
            return Err(Failure::Oracle("aead_guard_generation"));
        }
        let key = created.observation?;
        if !matches!(action.as_str(), "stream_length" | "extension_route") {
            let Some(Owner::Session(session)) = owner.take() else {
                return Err(Failure::Input("aead_guard_owner"));
            };
            owner = Some(Owner::Advanced(session.into_advanced()?));
        }
        Ok((action, key))
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        let Ok((action, key)) = &setup else {
            return Ok(());
        };
        let current = owner.as_ref().ok_or(Failure::Input("aead_guard_owner"))?;
        let before = module.call_counts()?;
        let (result, expected) =
            match current {
                Owner::Session(session) if action == "extension_route" => {
                    let object = &objects
                        .as_ref()
                        .ok_or(Failure::Input("aead_guard_object"))?
                        .as_slice()[0];
                    // SAFETY: CKM_AES_ECB is parameterless; this declaration
                    // truthfully selects single-part EncryptInit/Encrypt. The
                    // deliberately wrong stream entry point must reject it.
                    let contract = unsafe {
                        module.declare_mechanism_extension(
                            fe11_sys::CKM_AES_ECB as u64,
                            (2, 40),
                            ExtensionOperation::Encrypt,
                            false,
                        )
                    }?;
                    // SAFETY: NULL/0 parameters match standard AES ECB. No
                    // borrowed graph or output target is presented to native code.
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
                    (
                        session
                            .begin_extension_cipher_stream(
                                CipherKeyReference::Secret(object),
                                request,
                                CipherOutputPlan::Buffer { capacity: 16 },
                            )
                            .map(|_| ()),
                        RejectionReason::CipherContinuation(
                            CipherContinuationRejection::MultipartCipherDeclarationRequired,
                        ),
                    )
                }
                Owner::Advanced(session) if action == "dual_context" => (
                    session
                        .decrypt_digest_with_hash(
                            key,
                            HashAlgorithm::Sha256,
                            DualCipher::Gcm {
                                nonce: AeadNonce::Provided([0; 12]),
                                aad: &[],
                            },
                            &[&[0; 16]],
                            InputLimits {
                                maximum_parts: 1,
                                maximum_total_bytes: 16,
                            },
                        )
                        .map(|_| ()),
                    RejectionReason::CombinedOperations(
                        CombinedOperationsRejection::DualContextCeiling,
                    ),
                ),
                Owner::Session(session) => {
                    let object = &objects
                        .as_ref()
                        .ok_or(Failure::Input("aead_guard_object"))?
                        .as_slice()[0];
                    (session.begin_encrypt_classic_aead_stream(
                    object,
                    ClassicAeadParameters::Gcm { iv: &[0; 12], aad: &[], tag_bits: 128 },
                    Some(3), CipherOutputPlan::Buffer { capacity: 32 },
                ).map(|_| ()), RejectionReason::CipherContinuation(
                    CipherContinuationRejection::OnlyCcmRequiresAnExplicitStreamPlaintextLength,
                ))
                }
                Owner::Advanced(session) => {
                    let parts: [&[u8]; 1] = [b"abc"];
                    let message = [GcmEncryptMessage {
                        nonce: AeadNonce::Provided([0; 12]),
                        aad: &[],
                        parts: &parts,
                    }];
                    let empty = action == "message_count";
                    let limits = if empty {
                        InputLimits {
                            maximum_parts: 0,
                            maximum_total_bytes: 0,
                        }
                    } else {
                        InputLimits {
                            maximum_parts: 1,
                            maximum_total_bytes: 3,
                        }
                    };
                    (
                        session
                            .encrypt_gcm_messages(
                                key,
                                if empty { &[] } else { &message },
                                MessageRoute::Single,
                                limits,
                            )
                            .map(|_| ()),
                        RejectionReason::AeadMessages(if empty {
                            AeadMessagesRejection::AeadMessageMessageCount
                        } else {
                            AeadMessagesRejection::AeadMessageBatchCeiling
                        }),
                    )
                }
            };
        match result {
            Err(Error::Rejected(actual)) if actual == expected => (),
            Err(error) => return Err(error.into()),
            Ok(()) => return Err(Failure::Oracle("aead_guard_accepted")),
        }
        if module.call_counts()? != before {
            return Err(Failure::Oracle("aead_guard_dispatched"));
        }
        idle(current)
    })();
    let setup = setup.map(|_| ());
    let mut cleanup = Vec::new();
    if let Some(current) = &owner {
        if let Some(set) = &objects {
            for object in set.as_slice() {
                let result = match current {
                    Owner::Session(s) => s.destroy_native_object(object),
                    Owner::Advanced(s) => s.destroy_native_object(object),
                };
                if let Err(error) = result {
                    cleanup.push(error.into());
                }
            }
        }
        drop(objects);
        cleanup.extend(current.close(None));
    }
    drop(owner);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    module_controls::finish(report, setup, body, cleanup)
}
