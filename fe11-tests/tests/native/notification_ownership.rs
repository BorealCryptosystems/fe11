// SPDX-License-Identifier: Apache-2.0
//! Callback capture ownership on real synchronous session registrations.
//! Event delivery is a provider capability, not inferred from successful open.
use super::super::{
    configuration::{select_token, Budgets, Configuration},
    module_controls,
    object_owner::Owner,
    outcome::Failure,
    report::Report,
};
use fe11::*;
use std::{
    io::{self, Write},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

struct Capture(Arc<AtomicUsize>);
impl Capture {
    fn keep(&self) {}
}
impl Drop for Capture {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

pub(super) fn execute<W: Write>(
    config: &Configuration,
    action: &str,
    report: Report<W>,
) -> io::Result<bool> {
    let calls = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut module = None;
    let mut owner = None;
    let setup = (|| -> std::result::Result<(), Failure> {
        if !matches!(
            action,
            "session-continue" | "session-cancel" | "advanced-continue" | "advanced-cancel"
        ) {
            return Err(Failure::Input("notification_action"));
        }
        module = Some(config.open(&Budgets::ordinary())?);
        Ok(())
    })();
    let body = (|| -> std::result::Result<(), Failure> {
        let (Ok(()), Some(m)) = (&setup, &module) else {
            return Ok(());
        };
        let capture = Capture(dropped.clone());
        let observed = calls.clone();
        let cancel = action.ends_with("cancel");
        let handler = NotifyHandler::new(move |_| {
            capture.keep();
            observed.fetch_add(1, Ordering::SeqCst);
            if cancel {
                NotifyDecision::Cancel
            } else {
                NotifyDecision::Continue
            }
        });
        let retained = handler.clone();
        drop(handler);
        if dropped.load(Ordering::SeqCst) != 0 || calls.load(Ordering::SeqCst) != 0 {
            return Err(Failure::Oracle("notification_clone_called_or_released"));
        }
        let token = select_token(m, &config.label).ok_or(Failure::Input("notification_token"))?;
        let selected = m.select(&token)?;
        owner = Some(if action.starts_with("advanced") {
            Owner::Advanced(selected.open_advanced_session_with_notify(
                true,
                AdvancedSessionMode::Synchronous,
                retained,
            )?)
        } else {
            Owner::Session(selected.open_session_with_notify(true, retained)?)
        });
        if dropped.load(Ordering::SeqCst) != 0 {
            return Err(Failure::Oracle("notification_capture_released_while_live"));
        }
        let o = owner.as_ref().ok_or(Failure::Input("notification_owner"))?;
        let algorithm = NativeDigestAlgorithm::Sha256;
        let limits = InputLimits {
            maximum_parts: 1,
            maximum_total_bytes: 3,
        };
        let (digest, diagnostics) = match o {
            Owner::Session(s) => (
                s.digest_native(algorithm, &[b"abc"], limits)?,
                s.notify_diagnostics(),
            ),
            Owner::Advanced(s) => {
                let mut ticket = s.begin_native_digest(algorithm)?;
                s.digest_update(&mut ticket, b"abc", limits)?;
                let digest = match s.finish_native_digest(&mut ticket)? {
                    OperationProgress::NativeDigest(value) => value,
                    _ => return Err(Failure::Oracle("notification_digest_not_completed")),
                };
                (digest, s.notify_diagnostics())
            }
        };
        if digest.as_bytes()
            != [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
            || diagnostics != Some(NotifyDiagnostics::default())
        {
            return Err(Failure::Oracle("notification_session_control"));
        }
        // This recipe stores the callback but never emits an event. A zero
        // count proves only that fact; neither return decision is exercised.
        if calls.load(Ordering::SeqCst) != 0 {
            return Err(Failure::Oracle("notification_recipe_emitted_event"));
        }
        Ok(())
    })();
    let mut cleanup = owner.as_ref().map_or_else(Vec::new, |o| o.close(None));
    drop(owner);
    if let Some(m) = &module {
        if let Err(error) = m.close() {
            cleanup.push(error.into());
        }
    }
    drop(module);
    if setup.is_ok() && body.is_ok() && dropped.load(Ordering::SeqCst) != 1 {
        cleanup.push(Failure::Oracle("notification_capture_not_released_once"));
    }
    module_controls::finish(report, setup, body, cleanup)
}
