// SPDX-License-Identifier: Apache-2.0
//! Observe the second Init of a classic dual operation and retain prior outputs.
use super::{
    arguments::hex,
    configuration::{select_token, Configuration},
    credentials::Credentials,
    module_controls,
    outcome::{self, Failure},
    report::{Phase, Report},
    selection_symmetric,
};
use fe11::*;
use std::{
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

struct Case {
    route: String,
    key: Vec<u8>,
    iv: [u8; 16],
    input: Vec<u8>,
    mac_key: Vec<u8>,
    mac: [u8; 32],
    digest: Vec<u8>,
}
impl Case {
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut text = String::new();
        File::open(path)
            .map_err(|_| Failure::Input("dual_fixture_open"))?
            .take(2049)
            .read_to_string(&mut text)
            .map_err(|_| Failure::Input("dual_fixture_read"))?;
        if text.len() > 2048 {
            return Err(Failure::Input("dual_fixture_size"));
        }
        let fields: Vec<_> = text.split_terminator('\n').collect();
        if fields.len() != 7
            || !matches!(
                fields[0],
                "digest_encrypt"
                    | "decrypt_digest"
                    | "sign_encrypt"
                    | "decrypt_verify"
                    | "digest_encrypt_with_hash"
                    | "decrypt_digest_with_hash"
                    | "sign_encrypt_with_mac"
                    | "decrypt_verify_with_mac"
            )
        {
            return Err(Failure::Input("dual_fixture_fields"));
        }
        let bytes = |i| hex(fields[i], 64).map_err(Failure::Input);
        let key = bytes(1)?;
        let input = bytes(3)?;
        let mac_key = bytes(4)?;
        let digest = bytes(6)?;
        if key.len() != 16 || input.len() != 16 || mac_key.len() != 32 || digest.len() != 32 {
            return Err(Failure::Input("dual_fixture_dimensions"));
        }
        Ok(Self {
            route: fields[0].into(),
            key,
            input,
            mac_key,
            digest,
            iv: bytes(2)?
                .try_into()
                .map_err(|_| Failure::Input("dual_iv_width"))?,
            mac: bytes(5)?
                .try_into()
                .map_err(|_| Failure::Input("dual_mac_width"))?,
        })
    }
    fn uses_mac(&self) -> bool {
        self.route.starts_with("sign_") || self.route.starts_with("decrypt_verify")
    }
    fn cipher_function(&self) -> &'static str {
        if self.route.starts_with("decrypt_") {
            "C_DecryptInit"
        } else {
            "C_EncryptInit"
        }
    }
    fn auth_function(&self) -> &'static str {
        if self.route.starts_with("sign_") {
            "C_SignInit"
        } else if self.route.starts_with("decrypt_verify") {
            "C_VerifyInit"
        } else {
            "C_DigestInit"
        }
    }
}

fn specification(mac: bool) -> SymmetricIntroductionSpec {
    let mut spec = selection_symmetric::introduced();
    spec.key.label = if mac {
        "dual-cbc-mac"
    } else {
        "dual-cbc-cipher"
    }
    .into();
    spec.key.id = vec![if mac { 2 } else { 1 }];
    // Session objects disappear when their creating session is explicitly
    // closed, including a refusal while the authentication operation is active.
    spec.key.persistent = false;
    if mac {
        spec.key.algorithm = SymmetricAlgorithm::HmacSha256 { key_length: 32 };
        spec.key.hmac_key_type = Some(HmacKeyType::Generic);
        spec.key.usages = KeyUsageRequest {
            sign: Some(true),
            verify: Some(true),
            ..KeyUsageRequest::omitted()
        };
        spec.key.admission.observation.encrypt = false;
        spec.key.admission.observation.decrypt = false;
        spec.key.admission.observation.sign = true;
        spec.key.admission.observation.verify = true;
    }
    spec
}
fn import(
    session: &Session,
    bytes: &[u8],
    mac: bool,
    created: &mut Vec<CreatedObjectSet>,
) -> std::result::Result<SymmetricKey, Failure> {
    let mut secret = SecretBytes::new(bytes.len())?;
    secret.as_mut_slice().copy_from_slice(bytes);
    let result = session.import_symmetric_key(specification(mac), secret)?;
    created.push(result.objects);
    if result.remainder.is_some() {
        return Err(Failure::Oracle("dual_import_remainder"));
    }
    result.observation?;
    Ok(session.find_symmetric_key(specification(mac).key)?)
}
fn start(
    session: &AdvancedSession,
    case: &Case,
    key: &SymmetricKey,
    mac: Option<&SymmetricKey>,
) -> std::result::Result<OperationTicket, Failure> {
    let cipher = DualCipher::Cbc { iv: case.iv };
    let parts = [case.input.as_slice()];
    let limits = InputLimits {
        maximum_parts: 1,
        // Dual operations retain the IV and, for Sign/Verify, the MAC context
        // alongside the input. Include these in the caller's explicit budget.
        maximum_total_bytes: case.input.len()
            + case.iv.len()
            + if case.uses_mac() { 32 } else { 0 },
    };
    let value = match case.route.as_str() {
        "digest_encrypt" => session.digest_encrypt(key, cipher, &parts, limits),
        "decrypt_digest" => session.decrypt_digest(key, cipher, &parts, limits),
        "digest_encrypt_with_hash" => {
            session.digest_encrypt_with_hash(key, HashAlgorithm::Sha256, cipher, &parts, limits)
        }
        "decrypt_digest_with_hash" => {
            session.decrypt_digest_with_hash(key, HashAlgorithm::Sha256, cipher, &parts, limits)
        }
        "sign_encrypt" => session.sign_encrypt(
            key,
            mac.ok_or(Failure::Input("dual_mac_owner"))?,
            cipher,
            &parts,
            limits,
        ),
        "decrypt_verify" => session.decrypt_verify(
            key,
            mac.ok_or(Failure::Input("dual_mac_owner"))?,
            cipher,
            &parts,
            &case.mac,
            limits,
        ),
        "sign_encrypt_with_mac" => session.sign_encrypt_with_mac(
            key,
            mac.ok_or(Failure::Input("dual_mac_owner"))?,
            cipher,
            &parts,
            limits,
        ),
        "decrypt_verify_with_mac" => session.decrypt_verify_with_mac(
            key,
            mac.ok_or(Failure::Input("dual_mac_owner"))?,
            cipher,
            &parts,
            &case.mac,
            limits,
        ),
        _ => return Err(Failure::Input("dual_route")),
    };
    Ok(value?)
}

pub fn execute<W: Write>(
    module: Module,
    config: &Configuration,
    path: &Path,
    pins: &Credentials,
    mut report: Report<W>,
) -> io::Result<bool> {
    let mut first = None;
    let mut preparing = None;
    let mut subject = None;
    let mut created = Vec::new();
    let mut digest = None;
    let mut ticket = None;
    let mut logged = false;
    let mut closed = false;
    let setup = (|| -> std::result::Result<_, Failure> {
        let case = Case::read(path)?;
        let identity = select_token(&module, &config.label).ok_or(Failure::Input("dual_token"))?;
        let context = module.select(&identity)?;
        first = Some(context.open_session(true)?);
        let a = first.as_ref().ok_or(Failure::Input("dual_first_session"))?;
        a.login_as(LoginRole::User, SecretPin::new(pins.user.to_vec()))?;
        logged = true;
        digest = Some(a.digest_native_single(
            NativeDigestAlgorithm::Sha256,
            b"abc",
            InputLimits {
                maximum_parts: 1,
                maximum_total_bytes: 3,
            },
        )?);
        if digest
            .as_ref()
            .ok_or(Failure::Input("dual_owned_digest"))?
            .as_bytes()
            != case.digest
        {
            return Err(Failure::Oracle("dual_independent_digest"));
        }
        preparing = Some(context.open_session(true)?);
        let b = preparing
            .as_ref()
            .ok_or(Failure::Input("dual_preparing_session"))?;
        let key = import(b, &case.key, false, &mut created)?;
        let mac = if case.uses_mac() {
            Some(import(b, &case.mac_key, true, &mut created)?)
        } else {
            None
        };
        let b = preparing
            .take()
            .ok_or(Failure::Input("dual_preparing_session"))?;
        subject = Some(b.into_advanced()?);
        subject
            .as_mut()
            .ok_or(Failure::Input("dual_subject"))?
            .set_pacing(OperationPacing::Cooperative)?;
        Ok((case, key, mac))
    })();
    let mut body = match &setup {
        Err(_) => Ok(()),
        Ok((case, key, mac)) => (|| -> std::result::Result<(), Failure> {
            let b = subject.as_ref().ok_or(Failure::Input("dual_subject"))?;
            let mut counts = module.call_counts()?;
            ticket = Some(start(b, case, key, mac.as_ref())?);
            *counts.entry(case.auth_function()).or_default() += 1;
            if module.call_counts()? != counts {
                return Err(Failure::Oracle("dual_first_init_order"));
            }
            let t = ticket.as_mut().ok_or(Failure::Input("dual_ticket"))?;
            if b.next_native_function(t)? != Some(case.cipher_function()) {
                return Err(Failure::Oracle("dual_next_cipher_init"));
            }
            match b.poll(t) {
                Err(error @ Error::Native { function, code, .. })
                    if function == case.cipher_function()
                        && code == fe11_sys::CKR_OPERATION_ACTIVE as u64 =>
                {
                    outcome::record(&mut report, Phase::Body, &Failure::Product(error))
                        .map_err(|_| Failure::Input("report_write"))?;
                }
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(Failure::Oracle("dual_second_init_expected_refusal")),
            }
            *counts.entry(case.cipher_function()).or_default() += 1;
            if module.call_counts()? != counts {
                return Err(Failure::Oracle("dual_no_update_after_refusal"));
            }
            match b.close()? {
                AdvancedCloseStatus::Complete => closed = true,
                AdvancedCloseStatus::Pending => return Err(Failure::Oracle("dual_close_pending")),
            }
            if digest
                .as_ref()
                .ok_or(Failure::Input("dual_owned_digest"))?
                .as_bytes()
                != case.digest
            {
                return Err(Failure::Oracle("dual_completed_digest_changed"));
            }
            Ok(())
        })(),
    };
    let mut cleanup = Vec::new();
    if let Some(b) = &subject {
        if !closed {
            match b.close() {
                Ok(AdvancedCloseStatus::Complete) => (),
                Ok(AdvancedCloseStatus::Pending) => {
                    cleanup.push(Failure::Oracle("dual_cleanup_pending"))
                }
                Err(error) => cleanup.push(error.into()),
            }
        }
    }
    if let Some(b) = &preparing {
        if let Err(error) = b.close() {
            cleanup.push(error.into());
        }
    }
    drop(ticket);
    drop(subject);
    drop(preparing);
    drop(created);
    if let Some(a) = &first {
        if logged {
            if let Err(error) = a.logout() {
                cleanup.push(error.into());
            }
        }
        if let Err(error) = a.close() {
            cleanup.push(error.into());
        }
    }
    drop(first);
    if let Err(error) = module.close() {
        cleanup.push(error.into());
    }
    if let (Ok((case, _, _)), Some(value)) = (&setup, &digest) {
        if value.as_bytes() != case.digest {
            body = Err(Failure::Oracle("dual_digest_after_module_close"));
        }
    }
    module_controls::finish(report, setup.map(|_| ()), body, cleanup)
}
