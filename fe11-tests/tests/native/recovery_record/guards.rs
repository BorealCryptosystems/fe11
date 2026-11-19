// SPDX-License-Identifier: Apache-2.0
//! Recovery refusal must leave an unrelated destination operation intact.
use super::*;

impl Fixture {
    pub(super) fn guard(
        &mut self,
        module: &Module,
        config: &Configuration,
        active: bool,
    ) -> std::result::Result<(), Failure> {
        require(self.old_closed, "recovery_guard_old_executor_live")?;
        let token =
            select_token(module, &config.label).ok_or(Failure::Input("recovery_guard_token"))?;
        let session = module.select(&token)?.open_session(true)?;
        let key = session.find_aes_key(Self::spec())?;
        let mac = if active {
            None
        } else {
            let mut spec = selection_symmetric::introduced();
            spec.key.algorithm = SymmetricAlgorithm::HmacSha256 { key_length: 32 };
            spec.key.hmac_key_type = Some(HmacKeyType::Generic);
            spec.key.usages = KeyUsageRequest {
                sign: Some(true),
                verify: Some(true),
                ..KeyUsageRequest::omitted()
            };
            spec.key.persistent = true;
            spec.key.id = vec![9, 8, 7, 6];
            spec.key.label = "recovery-guard-mac".into();
            let imported = self
                .admin()?
                .import_symmetric_key(spec, SecretBytes::new(32)?)?;
            self.guard_created = Some(imported.objects);
            require(imported.remainder.is_none(), "recovery_guard_mac_remainder")?;
            imported.observation?;
            let mut spec = selection_symmetric::key(false);
            spec.algorithm = SymmetricAlgorithm::HmacSha256 { key_length: 32 };
            spec.hmac_key_type = Some(HmacKeyType::Generic);
            spec.persistent = true;
            spec.id = vec![9, 8, 7, 6];
            spec.label = "recovery-guard-mac".into();
            Some(self.admin()?.find_symmetric_key(spec)?)
        };
        self.new = Some(session.into_advanced()?);
        let new = self
            .new
            .as_ref()
            .ok_or(Failure::Input("recovery_guard_destination"))?;
        if active {
            self.new_ticket = Some(new.begin_digest(HashAlgorithm::Sha256)?);
        }
        let before = module.call_counts()?;
        let record = self
            .authenticated
            .take()
            .ok_or(Failure::Input("recovery_guard_record"))?;
        let result = new.start_dual_gcm_recovery(record, &key, mac.as_ref());
        match result {
            Err(Error::Busy(BusyReason::CombinedOperations(
                CombinedOperationsBusy::RecoveryDestinationActive,
            ))) if active => (),
            Err(Error::Rejected(RejectionReason::CombinedOperations(
                CombinedOperationsRejection::DualRecoveryKeyRoles,
            ))) if !active => (),
            Err(error) => return Err(error.into()),
            Ok(ticket) => {
                self.new_ticket = Some(ticket);
                return Err(Failure::Oracle("recovery_guard_accepted"));
            }
        }
        require(module.call_counts()? == before, "recovery_guard_dispatched")?;
        if active {
            let ticket = self
                .new_ticket
                .as_mut()
                .ok_or(Failure::Input("recovery_guard_digest"))?;
            new.digest_update(
                ticket,
                b"abc",
                InputLimits {
                    maximum_parts: 1,
                    maximum_total_bytes: 3,
                },
            )?;
            let OperationProgress::Digest(value) = new.finish_digest(ticket)? else {
                return Err(Failure::Oracle("recovery_guard_digest_publication"));
            };
            let expected = hex(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                32,
            )
            .map_err(Failure::Input)?;
            require(
                value.as_bytes() == expected,
                "recovery_guard_digest_changed",
            )?;
        }
        Ok(())
    }
}
