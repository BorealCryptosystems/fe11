// SPDX-License-Identifier: Apache-2.0
//! Classic CCM absence is observed with a real AES key and valid parameters.
use super::super::{
    object_owner::Owner,
    outcome::{self, Failure},
    report::{Phase, Producer, Report},
    single_key_case::SingleKeyCase,
};
use fe11::*;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

pub(super) fn selected(path: &Path) -> bool {
    let mut prefix = [0; 9];
    File::open(path)
        .and_then(|mut file| file.read_exact(&mut prefix))
        .is_ok()
        && &prefix == b"ccm-init\n"
}
pub(super) struct Case {
    advanced: bool,
}
impl SingleKeyCase for Case {
    const ASSERTION: &'static str = "ccm_valid_parameters_native_absence";
    const PRODUCER: Producer = Producer::TestOracle;
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("ccm_init_open"))?
            .take(33)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Input("ccm_init_read"))?;
        match bytes.as_slice() {
            b"ccm-init\nsession\n" => Ok(Self { advanced: false }),
            b"ccm-init\nadvanced\n" => Ok(Self { advanced: true }),
            _ => Err(Failure::Input("ccm_init_fixture")),
        }
    }
    fn advanced(&self) -> bool {
        self.advanced
    }
    fn bind_module(&mut self, module: &Module) -> std::result::Result<(), Failure> {
        for slot in module.slot_ids(true)? {
            if module
                .mechanism_ids(slot)?
                .contains(&(fe11_sys::CKM_AES_CCM as u64))
            {
                return Err(Failure::Oracle("ccm_unexpectedly_advertised"));
            }
        }
        Ok(())
    }
    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        Ok(owner.import_secret(
            &[0; 16],
            fe11_sys::CKK_AES,
            [StandardAttribute::ENCRYPT, StandardAttribute::DECRYPT],
        )?)
    }
    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        let parameters = ClassicAeadParameters::Ccm {
            nonce: &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
            aad: &[],
            mac_length: 16,
        };
        let result = match owner {
            Owner::Session(session) => session
                .encrypt_classic_aead(
                    key,
                    parameters,
                    MessageRoute::Single,
                    &[&[0]],
                    InputLimits {
                        maximum_parts: 1,
                        maximum_total_bytes: 1,
                    },
                )
                .map(|_| ()),
            Owner::Advanced(session) => session
                .begin_encrypt_classic_aead_stream(
                    key,
                    parameters,
                    Some(1),
                    CipherOutputPlan::Buffer { capacity: 17 },
                )
                .map(|_| ()),
        };
        match result {
            Err(
                error @ Error::Native {
                    function: "C_EncryptInit",
                    code: 112,
                    ..
                },
            ) => {
                outcome::record(report, Phase::Body, &Failure::Product(error))
                    .map_err(|_| Failure::Input("report_write"))?;
                Ok(())
            }
            Err(error) => Err(error.into()),
            Ok(()) => Err(Failure::Oracle("ccm_unexpected_native_acceptance")),
        }
    }
}
