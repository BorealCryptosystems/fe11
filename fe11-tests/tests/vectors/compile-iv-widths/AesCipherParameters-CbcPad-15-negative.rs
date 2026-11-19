// SPDX-License-Identifier: Apache-2.0
use fe11::AesCipherParameters;
pub fn contract() {
    let _ = AesCipherParameters::CbcPad { iv: [0u8; 15] };
}
