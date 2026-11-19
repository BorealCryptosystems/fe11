// SPDX-License-Identifier: Apache-2.0
use fe11::CipherParameters;
pub fn contract() {
    let _ = CipherParameters::DesCbcPad { iv: [0u8; 9] };
}
