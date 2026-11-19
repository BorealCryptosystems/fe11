// SPDX-License-Identifier: Apache-2.0
pub fn check() {
    let bytes = [0u8; 1];
    let value = fe11::OaepParams { hash: 0, mgf: 0, label: &bytes };
    std::hint::black_box(value);
}
