// SPDX-License-Identifier: Apache-2.0
pub fn check() {
    let value;
    { let bytes = [0u8; 1];
      value = fe11::OaepParams { hash: 0, mgf: 0, label: &bytes }; }
    std::hint::black_box(value);
}
