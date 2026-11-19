// SPDX-License-Identifier: Apache-2.0
pub fn check(value: &fe11::SecretBytes) {
    std::hint::black_box(value.as_slice());
}
