// SPDX-License-Identifier: Apache-2.0
pub fn check(value: &fe11::PqcPrivateInput) {
    std::hint::black_box(value.algorithm());
}
