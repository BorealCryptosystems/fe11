// SPDX-License-Identifier: Apache-2.0
pub fn check(value: fe11::SecretBytes) {
    let bytes = value.as_slice();
    drop(value);
    std::hint::black_box(bytes);
}
