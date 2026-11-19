// SPDX-License-Identifier: Apache-2.0
pub fn check(value: &fe11::DetachedOperationRecord) {
    std::hint::black_box(value.as_bytes());
}
