// SPDX-License-Identifier: Apache-2.0
pub fn consume(_: fe11::SecretBytes) {}
pub fn check(value: fe11::SecretBytes) {
    consume(value);
    consume(value);
}
