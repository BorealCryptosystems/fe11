// SPDX-License-Identifier: Apache-2.0
//! Complete non-null functions for one synchronous Init/use sequence.

/// The single-part and multipart routes have mutually exclusive requirements.
/// Construction resolves only the chosen route, before Init or any ownership
/// transition that can imply native effects. Copying function addresses does not
/// extend the loaded module lifetime; the enclosing session frame retains it.
#[derive(Clone, Copy)]
pub(super) enum Route<Single, Update, Final> {
    Single(Single),
    Multipart { update: Update, finish: Final },
}
