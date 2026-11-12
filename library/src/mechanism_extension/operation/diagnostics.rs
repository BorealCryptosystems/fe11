// SPDX-License-Identifier: Apache-2.0
//! Stack-owned diagnostics for the one route selected by an extension invocation.
//! The outer public method owns this enum. Routing selects a single variant before
//! dispatch; nested helpers borrow it and never detach its credits on return.
use crate::advanced::{cipher, digest, signature};

#[derive(Default)]
pub(crate) enum Invocation {
    #[default]
    Unselected,
    Digest(digest::batch::Invocation),
    Cipher(cipher::batch::Invocation),
    Signature(signature::batch::Invocation),
    Native(super::Diagnostics),
}

impl Invocation {
    // A route is selected once, before its startup can allocate or dispatch.
    pub(super) fn digest(&mut self) -> &mut digest::batch::Invocation {
        *self = Self::Digest(Default::default());
        let Self::Digest(root) = self else {
            unreachable!()
        };
        root
    }

    pub(super) fn cipher(&mut self) -> &mut cipher::batch::Invocation {
        *self = Self::Cipher(Default::default());
        let Self::Cipher(root) = self else {
            unreachable!()
        };
        root
    }

    pub(super) fn signature(&mut self) -> &mut signature::batch::Invocation {
        *self = Self::Signature(Default::default());
        let Self::Signature(root) = self else {
            unreachable!()
        };
        root
    }

    pub(super) fn native(&mut self, prepared: super::Diagnostics) -> &mut super::Diagnostics {
        *self = Self::Native(prepared);
        let Self::Native(root) = self else {
            unreachable!()
        };
        root
    }
}
