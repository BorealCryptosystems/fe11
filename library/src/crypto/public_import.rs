// SPDX-License-Identifier: Apache-2.0
//! One public template and readback contract for application imports and witnesses.
use crate::attributes::TemplateSink;

use fe11_sys::*;
pub(crate) mod observation;
pub(crate) mod publication;

// Internal callers supply structurally decoded public components; the native
// module validates their mathematical usability. Ownership,
// reservations and the outcome of CreateObject remain with those callers.


/// Keep metadata, component order and native usage requests identical for
/// borrowed components and the existing materialized import adapter.
pub(super) fn template_with<T: TemplateSink>(
    kind: CK_KEY_TYPE,
    metadata: Option<(crate::attributes::ByteParts<'_>, &[u8])>,
    options: &crate::PublicKeyImportOptions,
    public: impl FnOnce(&mut T),
) -> T {
    let mut t = T::empty();
    t.integer(CKA_CLASS, CKO_PUBLIC_KEY);
    t.integer(CKA_KEY_TYPE, kind);
    if let Some((id, label)) = metadata {
        t.byte_parts(CKA_ID, id);
        t.bytes(CKA_LABEL, label);
    }
    public(&mut t);
    for (field, value) in [
        (CKA_TOKEN, options.persistent),
        (CKA_PRIVATE, options.visibility.is_private()),
        (CKA_MODIFIABLE, options.modifiable),
        (CKA_COPYABLE, options.copyable),
        (CKA_DESTROYABLE, options.destroyable),
    ] {
        t.boolean(field, value);
    }
    options.usages.apply(&mut t);
    t
}


