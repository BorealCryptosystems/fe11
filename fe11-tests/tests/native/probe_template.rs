// SPDX-License-Identifier: Apache-2.0
//! Owned input attributes for direct recipe probes; descriptors never escape a call.
use super::outcome::Failure;
use fe11_sys::*;
use std::mem::size_of;
use zeroize::Zeroizing;

enum Value {
    Boolean(CK_BBOOL),
    Unsigned(CK_ULONG),
    Bytes(Zeroizing<Vec<u8>>),
}

pub(super) struct Template(Vec<(CK_ATTRIBUTE_TYPE, Value)>);

impl Template {
    pub fn new() -> Self {
        Self(Vec::new())
    }
    pub fn boolean(mut self, name: CK_ATTRIBUTE_TYPE, value: bool) -> Self {
        self.0
            .push((name, Value::Boolean(if value { CK_TRUE } else { CK_FALSE })));
        self
    }
    pub fn unsigned(mut self, name: CK_ATTRIBUTE_TYPE, value: CK_ULONG) -> Self {
        self.0.push((name, Value::Unsigned(value)));
        self
    }
    pub fn bytes(mut self, name: CK_ATTRIBUTE_TYPE, value: &[u8]) -> Self {
        self.0
            .push((name, Value::Bytes(Zeroizing::new(value.to_vec()))));
        self
    }
    pub fn with_native<T>(
        &mut self,
        call: impl FnOnce(&mut [CK_ATTRIBUTE]) -> Result<T, Failure>,
    ) -> Result<T, Failure> {
        if self.0.len() > 64 {
            return Err(Failure::Input("probe_template_count"));
        }
        let mut attributes = Vec::with_capacity(self.0.len());
        for (name, value) in &mut self.0 {
            let (pointer, size) = match value {
                Value::Boolean(value) => ((value as *mut CK_BBOOL).cast(), size_of::<CK_BBOOL>()),
                Value::Unsigned(value) => ((value as *mut CK_ULONG).cast(), size_of::<CK_ULONG>()),
                Value::Bytes(value) => (value.as_mut_ptr().cast(), value.len()),
            };
            let size =
                CK_ULONG::try_from(size).map_err(|_| Failure::Input("probe_attribute_length"))?;
            attributes.push(CK_ATTRIBUTE {
                r#type: *name,
                pValue: pointer,
                ulValueLen: size,
            });
        }
        // The backing values remain immutably located and exclusively borrowed
        // throughout the synchronous call. No descriptor is returned to a caller.
        call(&mut attributes)
    }
}
