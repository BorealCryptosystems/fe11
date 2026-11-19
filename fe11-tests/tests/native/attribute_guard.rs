// SPDX-License-Identifier: Apache-2.0
//! A nested native attribute must not be interpreted by a flat value reader.
use super::{
    arguments::hex, object_owner::Owner, outcome::Failure, report::Report,
    single_key_case::SingleKeyCase,
};
use fe11::*;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

pub struct Nested(Vec<u8>);
impl SingleKeyCase for Nested {
    const ASSERTION: &'static str = "nested_attribute_refused_before_flat_native_read";
    const PRODUCER: super::report::Producer = super::report::Producer::TestOracle;
    fn read(path: &Path) -> std::result::Result<Self, Failure> {
        let mut data = Vec::new();
        File::open(path)
            .map_err(|_| Failure::Input("attribute_guard_open"))?
            .take(66)
            .read_to_end(&mut data)
            .map_err(|_| Failure::Input("attribute_guard_read"))?;
        if data.len() != 65 || data.last() != Some(&b'\n') {
            return Err(Failure::Input("attribute_guard_width"));
        }
        let value = std::str::from_utf8(&data[..64])
            .map_err(|_| Failure::Input("attribute_guard_encoding"))?;
        Ok(Self(hex(value, 32).map_err(Failure::Input)?))
    }
    fn advanced(&self) -> bool {
        false
    }
    fn import(&self, owner: &Owner) -> std::result::Result<NativeObjectRef, Failure> {
        Ok(owner.import_secret(
            &self.0,
            fe11_sys::CKK_GENERIC_SECRET,
            [StandardAttribute::WRAP, StandardAttribute::UNWRAP],
        )?)
    }
    fn check<W: Write>(
        &self,
        owner: &Owner,
        key: &NativeObjectRef,
        _report: &mut Report<W>,
    ) -> std::result::Result<(), Failure> {
        let Owner::Session(session) = owner else {
            return Err(Failure::Input("attribute_guard_owner"));
        };
        match session.read_flat_attribute(
            key,
            StandardAttribute::WRAP_TEMPLATE,
            FlatAttributeReadPlan::Value {
                maximum_bytes: 32768,
            },
        ) {
            Err(Error::Rejected(RejectionReason::AttributeValues(
                AttributeValuesRejection::NestedAttributeRequiresARecursiveReader,
            ))) => Ok(()),
            Err(error) => Err(error.into()),
            Ok(_) => Err(Failure::Oracle("nested_attribute_flat_read_accepted")),
        }
    }
}
