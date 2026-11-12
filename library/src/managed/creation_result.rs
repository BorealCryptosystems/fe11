// SPDX-License-Identifier: Apache-2.0
//! Native success and optional description are separate outcomes.
use super::*;

/// A native object and its optional descriptive view. The generic reference is
/// usable without readable CKA_CLASS, CKA_KEY_TYPE or visibility attributes.
pub struct NativeObjectView {
    native: NativeObjectRef,
    description: Option<ManagedObjectRef>,
}
impl NativeObjectView {
    /// Borrow the original native reference, without querying the module.
    pub fn native(&self) -> &NativeObjectRef {
        &self.native
    }
    /// Metadata obtained by an explicitly requested successful observation.
    pub fn description(&self) -> Option<&ManagedObjectRef> {
        self.description.as_ref()
    }
    pub(crate) fn unobserved(native: NativeObjectRef) -> Self {
        Self {
            native,
            description: None,
        }
    }
    pub(crate) fn described(description: ManagedObjectRef) -> Self {
        Self {
            native: description.native_object(),
            description: Some(description),
        }
    }
}
impl std::ops::Deref for NativeObjectView {
    type Target = NativeObjectRef;
    fn deref(&self) -> &Self::Target {
        &self.native
    }
}

/// A completed native creation retains every returned object even when a later
/// attribute read or typed conversion fails. The outer operation's `Result`
/// describes dispatch; `observation` describes the requested descriptive view.
#[must_use = "inspect the observation and retain or explicitly destroy the created objects"]
pub struct CreatedObjects<T> {
    /// Returned native objects, in native output-slot order (absent slots omit
    /// their entry). These references share the quota of any successful views.
    pub objects: CreatedObjectSet,
    /// Optional descriptive work. An error here never authorizes creation replay.
    pub observation: Result<T>,
    /// Native auxiliary values retained when descriptive work could not finish.
    pub remainder: Option<CreationRemainder>,
}

impl<T> CreatedObjects<T> {
    /// Extract the descriptive view. Failure retains the native objects and
    /// auxiliary values, so callers can inspect or explicitly destroy them.
    pub fn into_observation(self) -> std::result::Result<T, CreationObservationFailure> {
        match self.observation {
            Ok(value) => Ok(value),
            Err(cause) => Err(CreationObservationFailure {
                cause,
                objects: self.objects,
                remainder: self.remainder,
            }),
        }
    }
    /// Convert the descriptive view while retaining every native object on error.
    pub fn try_map<U>(self, map: impl FnOnce(T) -> Result<U>) -> CreatedObjects<U> {
        CreatedObjects {
            objects: self.objects,
            observation: self.observation.and_then(map),
            remainder: self.remainder,
        }
    }
    /// Transform a successful descriptive result without losing native owners.
    pub fn map<U>(self, map: impl FnOnce(T) -> U) -> CreatedObjects<U> {
        CreatedObjects {
            objects: self.objects,
            observation: self.observation.map(map),
            remainder: self.remainder,
        }
    }

    pub(crate) fn without_objects(observation: Result<T>) -> Self {
        Self {
            objects: CreatedObjectSet(Storage::Empty),
            observation,
            remainder: None,
        }
    }
}

/// A failed description of a successful creation, retaining every native owner.
/// Formatting includes the error and object count, never key material or handles.
pub struct CreationObservationFailure {
    /// The independent observation or conversion failure.
    pub cause: Error,
    /// Objects created before that failure.
    pub objects: CreatedObjectSet,
    /// Valid auxiliary native output, if any.
    pub remainder: Option<CreationRemainder>,
}
impl std::fmt::Debug for CreationObservationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreationObservationFailure")
            .field("cause", &self.cause)
            .field("objects", &self.objects.as_slice().len())
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for CreationObservationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "native creation completed ({} objects); observation failed: {}",
            self.objects.as_slice().len(),
            self.cause
        )
    }
}
impl std::error::Error for CreationObservationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

/// The output vector and its allocation credit have the same lifetime. Cloning
/// an individual reference shares the existing native identity and quota.
pub struct CreatedObjectSet(Storage);
enum Storage {
    Empty,
    Single(NativeObjectRef),
    Pair([NativeObjectRef; 2]),
    Multiple {
        objects: Vec<NativeObjectRef>,
        _credit: Option<crate::symmetric::memory::Credit>,
    },
}
impl CreatedObjectSet {
    /// All returned objects in output-slot order. No native call is made.
    pub fn as_slice(&self) -> &[NativeObjectRef] {
        match &self.0 {
            Storage::Empty => &[],
            Storage::Single(object) => std::slice::from_ref(object),
            Storage::Pair(objects) => objects,
            Storage::Multiple { objects, .. } => objects,
        }
    }
    pub(crate) fn one(object: NativeObjectRef) -> Self {
        Self(Storage::Single(object))
    }
    pub(crate) fn pair(objects: [NativeObjectRef; 2]) -> Self {
        Self(Storage::Pair(objects))
    }
    pub(crate) fn many(
        objects: Vec<NativeObjectRef>,
        credit: Option<crate::symmetric::memory::Credit>,
    ) -> Self {
        Self(Storage::Multiple {
            objects,
            _credit: credit,
        })
    }
}

/// Owns valid native auxiliary output after an independent observation failure.
/// Parameter storage and secret buffers retain their original erasing owners.
pub struct CreationRemainder {
    output: Remainder,
}

enum Remainder {
    Native(mutations::outputs::Output),
    Ciphertext(crate::symmetric::memory::Buffer),
}
impl CreationRemainder {
    pub(in crate::managed) fn native(output: mutations::outputs::Output) -> Self {
        Self {
            output: Remainder::Native(output),
        }
    }
    pub(crate) fn ciphertext_buffer(bytes: crate::symmetric::memory::Buffer) -> Self {
        Self {
            output: Remainder::Ciphertext(bytes),
        }
    }

    /// Auxiliary generation result; no retry or observation is performed.
    pub fn generation_output(&self) -> Option<&Result<crate::NativeGenerationOutput>> {
        match &self.output {
            Remainder::Native(
                mutations::outputs::Output::Key { value, .. }
                | mutations::outputs::Output::Pair { value, .. },
            ) => Some(value),
            _ => None,
        }
    }
    /// Native derivation output, such as TLS version bytes.
    pub fn derivation_output(&self) -> Option<&crate::NativeDerivationOutput> {
        match &self.output {
            Remainder::Native(mutations::outputs::Output::Derived { value, .. }) => Some(value),
            _ => None,
        }
    }
    /// KEA randoms returned by the completed native call.
    pub fn kea_randoms(&self) -> Option<&crate::KeaRandoms> {
        match &self.output {
            Remainder::Native(mutations::outputs::Output::Kea { randoms, .. }) => Some(randoms),
            _ => None,
        }
    }
    /// KEM ciphertext, if that call returned one.
    pub fn ciphertext(&self) -> Option<&[u8]> {
        match &self.output {
            Remainder::Ciphertext(bytes) => Some(bytes.as_slice()),
            Remainder::Native(mutations::outputs::Output::Transport {
                value: Ok(value), ..
            }) => value.ciphertext.as_ref().map(|buffer| buffer.as_slice()),
            _ => None,
        }
    }
    /// Native output embedded in the caller-selected parameter graph.
    pub fn parameter_output(&self, index: usize) -> Option<&[u8]> {
        match &self.output {
            Remainder::Native(mutations::outputs::Output::Transport {
                value: Ok(value), ..
            }) => value.parameters.output(index),
            _ => None,
        }
    }
    /// TLS client/server IVs, retained independently of key metadata reads.
    pub fn tls_ivs(&self) -> Option<(&[u8], &[u8])> {
        match &self.output {
            Remainder::Native(mutations::outputs::Output::Tls { data, .. }) => data.tls_ivs(),
            _ => None,
        }
    }
    /// WTLS IV, retained independently of key metadata reads.
    pub fn wtls_iv(&self) -> Option<&[u8]> {
        match &self.output {
            Remainder::Native(mutations::outputs::Output::Tls { data, .. }) => data.wtls_iv(),
            _ => None,
        }
    }
}
