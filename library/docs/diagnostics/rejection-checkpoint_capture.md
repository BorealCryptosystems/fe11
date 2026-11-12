Cause contracts for `CheckpointCaptureRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-AeadStreamCaptureAccounting"></a>

### `AeadStreamCaptureAccounting`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/capture_preparation/aead_stream.rs`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/aead_stream.rs`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/aead_stream.rs`. Enclosing match alternative: `Materialized::Retry(actual)`.


<a id="cause-AeadStreamCaptureCapacity"></a>

### `AeadStreamCaptureCapacity`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/capture_preparation/aead_stream.rs`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/aead_stream.rs`.


<a id="cause-AeadStreamCaptureOwnerChanged"></a>

### `AeadStreamCaptureOwnerChanged`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/capture_preparation/aead_stream.rs`.


<a id="cause-AeadStreamValidationShapeChanged"></a>

### `AeadStreamValidationShapeChanged`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/capture_preparation/aead_stream.rs`. Enclosing match alternative: `_`.


<a id="cause-CipherCaptureParametersAbsent"></a>

### `CipherCaptureParametersAbsent`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/capture_preparation/cipher.rs`. Enclosing match alternative: `None`.


<a id="cause-CipherGraphPacketAccounting"></a>

### `CipherGraphPacketAccounting`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/capture_preparation/cipher.rs`. Enclosing match alternative: `None`.
- `CipherOperation::snapshot_shape` — `src/advanced/cipher/snapshot.rs`.


<a id="cause-CipherSnapshotShapeChanged"></a>

### `CipherSnapshotShapeChanged`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/capture_preparation/cipher.rs`. Enclosing true branch: `shape != planned`.
- `Request<'a>::allocate` — `src/advanced/cipher/snapshot.rs`. Enclosing true branch: `parts.len() != self.shape.fragments`.
- `Request<'a>::allocate_record` — `src/advanced/cipher/snapshot.rs`. Enclosing true branch: `fragments.len() != self.shape.fragments`.
- `Shape::allocate` — `src/advanced/cipher/snapshot.rs`. Enclosing true branch: `layout.len() != 1 || sizes.len() != self.parts || fragments.len() != self.fragments`.
- `PreparedSnapshot::fill_parts` — `src/advanced/cipher/snapshot.rs`. Enclosing true branch: `count != self.shape.fragments`.
- `PreparedSnapshot::fill_parts` — `src/advanced/cipher/snapshot.rs`. Enclosing true branch: `observed == count`.
- `PreparedSnapshot::fill_parts` — `src/advanced/cipher/snapshot.rs`.
- `PreparedSnapshot::fill_parts` — `src/advanced/cipher/snapshot.rs`. Enclosing true branch: `self.shape.route == MessageRoute::Multipart`.
- `PreparedSnapshot::fill_parts` — `src/advanced/cipher/snapshot.rs`. Enclosing true branch: `target.as_slice().len() != part.len()`.
- `PreparedSnapshot::fill_parts` — `src/advanced/cipher/snapshot.rs`. Enclosing true branch: `observed != count || offset != self.frame.expected.as_slice().len()`.
- `PreparedSnapshot::copy_from` — `src/advanced/cipher/snapshot.rs`. Enclosing true branch: `self.shape != source.snapshot_shape(entry)?`.


<a id="cause-DigestExtensionCaptureAccounting"></a>

### `DigestExtensionCaptureAccounting`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/capture_preparation/digest_extension.rs`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/digest_extension.rs`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/digest_extension.rs`. Enclosing match alternative: `Materialized::Retry(actual)`.


<a id="cause-DigestExtensionCaptureCapacity"></a>

### `DigestExtensionCaptureCapacity`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/capture_preparation/digest_extension.rs`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/digest_extension.rs`.


<a id="cause-DigestExtensionCaptureOwnerChanged"></a>

### `DigestExtensionCaptureOwnerChanged`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/capture_preparation/digest_extension.rs`.


<a id="cause-DigestExtensionValidationShapeChanged"></a>

### `DigestExtensionValidationShapeChanged`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/capture_preparation/digest_extension.rs`. Enclosing match alternative: `_`.


<a id="cause-DigestNotCapturable"></a>

### `DigestNotCapturable`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/capture_preparation/digest.rs`. Enclosing true branch: `!matches!( source.step, Step::Single | Step::Update(_) | Step::Final | Step::OutputRequired { .. } )`.


<a id="cause-DigestSnapshotOidShapeChanged"></a>

### `DigestSnapshotOidShapeChanged`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/capture_preparation/digest.rs`. Enclosing match alternative: `_`.


<a id="cause-DigestSnapshotShapeChanged"></a>

### `DigestSnapshotShapeChanged`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/capture_preparation/digest.rs`. Enclosing true branch: `frame.parts.len() != source.frame.parts.len()`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/digest.rs`. Enclosing true branch: `shape.count != source.frame.parts.len()`.


<a id="cause-DualSnapshotShapeChanged"></a>

### `DualSnapshotShapeChanged`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/capture_preparation/dual.rs`. Enclosing true branch: `shape != planned`.
- `Shape::allocate_request` — `src/advanced/dual/snapshot.rs`. Enclosing true branch: `parts.len() != self.fragments`.
- `Shape::allocate` — `src/advanced/dual/snapshot.rs`. Enclosing true branch: `layout.len() != 1 || sizes.len() != self.parts || fragments.len() != self.fragments`.
- `PreparedSnapshot::fill_request` — `src/advanced/dual/snapshot.rs`. Enclosing true branch: `self.body.inputs.len() != parts.len()`.
- `PreparedSnapshot::fill_request` — `src/advanced/dual/snapshot.rs`. Enclosing true branch: `target.as_slice().len() != source.len()`.
- `PreparedSnapshot::copy_from` — `src/advanced/dual/snapshot.rs`. Enclosing true branch: `self.shape != source.snapshot_shape(entry)?`.
- `RecordPlan<'a>::bind` — `src/advanced/dual/snapshot/record_plan.rs`.
- `RecordPlan<'a>::bind` — `src/advanced/dual/snapshot/record_plan.rs`. Enclosing true branch: `target.as_slice().len() != source.len()`.


<a id="cause-GenericMessageCaptureAccounting"></a>

### `GenericMessageCaptureAccounting`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/capture_preparation/native_messages.rs`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/native_messages.rs`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/native_messages.rs`. Enclosing match alternative: `Materialized::Retry(actual)`.


<a id="cause-GenericMessageCaptureCapacity"></a>

### `GenericMessageCaptureCapacity`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/capture_preparation/native_messages.rs`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/native_messages.rs`.


<a id="cause-GenericMessageCaptureOwnerChanged"></a>

### `GenericMessageCaptureOwnerChanged`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/capture_preparation/native_messages.rs`.


<a id="cause-GenericMessageValidationShapeChanged"></a>

### `GenericMessageValidationShapeChanged`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/capture_preparation/native_messages.rs`. Enclosing match alternative: `_`.


<a id="cause-MessageSnapshotShapeChanged"></a>

### `MessageSnapshotShapeChanged`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/capture_preparation/messages.rs`. Enclosing true branch: `shape != planned`.
- `MacOperation::snapshot_shape` — `src/advanced/messages/snapshot.rs`. Enclosing true branch: `self.inputs.len() != self.layouts.len() || self.inputs.len() != self.lengths.len() || self.inputs.len() != outputs.len() || self.inputs.len() != self .signatures .as_ref() .expect("checked results") .rejections .len()`.
- `MacOperation::describe_snapshot` — `src/advanced/messages/snapshot.rs`. Enclosing true branch: `self.inputs.len() != self.layouts.len() || self.inputs.len() != outputs.len()`.
- `Shape::allocate_request` — `src/advanced/messages/snapshot.rs`. Enclosing true branch: `messages.len() != self.rows || expected.is_some() != self.verify || expected.is_some_and(|values| values.len() != self.rows)`.
- `PreparedSnapshot::fill_request` — `src/advanced/messages/snapshot.rs`. Enclosing true branch: `messages.len() != self.shape.rows || expected.is_some() != self.shape.verify || expected.is_some_and(|values| values.len() != self.shape.rows)`.
- `PreparedSnapshot::fill_request` — `src/advanced/messages/snapshot.rs`. Enclosing true branch: `self.shape.route == MessageRoute::Single`.
- `PreparedSnapshot::fill_request` — `src/advanced/messages/snapshot.rs`. Enclosing true branch: `offset != destination[0].as_slice().len()`.
- `PreparedSnapshot::fill_request` — `src/advanced/messages/snapshot.rs`. Enclosing true branch: `destination.len() != message.parts.len()`.
- `PreparedSnapshot::fill_request` — `src/advanced/messages/snapshot.rs`. Enclosing true branch: `target.as_slice().len() != part.len()`.
- `PreparedSnapshot::fill_request` — `src/advanced/messages/snapshot.rs`. Enclosing true branch: `output.as_slice().len() != source.len()`.
- `PreparedSnapshot::copy_from` — `src/advanced/messages/snapshot.rs`. Enclosing true branch: `self.shape != source.snapshot_shape(entry)?`.
- `PreparedSnapshot::copy_from` — `src/advanced/messages/snapshot.rs`. Enclosing true branch: `targets.len() != originals.len()`.
- `RecordPlan<'a>::allocate` — `src/advanced/messages/snapshot/record_plan.rs`. Enclosing true branch: `rows.len() != self.shape.rows`.
- `RecordPlan<'a>::bind` — `src/advanced/messages/snapshot/record_plan.rs`.
- `RecordPlan<'a>::bind` — `src/advanced/messages/snapshot/record_plan.rs`. Enclosing true branch: `self.shape.route == MessageRoute::Single`.
- `RecordPlan<'a>::bind` — `src/advanced/messages/snapshot/record_plan.rs`. Enclosing false branch: `self.shape.route == MessageRoute::Single`.
- `RecordPlan<'a>::bind` — `src/advanced/messages/snapshot/record_plan.rs`. Enclosing true branch: `target.as_slice().len() != part.len()`.
- `RecordPlan<'a>::bind` — `src/advanced/messages/snapshot/record_plan.rs`. Enclosing true branch: `!streaming && self.shape.route == MessageRoute::Single && offset != row[0].as_slice().len()`.
- `RecordPlan<'a>::bind` — `src/advanced/messages/snapshot/record_plan.rs`.
- `RecordPlan<'a>::bind` — `src/advanced/messages/snapshot/record_plan.rs`. Enclosing true branch: `output.as_slice().len() != expected.len()`.


<a id="cause-OperationFamilyNotCapturable"></a>

### `OperationFamilyNotCapturable`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/capture_preparation.rs`. Enclosing match alternative: `_`.


<a id="cause-RecordStorageAccounting"></a>

### `RecordStorageAccounting`


Local detection/handling phase and implementation owner:

- `copy_registered` (module-level helper) — `src/advanced/record_preparation.rs`.
- `copy_registered` (module-level helper) — `src/advanced/record_preparation.rs`.


<a id="cause-SignatureCaptureAccounting"></a>

### `SignatureCaptureAccounting`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/capture_preparation/signature.rs`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/signature.rs`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/signature.rs`. Enclosing match alternative: `Materialized::Retry(actual)`.


<a id="cause-SignatureCaptureCapacity"></a>

### `SignatureCaptureCapacity`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/capture_preparation/signature.rs`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/signature.rs`.


<a id="cause-SignatureCaptureOwnerChanged"></a>

### `SignatureCaptureOwnerChanged`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/capture_preparation/signature.rs`.


<a id="cause-SignatureValidationShapeChanged"></a>

### `SignatureValidationShapeChanged`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/advanced/capture_preparation/signature.rs`. Enclosing match alternative: `_`.


<a id="cause-SnapshotFragmentAllocation"></a>

### `SnapshotFragmentAllocation`


Local detection/handling phase and implementation owner:

- `reserve` (module-level helper) — `src/advanced/capture_parts.rs`.


<a id="cause-SnapshotFragmentCountChanged"></a>

### `SnapshotFragmentCountChanged`


Local detection/handling phase and implementation owner:

- `Layouts::push_lengths` — `src/advanced/capture_layout.rs`.
- `Storage::allocate_fallible` — `src/advanced/capture_parts.rs`. Enclosing true branch: `owned_fragments.len() == fragment_count`.
- `Storage::allocate_fallible` — `src/advanced/capture_parts.rs`. Enclosing true branch: `owned_fragments.len() != fragment_count`.


<a id="cause-SnapshotInputCountChanged"></a>

### `SnapshotInputCountChanged`


Local detection/handling phase and implementation owner:

- `Storage::allocate_fallible` — `src/advanced/capture_parts.rs`. Enclosing true branch: `parts.len() == count`.
- `Storage::allocate_fallible` — `src/advanced/capture_parts.rs`. Enclosing true branch: `parts.len() != count`.


<a id="cause-SnapshotRowAbsent"></a>

### `SnapshotRowAbsent`


Local detection/handling phase and implementation owner:

- `Layouts::row` — `src/advanced/capture_layout.rs`.


<a id="cause-SnapshotRowCountChanged"></a>

### `SnapshotRowCountChanged`


Local detection/handling phase and implementation owner:

- `Layouts::push_lengths` — `src/advanced/capture_layout.rs`.


<a id="cause-SnapshotShapeAccounting"></a>

### `SnapshotShapeAccounting`


Local detection/handling phase and implementation owner:

- `Layouts::allocation_bytes` — `src/advanced/capture_layout.rs`.
- `Layouts::push_lengths` — `src/advanced/capture_layout.rs`.
- `Layouts::push_lengths` — `src/advanced/capture_layout.rs`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/digest.rs`. Enclosing match alternative: `None`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/digest.rs`. Enclosing match alternative: `None`.


<a id="cause-SnapshotShapeAllocation"></a>

### `SnapshotShapeAllocation`


Local detection/handling phase and implementation owner:

- `Layouts::allocate` — `src/advanced/capture_layout.rs`.
- `Layouts::allocate` — `src/advanced/capture_layout.rs`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/digest.rs`. Enclosing match alternative: `None`.


<a id="cause-SnapshotShapeIncomplete"></a>

### `SnapshotShapeIncomplete`


Local detection/handling phase and implementation owner:

- `Layouts::complete` — `src/advanced/capture_layout.rs`. Enclosing true branch: `self.next_row != self.rows.len() || self.next_length != self.lengths.len()`.


<a id="cause-SnapshotStorageAccounting"></a>

### `SnapshotStorageAccounting`


Local detection/handling phase and implementation owner:

- `Storage::temporary_bytes` — `src/advanced/capture_parts.rs`.
- `Storage::input_metadata_bytes` — `src/advanced/capture_parts.rs`.
- `Storage::allocated_bytes` — `src/advanced/capture_parts.rs`.
- `Storage::allocated_bytes` — `src/advanced/capture_parts.rs`.
- `Storage::allocated_bytes` — `src/advanced/capture_parts.rs`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/aead.rs`. Enclosing match alternative: `Some(AeadCandidate::Layout { shape: planned, mut metadata, mut credit, validation_maximum, reserved, layout_bytes, })`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/aead.rs`. Enclosing match alternative: `None`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/aead.rs`. Enclosing match alternative: `None`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/cipher.rs`. Enclosing match alternative: `Some(CipherCandidate::Layout { shape: planned, mut layout, mut credit, validation_maximum, reserved, layout_bytes, mut graph, })`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/cipher.rs`. Enclosing match alternative: `None`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/cipher.rs`. Enclosing match alternative: `None`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/digest.rs`. Enclosing match alternative: `Some(Candidate::Lengths { shape, mut lengths, mut credit, shape_credit, })`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/digest.rs`. Enclosing match alternative: `None`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/digest.rs`. Enclosing match alternative: `None`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/digest.rs`. Enclosing match alternative: `None`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/dual.rs`. Enclosing match alternative: `Some(DualCandidate::Layout { shape: planned, mut layout, mut credit, validation_maximum, reserved, layout_bytes, })`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/dual.rs`. Enclosing match alternative: `None`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/dual.rs`. Enclosing match alternative: `None`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/messages.rs`. Enclosing match alternative: `Some(MacCandidate::Layout { shape: planned, mut layout, mut credit, validation_maximum, reserved, layout_bytes, })`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/messages.rs`. Enclosing match alternative: `None`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/messages.rs`. Enclosing match alternative: `None`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/recover.rs`.
- `prepare` (module-level helper) — `src/advanced/capture_preparation/recover.rs`.
