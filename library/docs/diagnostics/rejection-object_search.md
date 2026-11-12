Cause contracts for `ObjectSearchRejection`.


The [Error](crate::Error) documentation defines the common effect and recovery
contract, including typed handling. The sites below locate the check within its
actual implementation owner; they are not a claim that the complete public request
is pre-dispatch. A cause shared by several sites has no single global phase.


## Causes and local owners


<a id="cause-DiscoveryContentPublicationIncomplete"></a>

### `DiscoveryContentPublicationIncomplete`


Local detection/handling phase and implementation owner:

- `DiscoveryOwner::resume_content` — `src/managed/discovery.rs`.


<a id="cause-DiscoveryPublicationIncomplete"></a>

### `DiscoveryPublicationIncomplete`


Local detection/handling phase and implementation owner:

- `DiscoveryOwner::take_permit` — `src/managed/discovery.rs`. Enclosing true branch: `!self.complete()`.


<a id="cause-DiscoveryQuotaAlreadyTransferred"></a>

### `DiscoveryQuotaAlreadyTransferred`


Local detection/handling phase and implementation owner:

- `DiscoveryOwner::take_permit` — `src/managed/discovery.rs`.


<a id="cause-DiscoveryQuotaTransferred"></a>

### `DiscoveryQuotaTransferred`


Local detection/handling phase and implementation owner:

- `DiscoveryOwner::publish` — `src/managed/discovery.rs`.


<a id="cause-EmptySearchBatchRequiresFinalization"></a>

### `EmptySearchBatchRequiresFinalization`


Local detection/handling phase and implementation owner:

- `SearchOwner::acknowledge_stream_batch` — `src/managed/search/owned/resident.rs`. Enclosing true branch: `self.stream_batch_len()? == 0`.


<a id="cause-IntegerAttributeWidth"></a>

### `IntegerAttributeWidth`


Local detection/handling phase and implementation owner:

- `InventoryOwner::advance` — `src/managed/inventory.rs`. Enclosing match alternative: `ReadPhase::Class(read)`.


<a id="cause-InvalidSearchResultHandle"></a>

### `InvalidSearchResultHandle`


Local detection/handling phase and implementation owner:

- `SearchOwner::stream_handle` — `src/managed/search/owned/resident.rs`. Enclosing true branch: `handle == CK_INVALID_HANDLE`.


<a id="cause-InventoryByteQuota"></a>

### `InventoryByteQuota`


Local detection/handling phase and implementation owner:

- `LegacyOwner::byte_quota_error` — `src/attributes/owned/resident.rs`. Enclosing true branch: `self._protection.is_inventory()`. Selects the inventory diagnostic for a proven logical byte-quota failure.
- `LegacyOwner::projected_total` — `src/attributes/owned/resident.rs`. Calls `byte_quota_error` when `next > maximum`; selects this cause only for an inventory child.
- `LegacyOwner::advance` — `src/attributes/owned/resident.rs`. Calls `byte_quota_error` for `LengthBound` from the size query after excluding `CK_UNAVAILABLE_INFORMATION`, with an initial total of zero; selects this cause only for an inventory child.
- `InventoryOwner::advance` — `src/managed/inventory.rs`. Enclosing match alternative: `ReadPhase::Class(read)`.
- `row` (module-level helper) — `src/managed/metadata.rs`. Enclosing true branch: `let AttributeValue::Available(bytes) = value`.


<a id="cause-InventoryCandidateKind"></a>

### `InventoryCandidateKind`


Local detection/handling phase and implementation owner:

- `InventoryOwner::attach` — `src/managed/inventory.rs`. Enclosing match alternative: `_`.


<a id="cause-InventoryContinuationChanged"></a>

### `InventoryContinuationChanged`


Local detection/handling phase and implementation owner:

- `InventoryOwner::attach` — `src/managed/inventory.rs`. Enclosing true branch: `self.need()? != Some(need)`.


<a id="cause-InventoryIncomplete"></a>

### `InventoryIncomplete`


Local detection/handling phase and implementation owner:

- `InventoryOwner::result` — `src/managed/inventory.rs`.


<a id="cause-InventoryMetadataAllocation"></a>

### `InventoryMetadataAllocation`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/managed/inventory.rs`. Enclosing match alternative: `Need::Rows(count)`.


<a id="cause-InventoryMetadataPhase"></a>

### `InventoryMetadataPhase`


Local detection/handling phase and implementation owner:

- `InventoryOwner::advance` — `src/managed/inventory.rs`. Enclosing match alternative: `ReadPhase::Stopped`.


<a id="cause-InventoryMetadataSize"></a>

### `InventoryMetadataSize`


Local detection/handling phase and implementation owner:

- `row_bytes` (module-level helper) — `src/managed/inventory.rs`.


<a id="cause-InventoryOwnerAbsent"></a>

### `InventoryOwnerAbsent`


Local detection/handling phase and implementation owner:

- `observe` (module-level helper) — `src/managed/inventory.rs`.
- `observe` (module-level helper) — `src/managed/inventory.rs`.


<a id="cause-InventoryPhase"></a>

### `InventoryPhase`


Local detection/handling phase and implementation owner:

- `InventoryOwner::advance` — `src/managed/inventory.rs`. Enclosing match alternative: `Phase::Stopped`.


<a id="cause-InventoryPossessionAbsent"></a>

### `InventoryPossessionAbsent`


Local detection/handling phase and implementation owner:

- `observe` (module-level helper) — `src/managed/inventory.rs`.


<a id="cause-InventoryReadNeed"></a>

### `InventoryReadNeed`


Local detection/handling phase and implementation owner:

- `InventoryOwner::attach` — `src/managed/inventory.rs`. Enclosing match alternative: `( Phase::Metadata(metadata), Candidate::Read { storage, mut credit, }, )`.


<a id="cause-InventoryReadPhase"></a>

### `InventoryReadPhase`


Local detection/handling phase and implementation owner:

- `InventoryOwner::attach` — `src/managed/inventory.rs`. Enclosing match alternative: `_`.


<a id="cause-InventoryResourceNeedAbsent"></a>

### `InventoryResourceNeedAbsent`


Local detection/handling phase and implementation owner:

- `observe` (module-level helper) — `src/managed/inventory.rs`.


<a id="cause-InventoryRowsCapacity"></a>

### `InventoryRowsCapacity`


Local detection/handling phase and implementation owner:

- `InventoryOwner::attach` — `src/managed/inventory.rs`. Enclosing true branch: `!rows.is_empty() || !order.is_empty() || rows.capacity() < count || order.capacity() < count`.


<a id="cause-InventoryRowsNeed"></a>

### `InventoryRowsNeed`


Local detection/handling phase and implementation owner:

- `InventoryOwner::attach` — `src/managed/inventory.rs`. Enclosing match alternative: `( phase @ Phase::Rows(_), Candidate::Rows { rows, order, mut credit, }, )`.


<a id="cause-InventorySortAllocation"></a>

### `InventorySortAllocation`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/managed/inventory.rs`. Enclosing match alternative: `Need::Rows(count)`.


<a id="cause-InventoryStorageSize"></a>

### `InventoryStorageSize`


Local detection/handling phase and implementation owner:

- `observe` (module-level helper) — `src/managed/inventory.rs`.
- `observe` (module-level helper) — `src/managed/inventory.rs`.
- `observe` (module-level helper) — `src/managed/inventory.rs`.


<a id="cause-InventoryValueNeed"></a>

### `InventoryValueNeed`


Local detection/handling phase and implementation owner:

- `InventoryOwner::attach` — `src/managed/inventory.rs`. Enclosing match alternative: `ReadPhase::Class(read) | ReadPhase::Details { read, .. }`.


<a id="cause-ManagedClassUnsupported"></a>

### `ManagedClassUnsupported`


Local detection/handling phase and implementation owner:

- `SelectedInitial::bind` — `src/managed/discovery/preparation.rs`. Enclosing true branch: `matches!(class, ManagedClass::Other(_))`.


<a id="cause-ManagedDiscoveryCandidateKind"></a>

### `ManagedDiscoveryCandidateKind`


Local detection/handling phase and implementation owner:

- `DiscoveryOwner::attach` — `src/managed/discovery.rs`. Enclosing match alternative: `_`.


<a id="cause-ManagedDiscoveryCompletionPhase"></a>

### `ManagedDiscoveryCompletionPhase`


Local detection/handling phase and implementation owner:

- `DiscoveryOwner::advance` — `src/managed/discovery.rs`. Enclosing match alternative: `_`.


<a id="cause-ManagedDiscoveryContentPhase"></a>

### `ManagedDiscoveryContentPhase`


Local detection/handling phase and implementation owner:

- `DiscoveryOwner::attach` — `src/managed/discovery.rs`. Enclosing match alternative: `_`.


<a id="cause-ManagedDiscoveryContinuationChanged"></a>

### `ManagedDiscoveryContinuationChanged`


Local detection/handling phase and implementation owner:

- `DiscoveryOwner::attach` — `src/managed/discovery.rs`. Enclosing true branch: `self.need()? != Some(need)`.


<a id="cause-ManagedDiscoveryFingerprintPhase"></a>

### `ManagedDiscoveryFingerprintPhase`


Local detection/handling phase and implementation owner:

- `DiscoveryOwner::attach` — `src/managed/discovery.rs`. Enclosing match alternative: `_`.


<a id="cause-ManagedDiscoveryFingerprintSelection"></a>

### `ManagedDiscoveryFingerprintSelection`


Local detection/handling phase and implementation owner:

- `prepare` (module-level helper) — `src/managed/discovery/preparation.rs`. Enclosing match alternative: `Need::Fingerprint(need)`.


<a id="cause-ManagedDiscoveryIncomplete"></a>

### `ManagedDiscoveryIncomplete`


Local detection/handling phase and implementation owner:

- `DiscoveryOwner::result` — `src/managed/discovery.rs`.


<a id="cause-ManagedDiscoveryMetadataPhase"></a>

### `ManagedDiscoveryMetadataPhase`


Local detection/handling phase and implementation owner:

- `DiscoveryOwner::attach` — `src/managed/discovery.rs`. Enclosing match alternative: `_`.


<a id="cause-ManagedDiscoveryNeedAbsent"></a>

### `ManagedDiscoveryNeedAbsent`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/managed/discovery/runner.rs`.


<a id="cause-ManagedDiscoveryOwnerAbsent"></a>

### `ManagedDiscoveryOwnerAbsent`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/managed/discovery/runner.rs`.
- `run` (module-level helper) — `src/managed/discovery/runner.rs`.


<a id="cause-ManagedDiscoveryPossessionAbsent"></a>

### `ManagedDiscoveryPossessionAbsent`


Local detection/handling phase and implementation owner:

- `run` (module-level helper) — `src/managed/discovery/runner.rs`.


<a id="cause-ManagedDiscoverySearchPhase"></a>

### `ManagedDiscoverySearchPhase`


Local detection/handling phase and implementation owner:

- `DiscoveryOwner::attach` — `src/managed/discovery.rs`. Enclosing match alternative: `_`.


<a id="cause-ManagedDiscoveryStopped"></a>

### `ManagedDiscoveryStopped`


Local detection/handling phase and implementation owner:

- `DiscoveryOwner::advance` — `src/managed/discovery.rs`. Enclosing match alternative: `Phase::Stopped`.


<a id="cause-ManagedDiscoveryStorageSize"></a>

### `ManagedDiscoveryStorageSize`


Local detection/handling phase and implementation owner:

- `metadata` (module-level helper) — `src/managed/discovery/preparation.rs`.
- `metadata` (module-level helper) — `src/managed/discovery/preparation.rs`.
- `find` (module-level helper) — `src/managed/discovery/runner.rs`.
- `find` (module-level helper) — `src/managed/discovery/runner.rs`.
- `find` (module-level helper) — `src/managed/discovery/runner.rs`.


<a id="cause-ManagedKeySelector"></a>

### `ManagedKeySelector`


Local detection/handling phase and implementation owner:

- `validate_selector` (module-level helper) — `src/managed/discovery/runner.rs`. Enclosing true branch: `!class.key()`.


<a id="cause-NativeObservationStorageSize"></a>

### `NativeObservationStorageSize`


Local detection/handling phase and implementation owner:

- `observe_native` (module-level helper) — `src/managed/discovery/runner.rs`.
- `observe_native` (module-level helper) — `src/managed/discovery/runner.rs`.


<a id="cause-NativeSearchBatchAllocation"></a>

### `NativeSearchBatchAllocation`


Local detection/handling phase and implementation owner:

- `NativeStorage::allocate` — `src/managed/search/owned/resident.rs`.


<a id="cause-NativeSearchOwnerAbsent"></a>

### `NativeSearchOwnerAbsent`


Local detection/handling phase and implementation owner:

- `publish_selected` (module-level helper) — `src/managed/native_search.rs`. Enclosing match alternative: `Ok(())`.
- `publish_selected` (module-level helper) — `src/managed/native_search.rs`. Enclosing true branch: `let Selection::All(matches) = &mut owner.selection`.
- `publish_selected` (module-level helper) — `src/managed/native_search.rs`. Enclosing match alternative: `Ok(())`.
- `find` (module-level helper) — `src/managed/native_search.rs`.
- `find` (module-level helper) — `src/managed/native_search.rs`. Enclosing true branch: `matches!(owner.selection, Selection::AllPending)`.
- `find` (module-level helper) — `src/managed/native_search.rs`.


<a id="cause-NativeSearchPossessionAbsent"></a>

### `NativeSearchPossessionAbsent`


Local detection/handling phase and implementation owner:

- `find` (module-level helper) — `src/managed/native_search.rs`.


<a id="cause-NativeSearchResourceNeedAbsent"></a>

### `NativeSearchResourceNeedAbsent`


Local detection/handling phase and implementation owner:

- `find` (module-level helper) — `src/managed/native_search.rs`.


<a id="cause-NativeSearchStillPending"></a>

### `NativeSearchStillPending`


Local detection/handling phase and implementation owner:

- `CompleteSearchRetirement<'_>::retire` — `src/managed/native_search.rs`. Enclosing match alternative: `SearchRetirement::Pending`.


<a id="cause-NativeSearchStorageAccounting"></a>

### `NativeSearchStorageAccounting`


Local detection/handling phase and implementation owner:

- `find` (module-level helper) — `src/managed/native_search.rs`.
- `find` (module-level helper) — `src/managed/native_search.rs`.
- `find` (module-level helper) — `src/managed/native_search.rs`.


<a id="cause-NativeSearchStorageSize"></a>

### `NativeSearchStorageSize`


Local detection/handling phase and implementation owner:

- `NativeStorage::requested` — `src/managed/search/owned/resident.rs`.
- `NativeStorage::bytes` — `src/managed/search/owned/resident.rs`.


<a id="cause-NativeSearchStreamOwnerAbsent"></a>

### `NativeSearchStreamOwnerAbsent`


Local detection/handling phase and implementation owner:

- `finish_cursor` (module-level helper) — `src/managed/native_search/stream.rs`.
- `start` (module-level helper) — `src/managed/native_search/stream/preparation.rs`.
- `fetch` (module-level helper) — `src/managed/native_search/stream/publication.rs`.
- `fetch` (module-level helper) — `src/managed/native_search/stream/publication.rs`.
- `publish` (module-level helper) — `src/managed/native_search/stream/publication.rs`.
- `publish` (module-level helper) — `src/managed/native_search/stream/publication.rs`.


<a id="cause-ObjectSearchCountOverflow"></a>

### `ObjectSearchCountOverflow`


Local detection/handling phase and implementation owner:

- `reserve_handles` (module-level helper) — `src/managed/search.rs`.
- `SearchCollection::append` — `src/managed/search.rs`.
- `SearchCollection::preparation_need` — `src/managed/search/preparation.rs`. Enclosing false branch: `batch.is_empty()`.


<a id="cause-ObjectSearchLimitExceeded"></a>

### `ObjectSearchLimitExceeded`


Local detection/handling phase and implementation owner:

- `SearchCollection::append` — `src/managed/search.rs`. Enclosing true branch: `self .plan .maximum_objects .is_some_and(|maximum| total > maximum)`.
- `SearchCollection::preparation_need` — `src/managed/search/preparation.rs`. Enclosing true branch: `self .plan .maximum_objects .is_some_and(|maximum| total > maximum)`.


<a id="cause-SearchAccessOwner"></a>

### `SearchAccessOwner`


Local detection/handling phase and implementation owner:

- `SearchOwner::context` — `src/managed/search/owned/resident.rs`. Enclosing true branch: `!access.owns_session(session)`.


<a id="cause-SearchBatchAllocation"></a>

### `SearchBatchAllocation`


Local detection/handling phase and implementation owner:

- `Storage::allocate_owned` — `src/managed/search/owned/resident.rs`.


<a id="cause-SearchCapacityOverflow"></a>

### `SearchCapacityOverflow`


Local detection/handling phase and implementation owner:

- `reserve_handles` (module-level helper) — `src/managed/search.rs`.
- `reserve_handles` (module-level helper) — `src/managed/search.rs`. Enclosing true branch: `let Some(credit) = credit`.
- `SearchCandidate::prepare_retaining` — `src/managed/search/preparation.rs`.
- `SearchCandidate::prepare_retaining` — `src/managed/search/preparation.rs`.
- `SearchCollection::attach` — `src/managed/search/preparation.rs`.


<a id="cause-SearchCardinalityWidth"></a>

### `SearchCardinalityWidth`


Local detection/handling phase and implementation owner:

- `ObjectSearchSelection::select` — `src/search_controls.rs`.


<a id="cause-SearchCleanupOwnerAbsent"></a>

### `SearchCleanupOwnerAbsent`


Local detection/handling phase and implementation owner:

- `finish_failed_search` (module-level helper) — `src/managed/search/recovery.rs`.


<a id="cause-SearchContinuationChanged"></a>

### `SearchContinuationChanged`


Local detection/handling phase and implementation owner:

- `SearchOwner::attach` — `src/managed/search/owned/resident.rs`. Enclosing true branch: `self.need()? != Some(candidate.need())`.


<a id="cause-SearchDispatchPhase"></a>

### `SearchDispatchPhase`


Local detection/handling phase and implementation owner:

- `SearchOwner::dispatch` — `src/managed/search/owned/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-SearchIdentityAllocation"></a>

### `SearchIdentityAllocation`


Local detection/handling phase and implementation owner:

- `AllMatches::prepare` — `src/managed/native_search/all.rs`.


<a id="cause-SearchIdentityStorageAccounting"></a>

### `SearchIdentityStorageAccounting`


Local detection/handling phase and implementation owner:

- `AllMatches::prepare` — `src/managed/native_search/all.rs`.


<a id="cause-SearchIncomplete"></a>

### `SearchIncomplete`


Local detection/handling phase and implementation owner:

- `SearchOwner::into_collection` — `src/managed/search/owned/resident.rs`. Enclosing true branch: `!self.complete()`.
- `SearchOwner::completed_len` — `src/managed/search/owned/resident.rs`. Enclosing true branch: `!self.complete()`.
- `SearchOwner::selected` — `src/managed/search/owned/resident.rs`. Enclosing true branch: `!self.complete()`.


<a id="cause-SearchOutcomeUncertain"></a>

### `SearchOutcomeUncertain`


Local detection/handling phase and implementation owner:

- `SearchOwner::dispatch` — `src/managed/search/owned/resident.rs`. Enclosing true branch: `!returned || completion == Completion::Uncertain`.
- `SearchOwner::advance` — `src/managed/search/owned/resident.rs`. Enclosing match alternative: `Phase::InFlight | Phase::Uncertain`.
- `SearchOwner::finish` — `src/managed/search/owned/resident.rs`. Enclosing match alternative: `Phase::InFlight | Phase::Uncertain`.


<a id="cause-SearchPreparationAbsent"></a>

### `SearchPreparationAbsent`


Local detection/handling phase and implementation owner:

- `SearchCollection::append_prepared` — `src/managed/search/preparation.rs`. Enclosing true branch: `self.preparation_need(batch)?.is_some()`.


<a id="cause-SearchPreparationAlreadyConsumed"></a>

### `SearchPreparationAlreadyConsumed`


Local detection/handling phase and implementation owner:

- `Storage::bind_retained` — `src/managed/search/owned/resident.rs`.


<a id="cause-SearchPreparationKindMismatch"></a>

### `SearchPreparationKindMismatch`


Local detection/handling phase and implementation owner:

- `find` (module-level helper) — `src/managed/native_search.rs`. Enclosing match alternative: `_`.


<a id="cause-SearchPreparationUnexpectedlyInvalidated"></a>

### `SearchPreparationUnexpectedlyInvalidated`


Local detection/handling phase and implementation owner:

- `find` (module-level helper) — `src/managed/native_search.rs`. Enclosing match alternative: `SelectionRequest::All`.
- `start` (module-level helper) — `src/managed/native_search/stream/preparation.rs`.
- `fetch` (module-level helper) — `src/managed/native_search/stream/publication.rs`.


<a id="cause-SearchPreparationWithoutByteOwner"></a>

### `SearchPreparationWithoutByteOwner`


Local detection/handling phase and implementation owner:

- `SearchCollection::attach` — `src/managed/search/preparation.rs`.


<a id="cause-SearchPublicationChanged"></a>

### `SearchPublicationChanged`


Local detection/handling phase and implementation owner:

- `find` (module-level helper) — `src/managed/native_search.rs`. Enclosing true branch: `!matches!(owner.selection, Selection::AllPending) || owner.search.completed_len()? != count`.


<a id="cause-SearchPublicationIncomplete"></a>

### `SearchPublicationIncomplete`


Local detection/handling phase and implementation owner:

- `AllMatches::result` — `src/managed/native_search/all.rs`. Enclosing true branch: `self.published != count || self.identities.len() != count || self.objects.capacity() < count`.


<a id="cause-SearchPublicationIndexAbsent"></a>

### `SearchPublicationIndexAbsent`


Local detection/handling phase and implementation owner:

- `publish_selected` (module-level helper) — `src/managed/native_search.rs`. Enclosing true branch: `let Selection::All(matches) = &mut owner.selection`.


<a id="cause-SearchPublicationNotPrepared"></a>

### `SearchPublicationNotPrepared`


Local detection/handling phase and implementation owner:

- `NativeSearchOwner::publication_activity` — `src/managed/native_search.rs`. Enclosing match alternative: `Selection::AllPending`.
- `NativeSearchOwner::result` — `src/managed/native_search.rs`. Enclosing match alternative: `Selection::AllPending`.


<a id="cause-SearchResultAllocation"></a>

### `SearchResultAllocation`


Local detection/handling phase and implementation owner:

- `reserve_handles` (module-level helper) — `src/managed/search.rs`. Enclosing true branch: `values.try_reserve_exact(additional).is_err()`.
- `AllMatches::prepare` — `src/managed/native_search/all.rs`.
- `SearchCandidate::prepare_retaining` — `src/managed/search/preparation.rs`.


<a id="cause-SearchResultKindMismatch"></a>

### `SearchResultKindMismatch`


Local detection/handling phase and implementation owner:

- `Session::find_native_object_at` — `src/managed/native_search.rs`. Enclosing match alternative: `SearchResult::All(_)`.
- `Session::find_native_objects` — `src/managed/native_search.rs`. Enclosing match alternative: `SearchResult::Index(_)`.


<a id="cause-SearchResultStorageAccounting"></a>

### `SearchResultStorageAccounting`


Local detection/handling phase and implementation owner:

- `AllMatches::prepare` — `src/managed/native_search/all.rs`.
- `AllMatches::prepare` — `src/managed/native_search/all.rs`.
- `AllMatches::prepare` — `src/managed/native_search/all.rs`.
- `AllMatches::result` — `src/managed/native_search/all.rs`.


<a id="cause-SearchStorageSize"></a>

### `SearchStorageSize`


Local detection/handling phase and implementation owner:

- `Storage::requested_bytes` — `src/managed/search/owned/resident.rs`.
- `Storage::allocated_bytes` — `src/managed/search/owned/resident.rs`.
- `Storage::bind_retained` — `src/managed/search/owned/resident.rs`.
- `Storage::bind_retained` — `src/managed/search/owned/resident.rs`.


<a id="cause-SearchStreamAlreadyInitialized"></a>

### `SearchStreamAlreadyInitialized`


Local detection/handling phase and implementation owner:

- `SearchOwner::initialize_stream` — `src/managed/search/owned/resident.rs`. Enclosing true branch: `!matches!(self.phase, Phase::Init)`.


<a id="cause-SearchStreamBatchAlreadyOwned"></a>

### `SearchStreamBatchAlreadyOwned`


Local detection/handling phase and implementation owner:

- `fetch` (module-level helper) — `src/managed/native_search/stream/publication.rs`. Enclosing true branch: `!matches!(owner.batch, Batch::Idle)`.


<a id="cause-SearchStreamBatchUnavailable"></a>

### `SearchStreamBatchUnavailable`


Local detection/handling phase and implementation owner:

- `SearchOwner::stream_batch_len` — `src/managed/search/owned/resident.rs`. Enclosing match alternative: `_`.


<a id="cause-SearchStreamIndexOutsideBatch"></a>

### `SearchStreamIndexOutsideBatch`


Local detection/handling phase and implementation owner:

- `SearchOwner::stream_handle` — `src/managed/search/owned/resident.rs`. Enclosing true branch: `index >= count`.


<a id="cause-SearchStreamPublicationAbsent"></a>

### `SearchStreamPublicationAbsent`


Local detection/handling phase and implementation owner:

- `NativeSearchStreamOwner::publication_activity` — `src/managed/native_search/stream/publication.rs`.
- `publish` (module-level helper) — `src/managed/native_search/stream/publication.rs`.


<a id="cause-SearchStreamPublicationChanged"></a>

### `SearchStreamPublicationChanged`


Local detection/handling phase and implementation owner:

- `fetch` (module-level helper) — `src/managed/native_search/stream/publication.rs`. Enclosing true branch: `!matches!(owner.batch, Batch::Reading(_)) || owner.search.stream_batch_len()? != count`.


<a id="cause-SearchStreamPublicationIndexAbsent"></a>

### `SearchStreamPublicationIndexAbsent`


Local detection/handling phase and implementation owner:

- `NativeSearchStreamOwner::publication_activity` — `src/managed/native_search/stream/publication.rs`.
- `publish` (module-level helper) — `src/managed/native_search/stream/publication.rs`.


<a id="cause-SearchStreamStillPending"></a>

### `SearchStreamStillPending`


Local detection/handling phase and implementation owner:

- `finish_cursor` (module-level helper) — `src/managed/native_search/stream.rs`. Enclosing false branch: `retired`.


<a id="cause-SearchStreamStorageAccounting"></a>

### `SearchStreamStorageAccounting`


Local detection/handling phase and implementation owner:

- `start` (module-level helper) — `src/managed/native_search/stream/preparation.rs`.
- `start` (module-level helper) — `src/managed/native_search/stream/preparation.rs`.
- `start` (module-level helper) — `src/managed/native_search/stream/preparation.rs`.


<a id="cause-SearchTemplateOrCapacityChanged"></a>

### `SearchTemplateOrCapacityChanged`


Local detection/handling phase and implementation owner:

- `SearchOwner::dispatch` — `src/managed/search/owned/resident.rs`. Enclosing true branch: `!self.call.template.unchanged() || matches!(phase, Phase::Find) && rv == CKR_OK && self.call.count as u128 > self.call.batch.len() as u128`.


<a id="cause-SelectedAdmissionStorageSize"></a>

### `SelectedAdmissionStorageSize`


Local detection/handling phase and implementation owner:

- `SelectedInitial::requested` — `src/managed/discovery/preparation.rs`.
- `SelectedInitial::allocated_bytes` — `src/managed/discovery/preparation.rs`.


<a id="cause-SelectedSearchResultAbsent"></a>

### `SelectedSearchResultAbsent`


Local detection/handling phase and implementation owner:

- `ObjectSearchSelection::select` — `src/search_controls.rs`.


<a id="cause-UnknownObjectClassRequiresAnExtensionContract"></a>

### `UnknownObjectClassRequiresAnExtensionContract`


Local detection/handling phase and implementation owner:

- `validate_selector` (module-level helper) — `src/managed/discovery/runner.rs`. Enclosing true branch: `matches!(class, ManagedClass::Other(_))`.


<a id="cause-UnselectedManagedContent"></a>

### `UnselectedManagedContent`


Local detection/handling phase and implementation owner:

- `DiscoveryOwner::advance` — `src/managed/discovery.rs`. Enclosing match alternative: `Phase::NeedContent(published)`.
