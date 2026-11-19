# Native cases by worker mode

Select a mode to find its input manifests and Rust dispatch. Some modes share an implementation. A manifest may select different modes for individual cases. The [suite guide](../README.md) explains preparation, assertions and output.

| Mode | Dispatch | Case manifests |
| --- | --- | --- |
| `absent-mechanism` | [main](../native/main.rs#L903) | [absent-mechanism](absent-mechanism/manifest.json) |
| `absent-object-attributes` | [extension_cases](../native/extension_cases.rs#L105) | [absent-object-attributes](absent-object-attributes/manifest.json), [additional-class-attribute-absence](additional-class-attribute-absence/manifest.json), [class-template-attribute-absence](class-template-attribute-absence/manifest.json), [remaining-class-attributes](remaining-class-attributes/manifest.json), [typed-secret-attribute-absence](typed-secret-attribute-absence/manifest.json) |
| `active-pair` | [main](../native/main.rs#L667) | [active-family-pairs](active-family-pairs/manifest.json) |
| `admission-family` | [main](../native/main.rs#L711) | [admission-family](admission-family/manifest.json), [final-structural-guards](final-structural-guards/manifest.json) |
| `admission-scope` | [main](../native/main.rs#L720) | [admission-scope](admission-scope/manifest.json) |
| `advanced-setting` | [main](../native/main.rs#L670) | [advanced-settings](advanced-settings/manifest.json) |
| `aead-input-guards` | [main](../native/main.rs#L634) | [cipher-agreement-guards](cipher-agreement-guards/manifest.json), [remaining-input-guards](remaining-input-guards/manifest.json) |
| `aead-preinit` | [main](../native/main.rs#L900) | [aead-preinit](aead-preinit/manifest.json), [input-guard](input-guard/manifest.json), [multipart-and-block](multipart-and-block/manifest.json), [remaining-ticket-guards](remaining-ticket-guards/manifest.json) |
| `aes-entry-guard` | [main](../native/main.rs#L738) | [aes-entry-guards](aes-entry-guards/manifest.json) |
| `aes-transport-class` | [extension_cases](../native/extension_cases.rs#L108) | [aes-transport-class](aes-transport-class/manifest.json) |
| `agreement-input-guards` | [main](../native/main.rs#L643) | [cipher-agreement-guards](cipher-agreement-guards/manifest.json), [typed-ecdh-kdf](typed-ecdh-kdf/manifest.json) |
| `attribute-creation-change` | [extension_cases](../native/extension_cases.rs#L96) | [creation-class-attribute-changes](creation-class-attribute-changes/manifest.json) |
| `attribute-guard` | [main](../native/main.rs#L828) | [simple-guards](simple-guards/manifest.json) |
| `attribute-mixed-values` | [extension_cases](../native/extension_cases.rs#L99) | [mixed-class-attribute-values](mixed-class-attribute-values/manifest.json) |
| `attribute-value-partitions` | [extension_cases](../native/extension_cases.rs#L102) | [explicit-class-attribute-values](explicit-class-attribute-values/manifest.json), [omitted-class-attribute-defaults](omitted-class-attribute-defaults/manifest.json) |
| `authenticated-transport-guard` | [main](../native/main.rs#L426) | [selection-native-slots](selection-native-slots/manifest.json), [transport-interface-guards](transport-interface-guards/manifest.json), [typed-wrap-query](typed-wrap-query/manifest.json) |
| `authentication-admission` | [main](../native/main.rs#L961) | [authentication](authentication/manifest.json) |
| `authentication-state` | [main](../native/main.rs#L958) | [auth-digest-complements](auth-digest-complements/manifest.json), [authentication-state](authentication-state/manifest.json) |
| `batch-state` | [main](../native/main.rs#L549) | [batch-capacity](batch-capacity/manifest.json), [batch-state](batch-state/manifest.json) |
| `binary-generation` | [main](../native/main.rs#L735) | [binary-generation](binary-generation/manifest.json) |
| `borrowed-client` | [main](../native/main.rs#L382) | [engine-and-borrowed](engine-and-borrowed/manifest.json) |
| `builder-choices` | [main](../native/main.rs#L388) | [builder-choices](builder-choices/manifest.json) |
| `builder-observation` | [main](../native/main.rs#L391) | [builder-observations](builder-observations/manifest.json), [concurrent-discovery](concurrent-discovery/manifest.json) |
| `builder-runtime-choices` | [main](../native/main.rs#L376) | [absent-agreement-selectors](absent-agreement-selectors/manifest.json), [absent-cipher-selectors](absent-cipher-selectors/manifest.json), [absent-hash-selectors](absent-hash-selectors/manifest.json), [absent-key-derivations](absent-key-derivations/manifest.json), [absent-key-schedules](absent-key-schedules/manifest.json), [absent-legacy-key-selectors](absent-legacy-key-selectors/manifest.json), [absent-rsa-selectors](absent-rsa-selectors/manifest.json), [absent-tls-derivations](absent-tls-derivations/manifest.json), [builder-runtime-choices](builder-runtime-choices/manifest.json), [capture-credit](capture-credit/manifest.json), [configuration-files](configuration-files/manifest.json), [configuration-variants](configuration-variants/manifest.json), [directory-denial](directory-denial/manifest.json), [drain-owner-order](drain-owner-order/manifest.json), [gost-derivation-destination](gost-derivation-destination/manifest.json), [imported-private-protection](imported-private-protection/manifest.json), [notification-ownership](notification-ownership/manifest.json), [output-credit](output-credit/manifest.json), [owner-progress](owner-progress/manifest.json), [permission-modes](permission-modes/manifest.json), [protocol-absence](protocol-absence/manifest.json), [public-point-forms](public-point-forms/manifest.json), [record-and-protocol-fields](record-and-protocol-fields/manifest.json), [reference-credit](reference-credit/manifest.json), [resource-controls](resource-controls/manifest.json), [resource-owner-baselines](resource-owner-baselines/manifest.json), [shared-clients](shared-clients/manifest.json), [waiting-cancellation](waiting-cancellation/manifest.json) |
| `cipher-batch-transition` | [main](../native/main.rs#L894) | [cipher-batch-transition](cipher-batch-transition/manifest.json) |
| `cipher-transition` | [main](../native/main.rs#L932) | [cbc-resume](cbc-resume/manifest.json), [cipher-transition](cipher-transition/manifest.json) |
| `cipher-usage` | [main](../native/main.rs#L598) | [additional-cipher-usage](additional-cipher-usage/manifest.json), [cipher-usage](cipher-usage/manifest.json), [tdes-padding-usage](tdes-padding-usage/manifest.json) |
| `cipher-vector` | [main](../native/main.rs#L970) | [block-boundaries](block-boundaries/manifest.json), [cipher](cipher/manifest.json), [cipher-empty-input](cipher-empty-input/manifest.json), [cipher-key-sizes](cipher-key-sizes/manifest.json), [ctr-boundaries](ctr-boundaries/manifest.json), [iv-width-control](iv-width-control/manifest.json), [multipart-and-block](multipart-and-block/manifest.json) |
| `classical-changed` | [main](../native/main.rs#L753) | [dsa-sha3-negatives](dsa-sha3-negatives/manifest.json), [sha1-signature-negatives](sha1-signature-negatives/manifest.json) |
| `classical-sign` | [main](../native/main.rs#L505) | [classical-sign](classical-sign/manifest.json) |
| `classical-sign-denied` | [main](../native/main.rs#L761) | [classical-usage](classical-usage/manifest.json), [dsa-sha3-negatives](dsa-sha3-negatives/manifest.json), [sha1-signature-negatives](sha1-signature-negatives/manifest.json) |
| `classical-verify-denied` | [main](../native/main.rs#L769) | [classical-usage](classical-usage/manifest.json), [dsa-sha3-negatives](dsa-sha3-negatives/manifest.json), [sha1-signature-negatives](sha1-signature-negatives/manifest.json) |
| `concatenation-negative` | [main](../native/main.rs#L750) | [concatenation-negatives](concatenation-negatives/manifest.json) |
| `concatenation-values` | [main](../native/main.rs#L542) | [concatenation-values](concatenation-values/manifest.json) |
| `context-local-guards` | [main](../native/main.rs#L939) | [context-local-guards](context-local-guards/manifest.json) |
| `context-login` | [main](../native/main.rs#L937) | [context-login](context-login/manifest.json) |
| `context-missing-login` | [main](../native/main.rs#L940) | [authentication-completion](authentication-completion/manifest.json) |
| `context-pss-login` | [main](../native/main.rs#L941) | [pss-context](pss-context/manifest.json) |
| `context-wrong-pin` | [main](../native/main.rs#L938) | [context-login](context-login/manifest.json) |
| `cross-runtime-guard` | [main](../native/main.rs#L379) | [cross-runtime-guards](cross-runtime-guards/manifest.json) |
| `derive-template-negative` | [main](../native/main.rs#L531) | [derive-negatives](derive-negatives/manifest.json) |
| `derive-usage-negative` | [main](../native/main.rs#L531) | [derive-negatives](derive-negatives/manifest.json) |
| `des-parity` | [main](../native/main.rs#L595) | [des-parity](des-parity/manifest.json) |
| `dh-import-identity` | [main](../native/main.rs#L501) | [dh-import-identity](dh-import-identity/manifest.json) |
| `dh-public-import` | [main](../native/main.rs#L501) | [dh-public-import](dh-public-import/manifest.json) |
| `dh-template-denied` | [main](../native/main.rs#L513) | [agreement-negatives](agreement-negatives/manifest.json) |
| `dh-usage-denied` | [main](../native/main.rs#L513) | [agreement-negatives](agreement-negatives/manifest.json) |
| `dh-vector` | [main](../native/main.rs#L542) | [dh](dh/manifest.json), [dh-peer-boundaries](dh-peer-boundaries/manifest.json), [dh-validation](dh-validation/manifest.json) |
| `digest-cancel` | [main](../native/main.rs#L979) | [digest-cancel](digest-cancel/manifest.json) |
| `digest-capacity` | [main](../native/main.rs#L891) | [auth-digest-complements](auth-digest-complements/manifest.json), [digest-capacity](digest-capacity/manifest.json), [digest-complements](digest-complements/manifest.json), [owner-progress](owner-progress/manifest.json), [zero-cooperative](zero-cooperative/manifest.json) |
| `digest-family-view` | [main](../native/main.rs#L726) | [digest-family-views](digest-family-views/manifest.json) |
| `digest-key-identity` | [main](../native/main.rs#L637) | [auth-digest-complements](auth-digest-complements/manifest.json), [digest-complements](digest-complements/manifest.json), [identity-budget](identity-budget/manifest.json) |
| `digest-live-alias` | [main](../native/main.rs#L702) | [digest-live-alias](digest-live-alias/manifest.json) |
| `digest-refused` | [main](../native/main.rs#L888) | [digest-refused](digest-refused/manifest.json) |
| `digest-stream` | [main](../native/main.rs#L982) | [digest-stream](digest-stream/manifest.json) |
| `digest-ticket-cipher` | [main](../native/main.rs#L729) | [digest-ticket-cipher](digest-ticket-cipher/manifest.json), [digest-transitive](digest-transitive/manifest.json) |
| `digest-transition` | [main](../native/main.rs#L482) | [digest-ownership-credits](digest-ownership-credits/manifest.json), [digest-transition](digest-transition/manifest.json), [live-digest-detachment](live-digest-detachment/manifest.json) |
| `direct-generation` | [main](../native/main.rs#L622) | [direct-generation](direct-generation/manifest.json) |
| `direct-material` | [main](../native/main.rs#L619) | [direct-material](direct-material/manifest.json) |
| `discovery-contract` | [main](../native/main.rs#L355) | [discovery](discovery/manifest.json), [identifier-widths](identifier-widths/manifest.json) |
| `drain-ticket-identity` | [main](../native/main.rs#L646) | [drain-ticket-identity](drain-ticket-identity/manifest.json) |
| `dsa-import-identity` | [main](../native/main.rs#L501) | [dsa-import-identity](dsa-import-identity/manifest.json) |
| `dsa-vector` | [main](../native/main.rs#L452) | [dsa](dsa/manifest.json), [dsa-wrong-key](dsa-wrong-key/manifest.json), [multipart-and-block](multipart-and-block/manifest.json), [signature-aead-boundaries](signature-aead-boundaries/manifest.json) |
| `dual-cbc` | [main](../native/main.rs#L926) | [dual-cbc](dual-cbc/manifest.json) |
| `ecdh-invalid` | [main](../native/main.rs#L556) | [ecdh-invalid](ecdh-invalid/manifest.json) |
| `ecdh-template-denied` | [main](../native/main.rs#L522) | [agreement-negatives](agreement-negatives/manifest.json) |
| `ecdh-usage-denied` | [main](../native/main.rs#L522) | [agreement-negatives](agreement-negatives/manifest.json) |
| `ecdh-vector` | [main](../native/main.rs#L542) | [ecdh](ecdh/manifest.json), [ecdh-point-forms](ecdh-point-forms/manifest.json) |
| `ecdsa-encoding` | [main](../native/main.rs#L446) | [dsa-der-negatives](dsa-der-negatives/manifest.json), [dsa-encoding](dsa-encoding/manifest.json), [encoding](encoding/manifest.json) |
| `ecdsa-transition` | [main](../native/main.rs#L921) | [ecdsa-transition](ecdsa-transition/manifest.json) |
| `ecdsa-vector` | [main](../native/main.rs#L449) | [ecdsa](ecdsa/manifest.json), [ecdsa-explicit](ecdsa-explicit/manifest.json), [ecdsa-invalid-point](ecdsa-invalid-point/manifest.json), [ecdsa-wrong-curve](ecdsa-wrong-curve/manifest.json), [multipart-and-block](multipart-and-block/manifest.json) |
| `edwards-negative` | [main](../native/main.rs#L485) | [edwards-boundaries](edwards-boundaries/manifest.json), [edwards-multipart](edwards-multipart/manifest.json), [edwards-negatives](edwards-negatives/manifest.json), [edwards-wrong-key](edwards-wrong-key/manifest.json) |
| `edwards-transition` | [main](../native/main.rs#L920) | [edwards-transition](edwards-transition/manifest.json) |
| `edwards-vector` | [main](../native/main.rs#L860) | [edwards](edwards/manifest.json), [edwards-boundaries](edwards-boundaries/manifest.json), [edwards-context-bounds](edwards-context-bounds/manifest.json), [edwards-empty-prehash](edwards-empty-prehash/manifest.json) |
| `encrypt-data-vector` | [main](../native/main.rs#L542) | [encrypt-data](encrypt-data/manifest.json) |
| `engine-choices` | [main](../native/main.rs#L385) | [engine-and-borrowed](engine-and-borrowed/manifest.json), [engine-component](engine-component/manifest.json), [engine-hash-completion](engine-hash-completion/manifest.json), [engine-identity](engine-identity/manifest.json), [engine-invalid-request](engine-invalid-request/manifest.json), [engine-retained](engine-retained/manifest.json), [engine-signature-format](engine-signature-format/manifest.json), [engine-unavailable](engine-unavailable/manifest.json), [rsa-generated-engine](rsa-generated-engine/manifest.json) |
| `extension-cipher` | [extension_cases](../native/extension_cases.rs#L148) | [extension-operations](extension-operations/manifest.json) |
| `extension-gcm` | [extension_cases](../native/extension_cases.rs#L134) | [gcm-extension-graphs](gcm-extension-graphs/manifest.json) |
| `extension-generation` | [extension_cases](../native/extension_cases.rs#L139) | [extension-generation](extension-generation/manifest.json), [poly1305-generation](poly1305-generation/manifest.json) |
| `extension-oaep` | [extension_cases](../native/extension_cases.rs#L122) | [extension-layout-complements](extension-layout-complements/manifest.json) |
| `extension-oaep-null` | [extension_cases](../native/extension_cases.rs#L128) | [extension-layout-complements](extension-layout-complements/manifest.json) |
| `extension-objects` | [extension_cases](../native/extension_cases.rs#L137) | [extension-layout-complements](extension-layout-complements/manifest.json), [extension-objects](extension-objects/manifest.json), [extension-pointer-bounds](extension-pointer-bounds/manifest.json) |
| `extension-pair` | [extension_cases](../native/extension_cases.rs#L138) | [extension-pair](extension-pair/manifest.json) |
| `extension-rsa-aes-advanced` | [extension_cases](../native/extension_cases.rs#L119) | [extension-layout-complements](extension-layout-complements/manifest.json) |
| `extension-rsa-aes-session` | [extension_cases](../native/extension_cases.rs#L119) | [extension-layout-complements](extension-layout-complements/manifest.json) |
| `extension-signature` | [extension_cases](../native/extension_cases.rs#L151) | [extension-operations](extension-operations/manifest.json) |
| `foreign-callback` | [main](../native/main.rs#L406) | [foreign-callbacks](foreign-callbacks/manifest.json) |
| `foreign-event-guard` | [main](../native/main.rs#L403) | [foreign-event-guard](foreign-event-guard/manifest.json) |
| `foreign-info` | [main](../native/main.rs#L409) | [foreign-info](foreign-info/manifest.json), [foreign-states](foreign-states/manifest.json), [module-boundaries](module-boundaries/manifest.json) |
| `foreign-session` | [main](../native/main.rs#L400) | [foreign-authentication](foreign-authentication/manifest.json), [foreign-objects](foreign-objects/manifest.json), [foreign-states](foreign-states/manifest.json), [owner-width-contracts](owner-width-contracts/manifest.json) |
| `foreign-slot-guard` | [main](../native/main.rs#L397) | [foreign-slot-guard](foreign-slot-guard/manifest.json) |
| `gcm-parameters` | [main](../native/main.rs#L568) | [gcm-parameters](gcm-parameters/manifest.json) |
| `gcm-result-metadata` | [extension_cases](../native/extension_cases.rs#L109) | [result-metadata](result-metadata/manifest.json) |
| `gcm-transition` | [main](../native/main.rs#L929) | [gcm-transition](gcm-transition/manifest.json) |
| `gcm-usage` | [main](../native/main.rs#L560) | [additional-cipher-usage](additional-cipher-usage/manifest.json) |
| `gcm-vector` | [main](../native/main.rs#L576) | [gcm](gcm/manifest.json), [gcm-family-boundaries](gcm-family-boundaries/manifest.json), [gcm-partitions](gcm-partitions/manifest.json), [signature-aead-boundaries](signature-aead-boundaries/manifest.json) |
| `gcm-withholding` | [main](../native/main.rs#L852) | [gcm-family-boundaries](gcm-family-boundaries/manifest.json), [gcm-withholding](gcm-withholding/manifest.json) |
| `generated-aes` | [main](../native/main.rs#L655) | [generated-aes](generated-aes/manifest.json) |
| `generation-negative` | [main](../native/main.rs#L601) | [generation-key-type](generation-key-type/manifest.json), [generation-negative](generation-negative/manifest.json) |
| `generation-transition` | [main](../native/main.rs#L732) | [generation-family](generation-family/manifest.json), [generation-refused](generation-refused/manifest.json), [generation-transition](generation-transition/manifest.json), [montgomery-refused-continuation](montgomery-refused-continuation/manifest.json), [montgomery-unavailable](montgomery-unavailable/manifest.json) |
| `generation-vector` | [main](../native/main.rs#L488) | [generated-permissions](generated-permissions/manifest.json), [generated-transport-permissions](generated-transport-permissions/manifest.json), [generated-usage-readback](generated-usage-readback/manifest.json), [generation](generation/manifest.json), [generation-domain-witness](generation-domain-witness/manifest.json), [generation-lifetime](generation-lifetime/manifest.json), [generation-protection](generation-protection/manifest.json), [generation-secret-witness](generation-secret-witness/manifest.json), [key-material-observations](key-material-observations/manifest.json), [pqc-generation-witness](pqc-generation-witness/manifest.json) |
| `hkdf-hash-widths` | [extension_cases](../native/extension_cases.rs#L89) | [hkdf-hash-widths](hkdf-hash-widths/manifest.json) |
| `import-encoding` | [main](../native/main.rs#L419) | [import-encoding](import-encoding/manifest.json) |
| `initialization-contract` | [main](../native/main.rs#L358) | [initialization](initialization/manifest.json) |
| `input-guard` | [main](../native/main.rs#L422) | [input-guard](input-guard/manifest.json) |
| `interface-contract` | [main](../native/main.rs#L370) | [interfaces](interfaces/manifest.json) |
| `kem-import` | [main](../native/main.rs#L909) | [kem-import](kem-import/manifest.json) |
| `kem-lifecycle` | [main](../native/main.rs#L906) | [kem-capacity](kem-capacity/manifest.json), [kem-generation-identity](kem-generation-identity/manifest.json), [kem-legacy-identity](kem-legacy-identity/manifest.json), [kem-lifecycle](kem-lifecycle/manifest.json), [kem-public-import](kem-public-import/manifest.json), [kem-usage-negatives](kem-usage-negatives/manifest.json) |
| `kem-vector` | [main](../native/main.rs#L912) | [kem](kem/manifest.json), [kem-lengths](kem-lengths/manifest.json) |
| `kem-wrong-key` | [extension_cases](../native/extension_cases.rs#L115) | [kem-wrong-key](kem-wrong-key/manifest.json) |
| `key-wrap-controlled` | [main](../native/main.rs#L457) | [key-wrap-controlled](key-wrap-controlled/manifest.json), [unwrap-boundaries](unwrap-boundaries/manifest.json) |
| `key-wrap-vector` | [main](../native/main.rs#L457) | [key-wrap](key-wrap/manifest.json), [kwp-absent](kwp-absent/manifest.json), [unwrap-boundaries](unwrap-boundaries/manifest.json), [wrap-contracts](wrap-contracts/manifest.json) |
| `legacy-contract` | [main](../native/main.rs#L717) | [legacy-contract](legacy-contract/manifest.json) |
| `mac-equivalence` | [main](../native/main.rs#L973) | [mac-equivalence](mac-equivalence/manifest.json) |
| `mac-transition` | [main](../native/main.rs#L917) | [mac-transition](mac-transition/manifest.json) |
| `mac-vector` | [main](../native/main.rs#L976) | [dedicated-hmac](dedicated-hmac/manifest.json), [mac](mac/manifest.json), [mac-bindings](mac-bindings/manifest.json), [mac-general-family](mac-general-family/manifest.json), [mac-parameters](mac-parameters/manifest.json), [mac-usage](mac-usage/manifest.json) |
| `mechanism-request-guard` | [main](../native/main.rs#L640) | [identity-budget](identity-budget/manifest.json) |
| `module-accessor` | [main](../native/main.rs#L415) | [module-accessors](module-accessors/manifest.json) |
| `module-boundary` | [main](../native/main.rs#L394) | [final-structural-guards](final-structural-guards/manifest.json), [module-boundaries](module-boundaries/manifest.json) |
| `module-controls` | [main](../native/main.rs#L667) | [module-controls](module-controls/manifest.json) |
| `module-lifecycle` | [main](../native/main.rs#L714) | [module-lifecycle](module-lifecycle/manifest.json), [recovery-destination-guards](recovery-destination-guards/manifest.json) |
| `oaep-decrypt-denied` | [main](../native/main.rs#L691) | [retained-crypto](retained-crypto/manifest.json) |
| `oaep-destination-guard` | [main](../native/main.rs#L705) | [oaep-destination-guard](oaep-destination-guard/manifest.json) |
| `oaep-encrypt` | [main](../native/main.rs#L467) | [oaep-encrypt](oaep-encrypt/manifest.json) |
| `oaep-encrypt-denied` | [main](../native/main.rs#L683) | [retained-crypto](retained-crypto/manifest.json) |
| `oaep-reference-guard` | [main](../native/main.rs#L708) | [object-record-guards](object-record-guards/manifest.json) |
| `oaep-vector` | [main](../native/main.rs#L470) | [oaep](oaep/manifest.json), [oaep-binary-parameter](oaep-binary-parameter/manifest.json), [oaep-contract](oaep-contract/manifest.json) |
| `object-contract` | [main](../native/main.rs#L952) | [attribute-input-limits](attribute-input-limits/manifest.json), [attribute-reading](attribute-reading/manifest.json), [certificate-objects](certificate-objects/manifest.json), [data-lifetimes](data-lifetimes/manifest.json), [empty-date](empty-date/manifest.json), [gost-secret-storage](gost-secret-storage/manifest.json), [managed-native-comparison](managed-native-comparison/manifest.json), [object-contract](object-contract/manifest.json), [object-creation](object-creation/manifest.json), [object-values](object-values/manifest.json), [reporting-secret-sentinel](reporting-secret-sentinel/manifest.json), [store-visibility](store-visibility/manifest.json) |
| `object-transition` | [main](../native/main.rs#L613) | [object-lifetime](object-lifetime/manifest.json), [object-transition](object-transition/manifest.json), [shared-login](shared-login/manifest.json) |
| `optional-rsa-crt-import` | [extension_cases](../native/extension_cases.rs#L93) | [optional-rsa-crt-import](optional-rsa-crt-import/manifest.json) |
| `pin-admission` | [main](../native/main.rs#L879) | [pin-admission](pin-admission/manifest.json) |
| `pin-contract` | [main](../native/main.rs#L364) | [pin-contract](pin-contract/manifest.json), [pin-standard](pin-standard/manifest.json) |
| `pqc-import-guard` | [main](../native/main.rs#L552) | [pqc-import-guard](pqc-import-guard/manifest.json), [pqc-private-forms](pqc-private-forms/manifest.json) |
| `pqc-random` | [main](../native/main.rs#L491) | [pqc-hedging](pqc-hedging/manifest.json), [pqc-random](pqc-random/manifest.json) |
| `pqc-signing-guard` | [main](../native/main.rs#L631) | [remaining-input-guards](remaining-input-guards/manifest.json) |
| `pqc-transition` | [main](../native/main.rs#L919) | [pqc-transition](pqc-transition/manifest.json) |
| `pqc-vector` | [main](../native/main.rs#L491) | [key-material-observations](key-material-observations/manifest.json), [pqc](pqc/manifest.json), [pqc-absent](pqc-absent/manifest.json), [pqc-binding-negatives](pqc-binding-negatives/manifest.json), [pqc-multipart](pqc-multipart/manifest.json) |
| `pqc-verification-guards` | [main](../native/main.rs#L652) | [pqc-verification-guards](pqc-verification-guards/manifest.json) |
| `public-guard` | [main](../native/main.rs#L610) | [public-guard](public-guard/manifest.json), [selection-native-slots](selection-native-slots/manifest.json) |
| `random-contract` | [main](../native/main.rs#L955) | [random](random/manifest.json), [random-boundaries](random-boundaries/manifest.json) |
| `record-parser` | [main](../native/main.rs#L607) | [object-record-guards](object-record-guards/manifest.json), [record-aead-lengths](record-aead-lengths/manifest.json), [record-algorithm](record-algorithm/manifest.json), [record-and-protocol-fields](record-and-protocol-fields/manifest.json), [record-parser](record-parser/manifest.json), [record-prefixes](record-prefixes/manifest.json), [transport-interface-guards](transport-interface-guards/manifest.json) |
| `recovery-record` | [main](../native/main.rs#L604) | [recovery-destination-guards](recovery-destination-guards/manifest.json), [recovery-lengths](recovery-lengths/manifest.json), [recovery-record](recovery-record/manifest.json) |
| `retained-cipher` | [main](../native/main.rs#L673) | [retained-crypto](retained-crypto/manifest.json) |
| `retained-digest` | [main](../native/main.rs#L699) | [retained-digest](retained-digest/manifest.json) |
| `retained-signature` | [main](../native/main.rs#L673) | [retained-crypto](retained-crypto/manifest.json) |
| `rsa-aes-private-unwrap` | [extension_cases](../native/extension_cases.rs#L88) | [rsa-aes-private-unwrap](rsa-aes-private-unwrap/manifest.json) |
| `rsa-aes-private-wrap` | [extension_cases](../native/extension_cases.rs#L88) | [rsa-aes-private-unwrap](rsa-aes-private-unwrap/manifest.json) |
| `rsa-changed-signature` | [main](../native/main.rs#L584) | [rsa-changed-signature](rsa-changed-signature/manifest.json) |
| `rsa-domain` | [main](../native/main.rs#L876) | [rsa-domain](rsa-domain/manifest.json) |
| `rsa-known` | [main](../native/main.rs#L868) | [rsa-cipher-boundaries](rsa-cipher-boundaries/manifest.json), [rsa-known](rsa-known/manifest.json), [rsa-lengths](rsa-lengths/manifest.json), [rsa-partitions](rsa-partitions/manifest.json), [rsa-raw-single](rsa-raw-single/manifest.json) |
| `rsa-negative` | [main](../native/main.rs#L836) | [rsa-negatives](rsa-negatives/manifest.json), [rsa-wrong-key](rsa-wrong-key/manifest.json) |
| `rsa-transition` | [main](../native/main.rs#L918) | [rsa-init-contract](rsa-init-contract/manifest.json), [rsa-transition](rsa-transition/manifest.json) |
| `rsa-unwrap-negative` | [main](../native/main.rs#L744) | [rsa-unwrap-negatives](rsa-unwrap-negatives/manifest.json) |
| `rsa-usage` | [main](../native/main.rs#L844) | [raw-rsa-usage](raw-rsa-usage/manifest.json), [retained-crypto](retained-crypto/manifest.json), [rsa-usage](rsa-usage/manifest.json) |
| `rsa-vector` | [main](../native/main.rs#L479) | [rsa](rsa/manifest.json) |
| `rsa-wrap-negative` | [main](../native/main.rs#L741) | [rsa-distinct-private-class](rsa-distinct-private-class/manifest.json), [rsa-secret-classes](rsa-secret-classes/manifest.json), [rsa-wrap-label](rsa-wrap-label/manifest.json), [rsa-wrap-negatives](rsa-wrap-negatives/manifest.json), [rsa-wrap-private-class](rsa-wrap-private-class/manifest.json) |
| `runtime-successor` | [main](../native/main.rs#L373) | [runtime-successor](runtime-successor/manifest.json) |
| `search-population` | [main](../native/main.rs#L885) | [search-partitions](search-partitions/manifest.json), [search-population](search-population/manifest.json), [search-selection](search-selection/manifest.json) |
| `search-transition` | [main](../native/main.rs#L882) | [search-transition](search-transition/manifest.json) |
| `session-abi-widths` | [extension_cases](../native/extension_cases.rs#L90) | [session-abi-widths](session-abi-widths/manifest.json) |
| `session-contract` | [main](../native/main.rs#L361) | [sessions](sessions/manifest.json) |
| `session-conversion` | [main](../native/main.rs#L658) | [session-conversion](session-conversion/manifest.json) |
| `shared-module` | [main](../native/main.rs#L412) | [module-controls](module-controls/manifest.json) |
| `signature-extension-single-route` | [extension_cases](../native/extension_cases.rs#L144) | [signature-extension-route](signature-extension-route/manifest.json) |
| `signature-extension-stream-route` | [extension_cases](../native/extension_cases.rs#L140) | [signature-extension-route](signature-extension-route/manifest.json) |
| `signature-result-metadata` | [extension_cases](../native/extension_cases.rs#L112) | [result-metadata](result-metadata/manifest.json) |
| `signing-guards` | [main](../native/main.rs#L661) | [signing-guards](signing-guards/manifest.json) |
| `single-part-guard-0` | [main](../native/main.rs#L780) | [single-part-guard](single-part-guard/manifest.json) |
| `single-part-guard-1` | [main](../native/main.rs#L788) | [single-part-guard](single-part-guard/manifest.json) |
| `single-part-guard-2` | [main](../native/main.rs#L796) | [single-part-guard](single-part-guard/manifest.json) |
| `single-part-guard-3` | [main](../native/main.rs#L804) | [single-part-guard](single-part-guard/manifest.json) |
| `single-part-guard-4` | [main](../native/main.rs#L812) | [single-part-guard](single-part-guard/manifest.json) |
| `single-part-guard-5` | [main](../native/main.rs#L820) | [simple-guards](simple-guards/manifest.json) |
| `single-signature-transition` | [main](../native/main.rs#L922) | [rsa-init-contract](rsa-init-contract/manifest.json), [single-rsa-state](single-rsa-state/manifest.json) |
| `symmetric-guards` | [main](../native/main.rs#L625) | [managed-mac-byte-view](managed-mac-byte-view/manifest.json), [symmetric-guards](symmetric-guards/manifest.json) |
| `ticket-boundary` | [main](../native/main.rs#L475) | [ticket-boundary](ticket-boundary/manifest.json) |
| `ticket-family` | [main](../native/main.rs#L475) | [remaining-ticket-guards](remaining-ticket-guards/manifest.json), [ticket-family](ticket-family/manifest.json) |
| `ticket-identity` | [main](../native/main.rs#L475) | [remaining-ticket-guards](remaining-ticket-guards/manifest.json), [ticket-identity](ticket-identity/manifest.json) |
| `ticket-owner-identity` | [main](../native/main.rs#L592) | [digest-publication](digest-publication/manifest.json), [remaining-ticket-guards](remaining-ticket-guards/manifest.json), [ticket-identity-complete](ticket-identity-complete/manifest.json) |
| `ticket-state-guard` | [main](../native/main.rs#L616) | [ticket-state-guard](ticket-state-guard/manifest.json) |
| `token-drain-session` | [main](../native/main.rs#L649) | [token-drain-session](token-drain-session/manifest.json) |
| `token-label-contract` | [main](../native/main.rs#L367) | [authentication-completion](authentication-completion/manifest.json), [token-initialization-preservation](token-initialization-preservation/manifest.json), [token-labels](token-labels/manifest.json), [token-open-session](token-open-session/manifest.json), [token-pin-boundaries](token-pin-boundaries/manifest.json) |
| `transport-negative` | [main](../native/main.rs#L747) | [kwp-negatives](kwp-negatives/manifest.json), [transport-negatives](transport-negatives/manifest.json), [unwrap-boundaries](unwrap-boundaries/manifest.json) |
| `trusted-wrap-advanced` | [extension_cases](../native/extension_cases.rs#L116) | [trusted-wrap](trusted-wrap/manifest.json) |
| `trusted-wrap-session` | [extension_cases](../native/extension_cases.rs#L116) | [trusted-wrap](trusted-wrap/manifest.json) |
| `typed-selection` | [main](../native/main.rs#L546) | [additional-selection](additional-selection/manifest.json), [asymmetric-selection](asymmetric-selection/manifest.json), [exact-selection](exact-selection/manifest.json), [public-selection](public-selection/manifest.json), [rsa-generation-exponent](rsa-generation-exponent/manifest.json), [rsa-selection](rsa-selection/manifest.json), [selection-native-slots](selection-native-slots/manifest.json), [symmetric-selection](symmetric-selection/manifest.json) |
| `unsupported-lifecycle` | [main](../native/main.rs#L628) | [cms-initializers](cms-initializers/manifest.json), [curve-operations](curve-operations/manifest.json), [ecdh-parameters](ecdh-parameters/manifest.json), [ecdh-peer-partitions](ecdh-peer-partitions/manifest.json), [hkdf-refusal](hkdf-refusal/manifest.json), [message-initialization](message-initialization/manifest.json), [multipart-and-block](multipart-and-block/manifest.json), [recovery-cipher-initializers](recovery-cipher-initializers/manifest.json), [rsa-native-roundtrip](rsa-native-roundtrip/manifest.json), [unsupported-lifecycle](unsupported-lifecycle/manifest.json) |
| `verification-guards` | [main](../native/main.rs#L664) | [dsa-der-guard](dsa-der-guard/manifest.json), [object-record-guards](object-record-guards/manifest.json), [simple-guards](simple-guards/manifest.json), [verification-guards](verification-guards/manifest.json) |

## Other fixture manifests

- [compile-contracts](compile-contracts/manifest.json)
- [compile-iv-widths](compile-iv-widths/manifest.json)
- [compile-native-outputs](compile-native-outputs/manifest.json)
- [compile-protocol-lifetimes](compile-protocol-lifetimes/manifest.json)
- [compile-protocol-owners](compile-protocol-owners/manifest.json)
- [compile-secret-aggregates](compile-secret-aggregates/manifest.json)
- [der-framing](der-framing/manifest.json)
- [digest](digest/manifest.json)
- [digest-boundaries](digest-boundaries/manifest.json)
- [digest-complements](digest-complements/manifest.json)
- [parameters](parameters/manifest.json)
