# ECDH qualification scope on the pinned SoftHSM recipe

The generated-key scenarios below are assessed from the raw/DER decoder, not from the list of past failures. The decoder belongs to SoftHSM commit `7380895665c3094a6f57640085bee97dcfeb1496`, `src/lib/SoftHSM.cpp`, function `getECDHPubData`.

An uncompressed SEC1 point contains `04 || X || Y`, with length `1 + 2 * ceil(field_bits / 8)`. The decoder treats lengths 32, 56, 65, 97 and 133 as raw. Otherwise it can mistake a valid coordinate prefix for a DER length. Both short-form and long-form length branches were examined. In this corpus every exposed long-form domain is already exposed to a short-form header. For excluded domains, the first coordinate byte cannot reach either branch, or the length is recognized as raw.

The 45 exposed generated-key scenarios (360 hosted coordinates) are `NOT_QUALIFIED`, including isolated raw successes. This is static domain exposure; it does not claim that a native failure was measured on every curve. The existing direct diagnostics establish the module defect. Each new refusal still needs its full bounded observation, or an unchanged exact documented divergence, to avoid blocking CI.

The 330 fixed ECDH-related fixtures were inspected separately, including the binary-curve generators and actual peer overrides. None adds a raw/DER collision: four intentionally DER-encoded point-form fixtures are decoded as DER as intended. The absent-selector and typed KDF/guard routes use fixed P-256/P-384 inputs or local refusal paths. Their oracles and qualification remain unchanged.

Domain parameters are taken from the public OpenSSL curve table; the audited source hash is `d1564b90893609ed761db376ab7023e8ee60482438748acab031ed3e3839641a`. The definition-bound machine-readable files are [domains](scripts/native-ecdh-domains.json) and [classification](scripts/native-unqualified.json). A new curve or changed definition requires reassessment in preflight.

| Scenario (`curve.operations.` prefix) | Field bits | Raw bytes | Assessment |
|---|---:|---:|---|
| `secp224r1` | 224 | 57 | Not qualified: ambiguous header domain |
| `secp384r1` | 384 | 97 | Raw length recognized directly |
| `secp521r1` | 521 | 133 | Raw length recognized directly |
| `X9_62_prime192v1` | 192 | 49 | Not qualified: ambiguous header domain |
| `X9_62_prime256v1` | 256 | 65 | Raw length recognized directly |
| `sect163k1` | 163 | 43 | Field bound excludes ambiguous header |
| `sect163r2` | 163 | 43 | Field bound excludes ambiguous header |
| `sect233k1` | 233 | 61 | Field bound excludes ambiguous header |
| `sect233r1` | 233 | 61 | Field bound excludes ambiguous header |
| `sect283k1` | 283 | 73 | Field bound excludes ambiguous header |
| `sect283r1` | 283 | 73 | Field bound excludes ambiguous header |
| `sect409k1` | 409 | 105 | Field bound excludes ambiguous header |
| `sect409r1` | 409 | 105 | Field bound excludes ambiguous header |
| `sect571k1` | 571 | 145 | Field bound excludes ambiguous header |
| `sect571r1` | 571 | 145 | Field bound excludes ambiguous header |
| `secp112r1` | 112 | 29 | Not qualified: ambiguous header domain |
| `secp112r2` | 112 | 29 | Not qualified: ambiguous header domain |
| `secp128r1` | 128 | 33 | Not qualified: ambiguous header domain |
| `secp128r2` | 128 | 33 | Not qualified: ambiguous header domain |
| `secp160k1` | 160 | 41 | Not qualified: ambiguous header domain |
| `secp160r1` | 160 | 41 | Not qualified: ambiguous header domain |
| `secp160r2` | 160 | 41 | Not qualified: ambiguous header domain |
| `secp192k1` | 192 | 49 | Not qualified: ambiguous header domain |
| `secp224k1` | 224 | 57 | Not qualified: ambiguous header domain |
| `secp256k1` | 256 | 65 | Raw length recognized directly |
| `X9_62_prime192v2` | 192 | 49 | Not qualified: ambiguous header domain |
| `X9_62_prime192v3` | 192 | 49 | Not qualified: ambiguous header domain |
| `X9_62_prime239v1` | 239 | 61 | Not qualified: ambiguous header domain |
| `X9_62_prime239v2` | 239 | 61 | Not qualified: ambiguous header domain |
| `X9_62_prime239v3` | 239 | 61 | Not qualified: ambiguous header domain |
| `sect113r1` | 113 | 31 | Field bound excludes ambiguous header |
| `sect113r2` | 113 | 31 | Field bound excludes ambiguous header |
| `sect131r1` | 131 | 35 | Field bound excludes ambiguous header |
| `sect131r2` | 131 | 35 | Field bound excludes ambiguous header |
| `sect163r1` | 163 | 43 | Field bound excludes ambiguous header |
| `sect193r1` | 193 | 51 | Field bound excludes ambiguous header |
| `sect193r2` | 193 | 51 | Field bound excludes ambiguous header |
| `sect239k1` | 239 | 61 | Not qualified: ambiguous header domain |
| `X9_62_c2pnb163v1` | 163 | 43 | Field bound excludes ambiguous header |
| `X9_62_c2pnb163v2` | 163 | 43 | Field bound excludes ambiguous header |
| `X9_62_c2pnb163v3` | 163 | 43 | Field bound excludes ambiguous header |
| `X9_62_c2pnb176v1` | 176 | 45 | Not qualified: ambiguous header domain |
| `X9_62_c2tnb191v1` | 191 | 49 | Not qualified: ambiguous header domain |
| `X9_62_c2tnb191v2` | 191 | 49 | Not qualified: ambiguous header domain |
| `X9_62_c2tnb191v3` | 191 | 49 | Not qualified: ambiguous header domain |
| `X9_62_c2pnb208w1` | 208 | 53 | Not qualified: ambiguous header domain |
| `X9_62_c2tnb239v1` | 239 | 61 | Not qualified: ambiguous header domain |
| `X9_62_c2tnb239v2` | 239 | 61 | Not qualified: ambiguous header domain |
| `X9_62_c2tnb239v3` | 239 | 61 | Not qualified: ambiguous header domain |
| `X9_62_c2pnb272w1` | 272 | 69 | Not qualified: ambiguous header domain |
| `X9_62_c2pnb304w1` | 304 | 77 | Not qualified: ambiguous header domain |
| `X9_62_c2tnb359v1` | 359 | 91 | Not qualified: ambiguous header domain |
| `X9_62_c2pnb368w1` | 368 | 93 | Not qualified: ambiguous header domain |
| `X9_62_c2tnb431r1` | 431 | 109 | Not qualified: ambiguous header domain |
| `wap_wsg_idm_ecid_wtls1` | 113 | 31 | Field bound excludes ambiguous header |
| `wap_wsg_idm_ecid_wtls3` | 163 | 43 | Field bound excludes ambiguous header |
| `wap_wsg_idm_ecid_wtls4` | 113 | 31 | Field bound excludes ambiguous header |
| `wap_wsg_idm_ecid_wtls5` | 163 | 43 | Field bound excludes ambiguous header |
| `wap_wsg_idm_ecid_wtls6` | 112 | 29 | Not qualified: ambiguous header domain |
| `wap_wsg_idm_ecid_wtls7` | 160 | 41 | Not qualified: ambiguous header domain |
| `wap_wsg_idm_ecid_wtls8` | 112 | 29 | Not qualified: ambiguous header domain |
| `wap_wsg_idm_ecid_wtls9` | 160 | 41 | Not qualified: ambiguous header domain |
| `wap_wsg_idm_ecid_wtls10` | 233 | 61 | Field bound excludes ambiguous header |
| `wap_wsg_idm_ecid_wtls11` | 233 | 61 | Field bound excludes ambiguous header |
| `wap_wsg_idm_ecid_wtls12` | 224 | 57 | Not qualified: ambiguous header domain |
| `brainpoolP160r1` | 160 | 41 | Not qualified: ambiguous header domain |
| `brainpoolP160t1` | 160 | 41 | Not qualified: ambiguous header domain |
| `brainpoolP192r1` | 192 | 49 | Not qualified: ambiguous header domain |
| `brainpoolP192t1` | 192 | 49 | Not qualified: ambiguous header domain |
| `brainpoolP224r1` | 224 | 57 | Not qualified: ambiguous header domain |
| `brainpoolP224t1` | 224 | 57 | Not qualified: ambiguous header domain |
| `brainpoolP256r1` | 256 | 65 | Raw length recognized directly |
| `brainpoolP256t1` | 256 | 65 | Raw length recognized directly |
| `brainpoolP320r1` | 320 | 81 | Not qualified: ambiguous header domain |
| `brainpoolP320t1` | 320 | 81 | Not qualified: ambiguous header domain |
| `brainpoolP384r1` | 384 | 97 | Raw length recognized directly |
| `brainpoolP384t1` | 384 | 97 | Raw length recognized directly |
| `brainpoolP512r1` | 512 | 129 | Not qualified: ambiguous header domain |
| `brainpoolP512t1` | 512 | 129 | Not qualified: ambiguous header domain |
| `sm2` | 256 | 65 | Raw length recognized directly |
| `unknown-enterprise-oid` | — | — | Unknown-OID negative; no agreement |
