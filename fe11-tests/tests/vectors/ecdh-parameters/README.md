# ECDH parameter contracts

Every case changes one parameter partition of the retained, published P-256
private scalar, peer point and shared secret. The source and exact fixture digest
identify this tuple; the public test scalar is not an operational secret.

All non-NULL CKD constants in the pinned header are submitted independently.
Constants intended for other mechanisms are labelled inapplicable to ECDH; their
refusal is not a missing positive ECDH capability. The named EcdhKdf constructors
also supply their public numeric identifiers to the same native derivation route.
This does not claim execution of the distinct typed AgreementKey API.

Absent shared data and the exact32-byte result reuse their existing controls.
Present-empty and binary shared data are separate negative requests. Lengths
0,1,31,33 have separate templates. Successful truncation must keep the trailing
bytes of Z; a larger result is not permitted. Allowed template refusals are
reported as refusals, never as a successful known-answer result.

The opaque output is sensitive and nonextractable. Its value read must return
unavailable; its HMAC over `abc` must match the independently calculated tag.
Every native creation remains owned until explicit cleanup, including an object
returned unexpectedly or with the wrong length.
