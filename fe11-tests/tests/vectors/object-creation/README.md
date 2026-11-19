# Creation template contracts

These tests use public, extractable session objects on isolated tokens. Equal
duplicates may succeed or return `CKR_TEMPLATE_INCONSISTENT`; successful creation
must preserve the exact class, key type and value. Different values for the same
attribute are inconsistent, not an unspecified first-value/last-value policy.

Class/key-type mismatches use standard integer values with incompatible meanings.
The mechanism-object probe omits its read-only mechanism-type attribute and uses
only common object attributes. Its expected refusal describes the configured
recipe's absent class, not a requirement that every module reject that class.

The driver selects the exact cleanup trace from the explicit object-returned
observation. Every returned reference is retained before reporting or assertions;
an unexpected successful creation is destroyed and remains a failure. No oracle
permits a missing template attribute, local rejection or unrelated native code.
