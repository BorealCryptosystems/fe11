# Native general-length MAC refusals

Each fixture requests a one-byte GENERAL MAC with a matching real key type.
The module catalogue must omit the selected mechanism. The case requires
CKR_MECHANISM_INVALID at both SignInit and VerifyInit, through the single and
multipart public routes. The verification operand is not a known answer; no
Sign or Verify call is allowed after these Init refusals. This establishes
native refusal propagation, not support for native MAC truncation.
