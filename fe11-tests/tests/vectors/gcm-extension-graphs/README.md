# GCM input graph boundaries

The explicit extension ABI is CK_GCM_PARAMS. IV and AAD use one owned block:
disjoint input spans, the same input bytes, NULL with zero length, or an end
pointer with zero length. Pointer fields are distinct and initialized to zero
before relocation. All scalars and alignment follow fe11-sys for the target.
No malformed graph or forbidden output overlap is submitted.

Session and AdvancedSession encrypt and decrypt against exact independent
PyCryptodome 3.23.0 references. The all-zero key, IV and plaintext are public
test data. The empty-AAD reference is checked against the known NIST GCM answer;
the nonempty-AAD references are generated answers, not published NIST vectors.
Native output is separate from the read-only graph. Classic GCM has no writable
parameter outputs, so these cases do not claim that capability.
