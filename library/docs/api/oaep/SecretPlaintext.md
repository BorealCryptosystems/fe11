Plaintext in a stable heap allocation erased in full on drop (including unwind).
No formatter, implicit clone, or conversion to an ordinary Vec is provided.
Fill the exposed slice directly; caller-created copies remain the caller's
responsibility. Provider, compiler, kernel copies and fatal abort are outside
the erasure guarantee. This type does not lock pages or isolate the process.
