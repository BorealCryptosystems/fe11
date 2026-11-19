# Named curve operation probes

Every OID from the reviewed curve inventory is requested before selecting
successful cases. Advertised prime-field curves and unadvertised binary or
out-of-range curves retain their distinct applicability classifications.
An unsupported curve is reported with its native result, not silently skipped.

Each nominal probe generates two independent pairs and checks the actual curve
parameters and encoded point widths. The first test scalar and public point are
reimported; generated and imported signing owners are cross-verified. Both pairs
derive CKD_NULL secrets of the complete field width and compare them. Generated
private test values stay in the bounded worker memory; reports expose no scalar
or shared secret. These native round trips do not independently establish curve
arithmetic. Published external known-answer vectors remain separate evidence.

The unknown-OID request keeps an otherwise complete EC generation template. Its
GENERAL_ERROR remains effect-uncertain and must not publish created objects.
Every unexpectedly returned owner is retained through explicit cleanup.
