# ECDH point representations

These cases preserve a published P-256 agreement from the adjacent ECDH corpus.
SEC1 compression uses the unchanged x-coordinate and the least significant bit
of y. DER OCTET STRING wrappers contain exactly the original or compressed
point. The private scalar, CKD_NULL parameters and expected shared secret do
not change. The native parameter bytes are passed as provided; each successful
case must return the exact published secret. Raw uncompressed controls and
invalid-point cases remain separately attributable.
