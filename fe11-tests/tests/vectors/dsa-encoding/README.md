# DSA scalar encodings

Published NIST DSA public parameters provide real imported verification keys
for the four 1024/160, 2048/224, 2048/256 and 3072/256 domains. No private key
material is needed. Each domain exercises zero, leading zero padding, sign-bit
padding on either scalar, and both short and long raw inputs.

The expected DER is constructed independently from ASN.1 integer rules.
Conversion does not assert signature validity. Positive controls bracket each
case, and native call counters must remain unchanged during conversion.
