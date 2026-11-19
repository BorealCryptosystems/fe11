# DSA DER boundary

Public domain parameters and public key from the first successful signature
verification vector in NIST CAVP DSA2 SigVer.rsp, CAVS 11.0, 1 April 2011.
The manifest records the official archive URL, archive/member digests and
vector ordinal. The public signature was independently verified using integer
arithmetic before extracting p, q, g and y into a canonical SPKI.

The negative operand is the empty DER SEQUENCE 30 00. Valid scalar encodings
are checked before and after rejection; this conversion check makes no claim
that the control scalars themselves are a valid signature.
