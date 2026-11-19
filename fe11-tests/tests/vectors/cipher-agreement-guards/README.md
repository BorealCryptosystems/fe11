# Cipher and agreement input guards

AES stream declarations and dual-operation input accounting use real generated
AES keys. The ECDH domain case combines a generated P-256 key with the exact
public P-384 SPKI attributed in the manifest. The X25519 constructor receives
the exact undersized public coordinate. Each case checks its precise refusal,
no native cryptographic initialization, an idle digest, and explicit cleanup.
