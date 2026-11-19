# Empty plaintext

Unpadded ECB, CBC and CTR transform an empty plaintext into an empty ciphertext.
CBC with PKCS#7 padding produces one complete padding block. Its inverse returns
an empty plaintext from that block; this does not claim that an empty padded
ciphertext is valid. Expected bytes are calculated independently with
PyCryptodome 3.23.0. The original public key provenance accompanies each case.
Both directions retain exact byte comparisons and native-call observations.
