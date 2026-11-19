# RSA unwrapping negatives

Public RSA key and OAEP envelope come from the Wycheproof source identified
by each manifest entry. Wycheproof Apache-2.0 notices are retained with the
existing fixture distribution. The PKCS#1 v1.5 envelope is independently derived
with public test padding 0x55. RSA-AES uses a public zero OAEP seed and the
unchanged first RFC 5649 section 6 envelope. These fixed values are test data.

RSA integer relations and OAEP decoding are independently checked when preparing
the fixtures. Every native negative follows an exact successful unwrapping
control; the output must equal the complete known plaintext.
