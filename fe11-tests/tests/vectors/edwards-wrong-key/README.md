# Edwards verification with a different valid key

Each case creates two real pairs on the same curve, Ed25519 or Ed448. Each pair
first signs and verifies the message `abc`. Verification of the first signature
with the second public key must then return CKR_SIGNATURE_INVALID. Finally the
unchanged first pair verifies again, proving that the refusal was terminal.

Both pairs remain owned until explicit destruction, including on failed
assertions. No private value is exported. These are generated-key negatives;
published-vector import and public-point encoding are separate assertions.
