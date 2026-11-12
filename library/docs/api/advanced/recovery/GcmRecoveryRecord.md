Sensitive recovery record captured under the owning operation's guards.
Contains ciphertext inputs and plaintext from completed native GCM messages.
A zero-bit tag provides no authentication.
The persistence service must protect the entire record and bind its command,
revision and durable key generation. Export neither closes the source nor
grants permission to recover it. This object holds no native/session lease.
