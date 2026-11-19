# AES-CBC retained output capacity

Encryption and decryption use a32-byte message with capacities0,31 and32.
A short result is resumed through storage replacement and poll; input is
submitted once. Progress counters and the native trace reject reinitialization
or replay. Exact independent CBC bytes are retained through owner cleanup.

The reference was generated with Python cryptography and checked first against
the named published AES-CBC control in each manifest entry. It is not obtained
from Fe11 or the native module under test.
