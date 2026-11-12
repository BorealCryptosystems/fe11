# Security policy

Report suspected vulnerabilities privately to **security@borealcryptosystems.com**.
Include the affected package/version, platform, relevant module behavior, impact
and a minimal reproducer where possible. Do not send PINs, private keys, token
credentials or unredacted production logs. Please coordinate disclosure before
publishing exploit details. No fixed response deadline is promised.

The native module and any optional verification component execute in the host
process and must be trusted by the application. Interface checks do not sandbox
hostile native code. Applications must satisfy documented unsafe obligations,
control module loading and handle errors without assuming that no effect occurred.

Security fixes and their affected versions will be documented publicly.
