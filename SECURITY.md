# Security

Keywarden reads `sshd -T` and `authorized_keys`. It fingerprints public keys in memory and writes reports that contain fingerprints, types, bit lengths, and comments. It does not write key bodies.

Do not include private keys, live `authorized_keys` files, or raw collector output in an issue. A fingerprint and the finding code are enough.

Report a vulnerability through **Security → Report a vulnerability** on this repository (a private advisory). If that is unavailable, use the contact on the maintainer's GitHub profile. You should hear back within 7 days. Please allow time for a fix before writing about it in public.

## Supported versions

Only the latest release gets security fixes. 0.1.0 has a known report-spoofing issue fixed in 0.1.1.
