# Security

Keywarden reads `sshd -T` and `authorized_keys`. It fingerprints public keys in memory and writes reports that contain fingerprints, types, bit lengths, and comments. It does not write key bodies.

Do not include private keys, live `authorized_keys` files, or raw collector output in an issue. A fingerprint and the finding code are enough.

Report a vulnerability by opening a private security advisory on this repository, or through the contact on the maintainer's GitHub profile if advisories are unavailable. Please allow time to fix before writing about it in public.
