# Changelog

## 0.1.0 — 2026-11-10

Free release. One command checks a machine, a host, or an Ansible inventory.

- Read this machine, or one host over SSH batch mode, or collector output on stdin.
- Walk an Ansible INI inventory. The log lists failures only (hostname, check, fingerprint). An unreachable host fails that host and the run continues. Passwords in the inventory are ignored.
- Check PermitRootLogin (including `prohibit-password` and `without-password`), password and keyboard-interactive authentication, empty passwords, public-key authentication, a key on root, `.ssh` and `authorized_keys` modes, DSA and RSA under 3072 bits, and keys that are not in the set you passed with `--allow`.
- An unreadable root `authorized_keys` is a warning, not a pass.
- Refuse private-key input. Do not copy key bodies into the JSON report.
- Check SSH certificates (validity, user versus host), `cert-authority` lines, trusted user CAs, revocation, `AuthorizedKeysCommand`, extra `AuthorizedKeysFile` paths, host-based authentication, authentication methods, and weak algorithms `sshd` still accepts.
- Drop key text after it is fingerprinted. Refuse OpenSSH and PuTTY private keys without keeping a copy.

Not in this release: schedules, retained evidence, sign-in, or pushing keys.
