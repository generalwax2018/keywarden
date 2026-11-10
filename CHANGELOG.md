# Changelog

## 0.1.1 — 2026-11-10

Security and correctness fixes found before the public release. Upgrade from 0.1.0.

- Security: a user who controls their own `authorized_keys` could write collector markers into it and make a remote or piped check report the daemon as safe (for example `PermitRootLogin yes` reported as a pass). Key lines are now prefixed on the host, the collector protocol is version 2, and the parser refuses repeated, out-of-order, unprefixed, or truncated output. In an inventory, that host fails with `collector-output`.
- An account whose home or `.ssh` could not be read was skipped silently. It is now reported as not checked. A local run as a non-root user no longer stops with a permission error.
- With passwordless sudo, the remote collector now reads other users' homes, not only the key file.
- `sshd` is found in `/usr/sbin`, `/usr/local/sbin`, and `/sbin` when it is not on PATH. When `sshd -T` cannot run, one `sshd-config` warning replaces the per-setting warnings.
- `Match` blocks are detected. Root is evaluated with `sshd -T -C`, and a block that re-enables root or password login for root fails the check.
- Ansible inventories: `[group:children]` now passes parent group vars to child hosts, `ansible_ssh_private_key_file` is passed to `ssh -i`, `ansible_ssh_user` and `ansible_ssh_host` are read, and YAML inventories are refused with a message instead of being misread.
- Drift: findings carry a `fingerprints` array, and a check that was already failing is marked `new-keys` when it names a new fingerprint.
- `--redact-comments` leaves key comments out of the output.
- Packaging: `pip install` from the tag failed on current setuptools because of a duplicate license declaration. Fixed. The distribution is named `keywarden-ssh` because `keywarden` on PyPI is an unrelated project.
- Tests skip, instead of erroring, when `ssh-keygen` is not installed. CI adds a job against a real OpenSSH server.

## 0.1.0 — 2026-11-10

First release. One command checks a machine, a host, or an Ansible inventory.

- Read this machine, or one host over SSH batch mode, or collector output on stdin.
- Walk an Ansible INI inventory. The log lists failures only. Each fingerprint is reported once, with the hosts where it failed. An unreachable host fails that host and the run continues. Passwords in the inventory are ignored.
- Check PermitRootLogin (including `prohibit-password` and `without-password`), password and keyboard-interactive authentication, empty passwords, public-key authentication, a key on root, `.ssh` and `authorized_keys` modes, DSA and RSA under 3072 bits, and keys that are not in the set you passed with `--allow`.
- An unknown or changed SSH host key fails that host. `--accept-new` is required to trust a key that is not already in `known_hosts`.
- Refuse private-key input. Do not copy key bodies into the JSON report.
- Check SSH certificates (validity, user versus host), `cert-authority` lines, trusted user CAs, revocation, `AuthorizedKeysCommand`, extra `AuthorizedKeysFile` paths, host-based authentication, authentication methods, and weak algorithms `sshd` still accepts.
- Drop key text after it is fingerprinted. Refuse OpenSSH and PuTTY private keys without keeping a copy.

