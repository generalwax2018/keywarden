# Changelog

## 0.3.1 — 2026-11-10

- Windows: `--host` and `--inventory` send the collector script as bytes, so Windows no longer turns its newlines into CRLF on the way to the remote shell.
- Windows: `--local` (and **This machine** in the GUI) explains that it needs to run on the Linux server instead of stopping with a Python error. The GUI greys the option out.
- Unexpected errors end in a one-line message with a link to report them; `KEYWARDEN_DEBUG=1` shows the details. Piping output into `head` no longer prints an error.
- README: a one-minute start with the lab hosts.

## 0.3.0 — 2026-11-10

- Compliance mapping: every check maps to CIS Controls v8, NIST SP 800-53 Rev. 5, PCI DSS v4.0, and NERC CIP (CIP-004-7, CIP-005-7, CIP-007-6). Findings in the JSON report carry `controls`; the UI shows them under each finding. See docs/compliance.md.
- Evidence report: `--evidence report.html` and **Evidence** in `keywarden ui`. Scope, run details, a control coverage table per framework, findings, the access review table, accepted risks, and a SHA-256 of the embedded JSON report.
- Terminal output: a summary line, colour (off for pipes, `NO_COLOR`, and `--color never`; on in Windows Terminal), and passing checks hidden unless `--verbose`. Inventory runs end with a host count.
- Published to PyPI as `keywarden-ssh`, from a tag, by a trusted-publishing workflow.
- README: a demo GIF and screenshots.

## 0.2.0 — 2026-11-10

Access review: who each key lets in, as what, from where, and whether anyone still uses it.

- `keywarden where` finds every host and account that accepts a key, by fingerprint or public key file, including `cert-authority` lines and recent logins from keys not in a readable file. Exits like `grep`.
- Last use per key from sshd's own log: the systemd journal (sshd units, uid 0 only) or rotated `auth.log` / `secure` files. New `stale-key` (`--stale-days`, default 90) and `auth-log` checks. Keys are called stale only when the logs cover the whole window.
- Reach per account from `sudo -l -U` and group membership: `root`, `root-nopasswd` (including shell-escape commands and `docker`/`lxd`/`disk` groups), `root-password`, `limited`, `none`. New `key-to-root` and `key-source` checks.
- `authorized_keys` options are parsed: `from=`, `command=`, `restrict` and the re-enable options, forwarding, `environment=`, `expiry-time`. New `forced-command-forwarding`, `key-environment`, `expired-key`, and `log-level` checks.
- Access review table in the JSON report (`keys`), on the terminal (`--keys`), and as CSV (`--csv`), with spreadsheet formula injection blocked.
- Waivers (`--waivers`, JSON or TOML): accepted risks with a reason, an owner or ticket, and a required end date. Waived findings are `accepted`; expired and unused waivers are reported.
- `--redact-addresses` drops the last login address.
- `keywarden ui`: the checks in a browser tab served from this machine only (127.0.0.1, one-time token, no external requests, no key storage), with a lab of six made-up hosts, the access review table, find a key, and JSON/CSV export.
- Collector protocol 3. Output from the 0.1.1 collector (protocol 2) is still read; it has no sudo or login data, so those checks are skipped.

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

