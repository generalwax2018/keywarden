# Changelog

## 0.1.0 — 2026-11-10

Free release. One host per run.

- Read this machine, or one host over SSH batch mode, or collector output on stdin.
- Check PermitRootLogin (including `prohibit-password` and `without-password`), password and keyboard-interactive authentication, empty passwords, public-key authentication, a key on root, `.ssh` and `authorized_keys` modes, DSA and RSA under 3072 bits, and keys that are not in the set you passed with `--allow`.
- An unreadable root `authorized_keys` is a warning, not a pass.
- Refuse private-key input. Do not copy key bodies into the JSON report.
- Compare a prior report and mark a check regressed, new, or cleared.

Not in this release: fleets, schedules, saved evidence, sign-in, or pushing keys.
