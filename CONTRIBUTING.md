# Contributing

Thanks for helping. Keywarden is small on purpose: standard library only, Python 3.9 and newer, and nothing that stores or prints key bodies.

## Before you open an issue

- Do not paste private keys, live `authorized_keys` files, or raw collector output. A fingerprint, the finding code, and the relevant `sshd -T` lines are enough.
- Security problems go through a private advisory, not an issue. See [SECURITY.md](SECURITY.md).

## Changes

1. Open an issue first for anything larger than a fix, so we can agree on the shape.
2. Keep the rule that a check which could not see something is a warning, never a pass.
3. Add a test. Run `python3 -m unittest discover -s tests -v` before you push.
4. If you change `REMOTE_SCRIPT`, keep it POSIX `sh`, keep usernames as arguments (never interpolated), and keep every line read from a key file prefixed with `K `. Bump `PROTOCOL_VERSION` if the wire format changes.
5. Add a line to `CHANGELOG.md`.

By contributing you agree your work is released under the MIT license.
