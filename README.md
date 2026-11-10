# Keywarden

Check SSH posture around the public keys you already push. Keywarden does not push keys, and it does not store them.

You keep using whatever already places `authorized_keys` on a machine (Ansible, a script, by hand). Keywarden reads the effective daemon config and the keys that are actually authorized, fingerprints those keys, and drops the bodies before it writes a report.

This is the free release: **one host per run**. Fleet schedules, retained evidence, and sign-in are not in it.

## Install

Python 3.9 or newer. No third-party packages.

```sh
python3 -m pip install git+https://github.com/generalwax2018/keywarden.git
```

Or clone this repository and run it from the tree:

```sh
git clone https://github.com/generalwax2018/keywarden.git
cd keywarden
PYTHONPATH=src python3 -m keywarden --version
```

## Check this machine

```sh
keywarden check --local --allow team.pub
```

`team.pub` is the public keys you intend to be authorized, one OpenSSH line each. Keywarden fingerprints them for the comparison and does not copy them into the report.

A failing check exits 1. A clean or warning-only check exits 0. Bad input, including a private key, exits 2 and writes no report.

```sh
keywarden check --local --allow team.pub --output keywarden-report.json
```

The JSON file has fingerprints, key types, bit lengths, comments, daemon settings, and findings. It does not have key bodies. Do not point `--allow` at a private key. If one is present, Keywarden stops and keeps nothing.

## Check one other host

```sh
keywarden check --host deploy@app-web-03.example --allow team.pub --json
```

This is `ssh` in batch mode (no password prompt). The remote command prints `sshd -T` and `authorized_keys` back to this process. Fingerprints are computed here. Nothing is written on the remote host.

Reading root, and reading other accounts, needs to be allowed: run as root, or have passwordless `sudo` for `sshd -T` and `cat` of `authorized_keys`. If root's file cannot be read, the root-key check is a **warning, not a pass**. A hidden root key must not look clean.

`--account` adds a specific user. Repeat it. Accounts that already have an `authorized_keys` file are included when the file is visible.

## What is checked

| Code | Fails when |
| --- | --- |
| `permit-root` | `PermitRootLogin` is anything but `no`. `prohibit-password` and `without-password` still allow a root key, so they fail. |
| `password-auth` | `PasswordAuthentication` is on |
| `keyboard-interactive` | `KbdInteractiveAuthentication` is on |
| `empty-passwords` | `PermitEmptyPasswords` is on |
| `pubkey-auth` | `PubkeyAuthentication` is off |
| `root-authorized-key` | root has a key. Unreadable is a warning. |
| `permissions` | `.ssh` or `authorized_keys` is group- or world-accessible |
| `weak-algorithm` | DSA, or RSA under 3072 bits |
| `outside-push` | a non-root key is not in `--allow` |

`forced-commands-only` is a warning. Pass `--no-weak` or `--no-outside` to skip those two comparisons.

## Drift

Keep the previous report (it has no key bodies) and pass it next time:

```sh
keywarden check --local --allow team.pub --prior keywarden-report.json
```

A check that was a pass and is now a fail is marked `regressed`. A new failure is `new`. A failure that cleared is `cleared`.

## Offline observation

If you would rather not have Keywarden open SSH itself, run the collector on the host and pipe it. Do not save that stream: it contains public keys. The report does not.

```sh
python3 -c 'from keywarden.collect import REMOTE_SCRIPT; print(REMOTE_SCRIPT)' | sh | keywarden check --observation - --allow team.pub
```

## What this release does not do

- It does not install, rotate, or delete keys.
- It does not remember a push, a host list, or a report unless you choose `--output`.
- It does not scan a fleet, wait on a schedule, sign you in, or keep evidence for you.

That is the later work. The free tool is the check.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

Fingerprints are checked against `ssh-keygen -lf` when it is installed.

## License

[MIT](LICENSE).
