# Keywarden

Check SSH posture around the public keys you already push. Keywarden does not push keys, and it does not store them.

You keep using whatever already places `authorized_keys` on a machine (Ansible, a script, by hand). Keywarden reads the effective daemon config and the keys that are actually authorized, fingerprints those keys, and drops the bodies before it writes a report.

One command checks this machine, one host, or every host in an Ansible inventory. It is a point-in-time check: there is no daemon, scheduler, or stored state.

## Install

Python 3.9 or newer, on Linux or another POSIX system. No third-party packages.

```sh
python3 -m pip install "git+https://github.com/generalwax2018/keywarden.git@v0.1.1"
```

The distribution name is `keywarden-ssh`. The `keywarden` package on PyPI is an unrelated project; do not install it expecting this tool.

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

A host key that is missing or changed fails the connection. Keywarden does not accept it. `--accept-new` trusts a key you have not seen before and is off unless you pass it. Use the `known_hosts` file your SSH client already has.

Reading root, and reading other accounts, needs to be allowed: run as root, or have passwordless `sudo`. With general passwordless sudo the collector uses it for `sshd -T`, `stat`, `test`, `ls`, `grep` of the sshd config, and `cat` of `authorized_keys`. With sudo limited to `sshd -T` and `cat`, those two still work, and file modes behind an unreadable home are reported as unknown. If root's file cannot be read, the root-key check is a **warning, not a pass**. A hidden root key must not look clean, and an account whose home cannot be read is listed as not checked instead of being skipped.

Every line read from an `authorized_keys` file is prefixed before it crosses the wire, and the parser refuses output that is out of order, repeated, or truncated. A user who writes collector markers into their own key file cannot change what the report says about the daemon or other accounts; the host fails with `collector-output` instead.

`--account` adds a specific user. Repeat it. Accounts that already have an `authorized_keys` file are included when the file is visible.

## Check an Ansible inventory

```sh
keywarden check --inventory hosts.ini --allow team.pub
```

`hosts.ini` is the INI inventory you already use. Keywarden reads `ansible_user`, `ansible_host`, `ansible_port`, and `ansible_ssh_private_key_file` (and their `ansible_ssh_*` spellings), from host lines, `[group:vars]`, and parent groups through `[group:children]`. A nearer group overrides a parent, and a host line overrides both, as in Ansible. A private-key path is handed to `ssh -i`; Keywarden never opens the file. Passwords, become passwords, and every other variable are dropped as the file is read. YAML inventories are not supported yet and are refused with a message. Each host is one SSH, in order. A host that cannot be reached is a failure, and the rest are still checked.

The terminal shows failures only. A check that names a key is printed once per fingerprint, with every host where that fingerprint failed. Other failures stay on their own line: hostname and check. Passes are not printed. Exit 1 if any host failed. `--output` writes the JSON report, still without key bodies. The `fingerprints` array is the unique set. `--prior` is for one host, not an inventory.

```ini
[web]
app-web-03 ansible_user=deploy
bastion ansible_host=10.0.0.9 ansible_user=ops ansible_port=2222
```

There is no scheduler. The next run is the next time you start the command.

## What is checked

| Code | Fails when |
| --- | --- |
| `permit-root` | `PermitRootLogin` is anything but `no`. `prohibit-password` and `without-password` still allow a root key, so they fail. |
| `password-auth` | `PasswordAuthentication` is on |
| `keyboard-interactive` | `KbdInteractiveAuthentication` is on |
| `empty-passwords` | `PermitEmptyPasswords` is on |
| `pubkey-auth` | `PubkeyAuthentication` is off |
| `root-authorized-key` | root has a key. Unreadable is a warning. |
| `root-account` | another account has uid 0, root is missing, or root's password field is empty |
| `permissions` | `.ssh` or `authorized_keys` is group- or world-accessible |
| `weak-algorithm` | DSA, or RSA under 3072 bits |
| `outside-push` | a non-root key is not in `--allow` |
| `cert-authority` | a line is marked `cert-authority` |
| `ssh-certificate` | a certificate is expired, not yet valid, a host certificate, or unreadable |
| `accepted-algorithms` | `PubkeyAcceptedAlgorithms` still allows `ssh-rsa`, `ssh-dss`, or SHA-1 |
| `ca-algorithms` | `CASignatureAlgorithms` still allows those |
| `trusted-user-ca` | `TrustedUserCAKeys` is set, so a signed key can bypass the push |
| `revoked-keys` | a user CA is trusted and `RevokedKeys` is none (warning) |
| `authorized-keys-command` | a command can inject keys that are not in the file |
| `authorized-keys-file` | `sshd` also reads a path other than `.ssh/authorized_keys` |
| `hostbased-auth` | host-based authentication is on |
| `auth-methods` | `AuthenticationMethods` still allows a password |
| `sshd-config` | `sshd -T` could not run, so daemon checks were skipped (warning) |
| `match-blocks` | `sshd_config` has `Match` blocks (warning; see below) |
| `collector-output` | the collector output was malformed or tampered with |
| `unreachable` | an inventory host could not be reached |

Fields that are absent from the observation are skipped, not treated as a pass.

`sshd -T` prints the default settings, before any `Match` block applies. When the config has `Match` blocks, Keywarden also runs `sshd -T -C user=root,...` and fails `permit-root`, `password-auth`, or `keyboard-interactive` if a block makes root worse than the default. A `Match` block can only make a result worse, never better. Blocks for other users, groups, or source addresses are not evaluated; `match-blocks` warns so you know to read them.

Key text is fingerprinted in memory and then dropped. A private key, including a PuTTY private key, stops the run and is not written. The report never contains a key body. `--allow` is not deleted; it is your file.

`forced-commands-only` is a warning. Pass `--no-weak` or `--no-outside` to skip those two comparisons.

Key comments are often an email address or a machine name. Pass `--redact-comments` to leave them out of the terminal output and the report.

## Drift

Keep the previous report (it has no key bodies) and pass it next time:

```sh
keywarden check --local --allow team.pub --prior keywarden-report.json
```

A check that was a pass and is now a fail is marked `regressed`. A new failure is `new`. A failure that cleared is `cleared`. A check that was already failing and now names a fingerprint it did not name before is `new-keys`, with the added fingerprints in `newFingerprints`. Each finding that names keys carries a `fingerprints` array.

## Offline observation

If you would rather not have Keywarden open SSH itself, run the collector on the host and pipe it. Do not save that stream: it contains public keys. The report does not. Collector output from 0.1.0 (protocol 1) is refused; run the current collector.

```sh
python3 -c 'from keywarden.collect import REMOTE_SCRIPT; print(REMOTE_SCRIPT)' | sh | keywarden check --observation - --allow team.pub
```

## What this release does not do

- It does not install, rotate, or delete keys.
- It does not remember a push, a host list, or a report unless you choose `--output`.
- It does not run on a schedule or keep evidence for you. Run it from cron or CI and keep the reports you want.
- It checks inventory hosts one at a time, up to 256 per run.
- It reads `/etc/passwd` and `~/.ssh/authorized_keys`. Accounts that exist only in LDAP or SSSD, and keys served by `AuthorizedKeysCommand`, are not listed (the command itself is flagged).

## Tests

```sh
python3 -m unittest discover -s tests -v
```

Fingerprint and certificate tests run when `ssh-keygen` is installed and are skipped otherwise. CI also runs the collector against a real OpenSSH server, including an `authorized_keys` file that tries to rewrite the report.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report security issues privately; see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE).
