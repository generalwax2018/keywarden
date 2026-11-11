# Compliance mapping

Each Keywarden check is mapped to the framework controls it gives evidence for. The evidence report (`keywarden check --evidence report.html`, or **Evidence** in `keywarden ui`) groups the results by control.

This mapping is meant to help an assessment, not replace one:

- A passing check is evidence toward a control on the hosts that were checked. It does not show the control is met. Most controls also cover process, people, and systems a host scan cannot see.
- Keywarden makes no MFA claim. Turning passwords off is not the same as requiring a second factor.
- Requirement names in the report are paraphrased. Read the framework for the exact wording.
- Versions: CIS Controls v8 safeguards, NIST SP 800-53 Rev. 5, PCI DSS v4.0, and NERC CIP-004-7, CIP-005-7, and CIP-007-6.

Corrections are welcome: open an issue with the check, the control, and why.

| Check | CIS Controls v8 | NIST SP 800-53 Rev. 5 | PCI DSS v4.0 | NERC CIP |
| --- | --- | --- | --- | --- |
| `accepted-algorithms` | 3.10 | SC-13 | 2.2.7 | CIP-005-7 R2.2 |
| `auth-log` | 8.11 | AU-6 | 10.4.1 | – |
| `auth-methods` | 4.1 | IA-2, IA-5(1) | 8.3.1 | CIP-007-6 R5.1 |
| `authorized-keys-command` | 4.1 | AC-2, CM-6 | 2.2.1 | – |
| `authorized-keys-file` | 4.1 | CM-6 | 2.2.1 | – |
| `ca-algorithms` | 3.10 | SC-13, SC-17 | 2.2.7 | – |
| `cert-authority` | – | IA-5(2), SC-17 | 7.2.2 | CIP-004-7 R4.1 |
| `empty-passwords` | 5.2 | IA-5(1) | 8.3.1, 8.3.6 | CIP-007-6 R5.5 |
| `expired-key` | – | IA-5 | 8.2.6 | – |
| `forced-command-forwarding` | 4.1 | CM-7, AC-17 | 2.2.4 | – |
| `hostbased-auth` | 4.1 | IA-2, AC-17 | 8.3.1 | CIP-007-6 R5.1 |
| `key-environment` | 4.1 | CM-6, CM-7 | 2.2.1 | – |
| `key-source` | – | AC-17, AC-6 | 7.2.2 | CIP-005-7 R2.1 |
| `key-to-root` | 5.4, 6.8 | AC-6, AC-6(5) | 7.2.2 | CIP-004-7 R4.3 |
| `keyboard-interactive` | 4.1 | IA-2, IA-5(1) | 8.3.1 | CIP-007-6 R5.1 |
| `log-level` | 8.2 | AU-2, AU-12 | 10.2.1 | CIP-007-6 R4.1 |
| `match-blocks` | 4.1 | CM-6 | 2.2.1 | – |
| `outside-push` | 5.1, 6.1, 6.2 | AC-2 | 7.2.1, 7.2.4, 8.2.5 | CIP-004-7 R4.1, CIP-004-7 R4.3 |
| `password-auth` | 4.1 | IA-2, IA-5(1) | 8.3.1 | CIP-007-6 R5.1, CIP-007-6 R5.5 |
| `permissions` | 3.3, 4.1 | AC-3, CM-6 | 2.2.1 | – |
| `permit-root` | 5.4 | AC-6(5), IA-2(5) | 8.2.2 | CIP-007-6 R5.2, CIP-007-6 R5.3 |
| `pubkey-auth` | – | IA-5(2) | 8.3.1 | CIP-007-6 R5.1 |
| `revoked-keys` | – | IA-5(2), SC-17 | 8.2.5 | CIP-004-7 R5.1 |
| `root-account` | 4.7, 5.2 | AC-2, AC-6(5), IA-5(1) | 8.2.2 | CIP-007-6 R5.2 |
| `root-authorized-key` | 5.4 | AC-6(5), IA-2(5) | 8.2.2 | CIP-007-6 R5.3 |
| `ssh-certificate` | – | IA-5(2), SC-17 | – | – |
| `sshd-config` | 4.1 | CM-6 | 2.2.1 | – |
| `stale-key` | 5.3, 6.2 | AC-2, AC-2(3), IA-5 | 7.2.4, 8.2.6 | CIP-004-7 R4.2, CIP-004-7 R4.3 |
| `trusted-user-ca` | – | IA-5(2), SC-17 | – | CIP-004-7 R4.1 |
| `weak-algorithm` | 3.10 | IA-5(2), SC-13 | 2.2.7 | CIP-005-7 R2.2 |

The table is generated from `src/keywarden/controls.py`, and a test fails if the two disagree.
