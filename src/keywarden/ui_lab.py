"""The lab: six made-up hosts for trying the interface. None of these keys exist anywhere real."""

from __future__ import annotations

from keywarden.check import HostObservation
from keywarden.collect import parse_protocol
from keywarden.parse import parse_public_keys

DAY = 86400

LAB_KEYS = {
    "ops": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMw3CRyIVJdlcMu0yNey4yKK9cbarwPgFyt3RYj11nOm ops@latch",
    "deploy": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFNC5kulzZA+Y15VIvsXBCD4xVqmzgNc3Yrt0uMZrLMe deploy@latch",
    "ci": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKyqTebqUn7JMI3f6e7CRqxw/LVNetdp5tfDuNCSA9hi ci-bot",
    "root": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMjKhLYgU3zJepCV0ElII061TiD8YX9qsBP9hfJjhB6v root@app-web-03",
    "contractor": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAFuDUY/c8R+5oUuOUyByXj9ZGOVT/nVX5lnf+RXtZwI contractor@temp",
    "alice": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILamNR3cDT6qyuPVk9beyF8PHD/KXGgtPGuYeqOp4Tmz alice@old-laptop",
    "legacy": (
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDM6KTe5dS730B8qyUwp1YK6JM8ccsTIrDRedOsdrz0eF+058iL/B21uIPEE+5/ffdY+DXN0so0IjckwZvVm3SkdFu3"
        "KnVShlUXIlyvjtHWKohCpK6ZiNf33OvpPBePbciFUrcFT9XeclgqziKoMUzeCgsSJ89sOkXvUTBfBNkq3JkK7Lges129q/D0XpFduFjAagdG10jOGBbR5OyduljMYJVjL3bn"
        "88GaaNsPTkYoZsEZ9ttawoIi4sJTNLQYJBcXjmrviQNjIjVLDzsnhXArXQd/oJnXl2ZxVXIoQxKucHlChbLQDIJ8MT61hB2X4ee+ltwAwK3lRHRSynzLyfyh legacy-jump"
    ),
}
LAB_PUSH = [LAB_KEYS["ops"], LAB_KEYS["deploy"], LAB_KEYS["ci"]]

_SAFE_SSHD = {
    "permitrootlogin": "no",
    "passwordauthentication": "no",
    "kbdinteractiveauthentication": "no",
    "pubkeyauthentication": "yes",
    "permitemptypasswords": "no",
    "authenticationmethods": "publickey",
    "hostbasedauthentication": "no",
    "pubkeyacceptedalgorithms": "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256",
    "casignaturealgorithms": "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256",
    "trustedusercakeys": "none",
    "revokedkeys": "none",
    "authorizedkeyscommand": "none",
    "authorizedkeysfile": ".ssh/authorized_keys .ssh/authorized_keys2",
    "loglevel": "INFO",
    "allowtcpforwarding": "yes",
    "allowagentforwarding": "yes",
    "x11forwarding": "no",
    "permituserenvironment": "no",
}
_ADMIN_SUDO = ["User {user} may run the following commands on {host}:", "    (ALL : ALL) NOPASSWD: ALL"]
_NO_SUDO = ["User {user} is not allowed to run sudo on {host}."]
_PASSWORD_SUDO = ["User {user} may run the following commands on {host}:", "    (ALL : ALL) ALL"]


def _fingerprint(line: str) -> str:
    return parse_public_keys(line)[0][0].fingerprint


def _account(user, uid, groups, sudo, keys, host, mode="600"):
    lines = [f"ACCOUNT {user}", f"UID {uid}", "LOCKED yes", f"GROUPS {' '.join(groups)}", "SUDOSTATE ok", "SUDO"]
    lines += ["S " + line.format(user=user, host=host) for line in sudo]
    lines += ["ENDSUDO"]
    if not keys:
        return lines + ["DIR 700", "FILE absent", "STATE absent", "KEYS", "ENDKEYS"]
    lines += ["DIR 700", f"FILE {mode}", "STATE ok", "KEYS"]
    lines += ["K " + key for key in keys]
    return lines + ["ENDKEYS"]


def _host(name, now, sshd_changes, accounts, logins):
    sshd = dict(_SAFE_SSHD)
    sshd.update(sshd_changes)
    lines = [
        "KEYWARDEN 3",
        f"HOST {name}",
        f"NOW {now} +0000",
        "PRIV sudo",
        "SSHDRUN ok",
        "SSHD",
        *(f"{key} {value}" for key, value in sshd.items()),
        "ENDSSHD",
        "MATCH no",
        "SSHDROOT",
        "ENDSSHDROOT",
        "AUTHLOG journal",
        "LOGINS",
        f"AUTHFIRST {now - 210 * DAY}.000000",
    ]
    for user, key, days_ago, source, count in logins:
        lines.append(
            f"L {count} {now - days_ago * DAY}.000000 {name} sshd[1]: Accepted publickey for {user} "
            f"from {source} port 50000 ssh2: ED25519 {_fingerprint(LAB_KEYS[key])}"
        )
    lines.append("ENDLOGINS")
    for account in accounts:
        lines += account
    lines += ["PASSWD ok", "END"]
    return "\n".join(lines) + "\n"


def lab_hosts(now: int) -> list[tuple[HostObservation, str, str, dict]]:
    """(observation, address, role, prior changes) for each lab host.

    The prior changes are how the previous run differed from this one; every other check is unchanged.
    """
    k = LAB_KEYS
    root_none = lambda host: _account("root", 0, ["root"], [], [], host)  # noqa: E731
    specs = [
        (
            "app-web-03", "10.0.4.23", "Application",
            {"permitrootlogin": "prohibit-password"},
            lambda h: [
                _account("root", 0, ["root"], [], [k["root"]], h),
                _account("ops", 1000, ["ops", "sudo"], _ADMIN_SUDO, ['from="10.0.0.0/16" ' + k["ops"]], h),
                _account("deploy", 1001, ["deploy"], _NO_SUDO, [k["deploy"]], h),
            ],
            [("ops", "ops", 1, "10.0.0.9", 41), ("deploy", "deploy", 0, "10.0.6.15", 212)],
            {"permit-root": ("pass", set()), "root-authorized-key": ("pass", set())},
        ),
        (
            "db-primary", "10.0.8.4", "Database",
            {"passwordauthentication": "yes"},
            lambda h: [
                root_none(h),
                _account("ops", 1000, ["ops", "sudo"], _ADMIN_SUDO, ['from="10.0.0.0/16" ' + k["ops"]], h),
                _account("postgres", 113, ["postgres"], _NO_SUDO, [k["contractor"]], h),
            ],
            [("ops", "ops", 3, "10.0.0.9", 12)],
            {"password-auth": ("fail", set()), "outside-push": ("fail", {_fingerprint(k["contractor"])})},
        ),
        (
            "ci-runner", "10.0.6.15", "Automation",
            {},
            lambda h: [
                root_none(h),
                _account("deploy", 1001, ["deploy", "docker"], _NO_SUDO, [k["ci"], k["alice"]], h),
            ],
            [("deploy", "ci", 0, "140.82.112.4", 388), ("deploy", "alice", 151, "10.20.0.14", 3)],
            {"outside-push": ("pass", set()), "stale-key": ("pass", set())},
        ),
        (
            "jump-legacy", "10.0.1.4", "Legacy jump",
            {"pubkeyacceptedalgorithms": "ssh-ed25519,rsa-sha2-256,ssh-rsa"},
            lambda h: [
                root_none(h),
                _account("ops", 1000, ["ops"], _NO_SUDO, ['from="10.0.0.0/16" ' + k["ops"], k["legacy"]], h),
            ],
            [("ops", "ops", 2, "10.0.0.9", 30)],
            {"weak-algorithm": ("fail", {_fingerprint(k["legacy"])}), "accepted-algorithms": ("fail", set())},
        ),
        (
            "bastion", "10.0.0.9", "Bastion",
            {"allowtcpforwarding": "no", "allowagentforwarding": "no"},
            lambda h: [
                root_none(h),
                _account("ops", 1000, ["ops"], _NO_SUDO, [k["ops"]], h),
            ],
            [("ops", "ops", 0, "203.0.113.20", 96)],
            {},
        ),
        (
            "mon-01", "10.0.9.7", "Monitoring",
            {},
            lambda h: [
                root_none(h),
                _account("ops", 1000, ["ops", "sudo"], _PASSWORD_SUDO, ['from="10.0.0.0/16" ' + k["ops"]], h),
                _account("deploy", 1001, ["deploy"], _NO_SUDO, ['restrict,command="/usr/local/bin/collect" ' + k["deploy"]], h),
            ],
            [("ops", "ops", 6, "10.0.0.9", 8), ("deploy", "deploy", 0, "10.0.6.15", 1440)],
            {},
        ),
    ]
    result = []
    for name, address, role, sshd, accounts, logins, prior in specs:
        observation = parse_protocol(_host(name, now, sshd, accounts(name), logins), address=address)
        result.append((observation, address, role, prior))
    return result
