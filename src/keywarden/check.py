"""Posture rules. Findings name fingerprints, never key bodies."""

from __future__ import annotations

import dataclasses
import re
import time
from dataclasses import dataclass, field

from keywarden.parse import KeyRef

WEAK_RSA_BITS = 3072
FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]+")
_RANK = {"pass": 0, "warn": 1, "fail": 2}


@dataclass
class SshdFacts:
    permit_root_login: str = "unknown"
    password_authentication: str = "unknown"
    kbd_interactive_authentication: str = "unknown"
    pubkey_authentication: str = "unknown"
    permit_empty_passwords: str = "unknown"
    authentication_methods: str = "unknown"
    hostbased_authentication: str = "unknown"
    pubkey_accepted_algorithms: str = "unknown"
    ca_signature_algorithms: str = "unknown"
    trusted_user_ca_keys: str = "unknown"
    revoked_keys: str = "unknown"
    authorized_keys_command: str = "unknown"
    authorized_keys_file: str = "unknown"
    log_level: str = "unknown"
    allow_tcp_forwarding: str = "unknown"
    allow_agent_forwarding: str = "unknown"
    x11_forwarding: str = "unknown"
    permit_user_environment: str = "unknown"

    def as_dict(self) -> dict:
        return {
            "permitRootLogin": self.permit_root_login,
            "passwordAuthentication": self.password_authentication,
            "kbdInteractiveAuthentication": self.kbd_interactive_authentication,
            "pubkeyAuthentication": self.pubkey_authentication,
            "permitEmptyPasswords": self.permit_empty_passwords,
            "authenticationMethods": self.authentication_methods,
            "hostbasedAuthentication": self.hostbased_authentication,
            "pubkeyAcceptedAlgorithms": self.pubkey_accepted_algorithms,
            "caSignatureAlgorithms": self.ca_signature_algorithms,
            "trustedUserCaKeys": self.trusted_user_ca_keys,
            "revokedKeys": self.revoked_keys,
            "authorizedKeysCommand": self.authorized_keys_command,
            "authorizedKeysFile": self.authorized_keys_file,
            "logLevel": self.log_level,
            "allowTcpForwarding": self.allow_tcp_forwarding,
            "allowAgentForwarding": self.allow_agent_forwarding,
            "x11Forwarding": self.x11_forwarding,
            "permitUserEnvironment": self.permit_user_environment,
        }


@dataclass
class Account:
    user: str
    dir_mode: str
    file_mode: str
    keys: list[KeyRef]
    read_state: str  # ok, absent, unreadable
    uid: int | None = None
    password_locked: bool | None = None
    groups: list[str] | None = None
    sudo_state: str = "unknown"  # ok, unreadable, absent (no sudo installed), unknown
    sudo_lines: list[str] = field(default_factory=list)


@dataclass
class Login:
    """Successful public-key logins for one account and fingerprint, from sshd's own log."""

    last: int | None
    count: int
    source: str = ""


@dataclass
class HostObservation:
    name: str
    address: str
    role: str
    observed_at: str
    sshd: SshdFacts
    accounts: list[Account]
    passwd_state: str = "unknown"
    sshd_state: str = "unknown"  # ok, failed, missing, unknown (hand-made observation)
    match_blocks: str = "unknown"  # yes, no, unknown
    sshd_root: SshdFacts | None = None  # sshd -T -C user=root, when Match blocks exist
    privilege: str = "unknown"  # root, sudo, none
    now: int | None = None  # the host's clock when it was observed
    log_source: str = "unknown"  # journal, file, none, unreadable, unknown
    log_since: int | None = None  # earliest log line the collector saw
    logins: dict[tuple[str, str], Login] = field(default_factory=dict)


@dataclass
class Finding:
    code: str
    severity: str
    title: str
    detail: str
    drift: str | None = None
    new_fingerprints: list[str] = field(default_factory=list)
    waivers: list[dict] = field(default_factory=list)
    was: str | None = None  # the severity before a waiver accepted it

    @property
    def fingerprints(self) -> list[str]:
        return list(dict.fromkeys(FINGERPRINT.findall(self.detail or "")))

    def as_dict(self) -> dict:
        data = {
            "code": self.code,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
        }
        prints = self.fingerprints
        if prints:
            data["fingerprints"] = prints
        if self.drift:
            data["drift"] = self.drift
        if self.new_fingerprints:
            data["newFingerprints"] = list(self.new_fingerprints)
        if self.waivers:
            data["waivers"] = list(self.waivers)
        if self.was:
            data["was"] = self.was
        from keywarden.controls import controls_for

        controls = controls_for(self.code)
        if controls:
            data["controls"] = controls
        return data


@dataclass
class Policy:
    flag_outside_push: bool = True
    flag_weak: bool = True
    stale_days: int = 90


def parse_sshd(text: str) -> SshdFacts:
    mapped: dict[str, str] = {}
    for line in text.splitlines():
        trimmed = line.strip()
        if not trimmed or trimmed.startswith("#"):
            continue
        parts = trimmed.split(None, 1)
        if len(parts) != 2 or not parts[0][:1].isalpha():
            continue
        mapped[parts[0].lower()] = parts[1].strip()

    def pick(key: str) -> str:
        return mapped.get(key, "unknown")

    return SshdFacts(
        permit_root_login=pick("permitrootlogin"),
        password_authentication=pick("passwordauthentication"),
        kbd_interactive_authentication=pick("kbdinteractiveauthentication"),
        pubkey_authentication=pick("pubkeyauthentication"),
        permit_empty_passwords=pick("permitemptypasswords"),
        authentication_methods=pick("authenticationmethods"),
        hostbased_authentication=pick("hostbasedauthentication"),
        pubkey_accepted_algorithms=pick("pubkeyacceptedalgorithms")
        if pick("pubkeyacceptedalgorithms") != "unknown"
        else pick("pubkeyacceptedkeytypes"),
        ca_signature_algorithms=pick("casignaturealgorithms"),
        trusted_user_ca_keys=pick("trustedusercakeys"),
        revoked_keys=pick("revokedkeys"),
        authorized_keys_command=pick("authorizedkeyscommand"),
        authorized_keys_file=pick("authorizedkeysfile"),
        log_level=pick("loglevel"),
        allow_tcp_forwarding=pick("allowtcpforwarding"),
        allow_agent_forwarding=pick("allowagentforwarding"),
        x11_forwarding=pick("x11forwarding"),
        permit_user_environment=pick("permituserenvironment"),
    )


def _mode_too_open(mode: str) -> bool | None:
    if not mode or mode in {"absent", "unknown"}:
        return None
    if len(mode) not in (3, 4) or any(char not in "01234567" for char in mode):
        return None
    last = mode[-3:]
    return last[1] != "0" or last[2] != "0"


def _describe(keys: list[KeyRef]) -> str:
    grouped: dict[str, list[KeyRef]] = {}
    order: list[str] = []
    for key in keys:
        if key.fingerprint not in grouped:
            grouped[key.fingerprint] = []
            order.append(key.fingerprint)
        grouped[key.fingerprint].append(key)
    parts = []
    for fingerprint in order:
        items = grouped[fingerprint]
        key = items[0]
        users: list[str] = []
        for item in items:
            if item.user and item.user not in users:
                users.append(item.user)
        where = f"{', '.join(users)} · " if users else ""
        bits = f" {key.bits}-bit" if key.bits else ""
        who = key.comment or "no comment"
        parts.append(f"{where}{key.type}{bits} {fingerprint} ({who})")
    return "; ".join(parts)


def _names(accounts: list[Account], limit: int = 10) -> str:
    names = [account.user for account in accounts]
    shown = ", ".join(names[:limit])
    return shown + (f", and {len(names) - limit} more" if len(names) > limit else "")


def _unique_count(keys: list[KeyRef]) -> int:
    return len({key.fingerprint for key in keys})


def _root_account(host: HostObservation) -> Finding | None:
    """Fail when passwd shows a second uid 0 account, no root, or an empty root password."""
    if host.passwd_state == "unknown":
        return None
    if host.passwd_state != "ok":
        return Finding(
            "root-account",
            "warn",
            "The root account could not be listed",
            "passwd was not readable, so another uid 0 account would be invisible.",
        )
    uid0 = [account for account in host.accounts if account.uid == 0]
    aliases = [account.user for account in uid0 if account.user != "root"]
    root = next((account for account in host.accounts if account.user == "root"), None)
    problems: list[str] = []
    if aliases:
        problems.append(f"{', '.join(aliases)} has uid 0")
    if root is None:
        problems.append("passwd has no root user")
    elif root.password_locked is False:
        problems.append("root's password field is empty")
    if problems:
        title = "An account other than root has uid 0" if aliases else "The root account is not safe"
        return Finding("root-account", "fail", title, ". ".join(problems) + ".")
    return Finding(
        "root-account",
        "pass",
        "The only uid 0 account is root",
        "No other account has uid 0, and the root password field is not empty.",
    )


def _with_user(key: KeyRef, user: str) -> KeyRef:
    return dataclasses.replace(key, user=user)


def _permit_root(value: str, raw: str) -> Finding | None:
    if value == "no":
        return Finding("permit-root", "pass", "Root login is disabled", "PermitRootLogin is no. Named accounts must log in, then escalate.")
    if value in {"prohibit-password", "without-password"}:
        return Finding(
            "permit-root",
            "fail",
            "Root can still log in with a key",
            f"PermitRootLogin is {raw}. Password is blocked, but a root public key still opens a root shell. Set it to no.",
        )
    if value == "forced-commands-only":
        return Finding(
            "permit-root",
            "warn",
            "Root login is forced-commands-only",
            "Root SSH is limited to a command pinned on the key. Confirm that command is the only one you intend.",
        )
    if value in {"unknown", ""}:
        return Finding("permit-root", "warn", "PermitRootLogin was not in the observation", "sshd -T did not include PermitRootLogin.")
    return Finding("permit-root", "fail", "Root login is enabled", f"PermitRootLogin is {raw}. Set it to no.")


def _password_auth(value: str, raw: str) -> Finding | None:
    if value == "no":
        return Finding("password-auth", "pass", "Password authentication is off", "PasswordAuthentication is no.")
    if value in {"unknown", ""}:
        return Finding("password-auth", "warn", "Password authentication was not observed", "sshd -T did not include PasswordAuthentication.")
    return Finding(
        "password-auth",
        "fail",
        "Password authentication is on",
        f"PasswordAuthentication is {raw}. Keys do not help if a password still works.",
    )


def _kbd_interactive(value: str, raw: str) -> Finding | None:
    if value == "yes":
        return Finding(
            "keyboard-interactive",
            "fail",
            "Keyboard-interactive authentication is on",
            "KbdInteractiveAuthentication yes is another password path. Turn it off.",
        )
    if value == "no":
        return Finding("keyboard-interactive", "pass", "Keyboard-interactive authentication is off", "KbdInteractiveAuthentication is no.")
    return None


def _with_root_match(host: HostObservation, attr: str, rule, daemon_unread: bool) -> Finding | None:
    """Evaluate a daemon setting, then let a Match block for root make it worse, never better."""
    raw = getattr(host.sshd, attr)
    value = raw.lower()
    if daemon_unread and value in {"unknown", ""}:
        return None
    base = rule(value, raw)
    if host.sshd_root is None:
        return base
    root_raw = getattr(host.sshd_root, attr)
    root_value = root_raw.lower()
    if root_value in {"unknown", ""} or root_value == value:
        return base
    for_root = rule(root_value, root_raw)
    if for_root is None or (base is not None and _RANK[for_root.severity] <= _RANK[base.severity]):
        return base
    return Finding(
        for_root.code,
        for_root.severity,
        for_root.title + " (Match block for root)",
        f"A Match block changes this for root. Default: {raw}. For root: {root_raw}. " + for_root.detail,
    )


def evaluate(host: HostObservation, push: list[KeyRef], policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    daemon_unread = host.sshd_state in {"failed", "missing"}
    if daemon_unread:
        reason = (
            "sshd was not found on PATH or in /usr/sbin, /usr/local/sbin, or /sbin."
            if host.sshd_state == "missing"
            else "sshd -T exited with an error. It usually needs root, or passwordless sudo, to read the host keys."
        )
        findings.append(
            Finding(
                "sshd-config",
                "warn",
                "The effective sshd configuration could not be read",
                reason + " Daemon checks were skipped, not passed.",
            )
        )

    for finding in (
        _with_root_match(host, "permit_root_login", _permit_root, daemon_unread),
        _with_root_match(host, "password_authentication", _password_auth, daemon_unread),
        _with_root_match(host, "kbd_interactive_authentication", _kbd_interactive, daemon_unread),
    ):
        if finding is not None:
            findings.append(finding)

    if host.match_blocks == "yes":
        evaluated = "Root was evaluated with its own Match context. " if host.sshd_root is not None else ""
        findings.append(
            Finding(
                "match-blocks",
                "warn",
                "sshd_config has Match blocks",
                "The daemon checks use the default settings. "
                + evaluated
                + "Match blocks for other users, groups, or addresses can override them and were not evaluated.",
            )
        )

    empty = host.sshd.permit_empty_passwords.lower()
    if empty == "yes":
        findings.append(Finding("empty-passwords", "fail", "Empty passwords are permitted", "PermitEmptyPasswords is yes."))
    elif empty == "no":
        findings.append(Finding("empty-passwords", "pass", "Empty passwords are refused", "PermitEmptyPasswords is no."))

    pubkey = host.sshd.pubkey_authentication.lower()
    if pubkey == "no":
        findings.append(
            Finding(
                "pubkey-auth",
                "fail",
                "Public-key authentication is disabled",
                "PubkeyAuthentication is no, so the keys you push cannot be what logs people in.",
            )
        )
    elif pubkey == "yes":
        findings.append(Finding("pubkey-auth", "pass", "Public-key authentication is on", "PubkeyAuthentication is yes."))

    root_accounts = [account for account in host.accounts if account.user == "root"]
    if not root_accounts or any(account.read_state == "unreadable" for account in root_accounts):
        findings.append(
            Finding(
                "root-authorized-key",
                "warn",
                "Root's authorized_keys could not be read",
                "No pass is given for an empty root key unless the file was readable or absent. Re-run as root, or with passwordless sudo, so a hidden root key cannot hide.",
            )
        )
    else:
        root_keys = [
            _with_user(key, "root")
            for account in root_accounts
            if account.read_state == "ok"
            for key in account.keys
        ]
        if not root_keys:
            findings.append(
                Finding(
                    "root-authorized-key",
                    "pass",
                    "No authorized key on root",
                    "root's authorized_keys is empty or absent.",
                )
            )
        else:
            title = "A key is authorized for root" if _unique_count(root_keys) == 1 else f"{_unique_count(root_keys)} keys are authorized for root"
            findings.append(Finding("root-authorized-key", "fail", title, _describe(root_keys)))

    loose = []
    unseen = []
    for account in host.accounts:
        if account.read_state == "unreadable" or (
            account.read_state == "ok" and "unknown" in {account.dir_mode, account.file_mode}
        ):
            unseen.append(account)
            continue
        dir_open = _mode_too_open(account.dir_mode)
        file_open = _mode_too_open(account.file_mode)
        if dir_open or file_open:
            loose.append(account)
    if loose:
        detail = "; ".join(f"{account.user}: .ssh {account.dir_mode}, authorized_keys {account.file_mode}" for account in loose)
        findings.append(Finding("permissions", "fail", "SSH files are group- or world-readable", detail))
    elif unseen:
        findings.append(
            Finding(
                "permissions",
                "warn",
                "Some SSH files could not be read",
                "Modes were checked only where they were visible. Not checked: " + _names(unseen) + ".",
            )
        )
    else:
        findings.append(
            Finding(
                "permissions",
                "pass",
                "SSH directory permissions are tight",
                "Each readable .ssh directory is 700 and authorized_keys is 600, or the file is absent.",
            )
        )

    if policy.flag_weak:
        weak = [
            _with_user(key, account.user)
            for account in host.accounts
            if account.user != "root" and account.read_state == "ok"
            for key in account.keys
            if key.kind == "dsa" or (key.kind == "rsa" and (key.bits is None or key.bits < WEAK_RSA_BITS))
        ]
        if not weak:
            findings.append(
                Finding(
                    "weak-algorithm",
                    "pass",
                    "No weak public keys",
                    "No DSA keys and no RSA keys under 3072 bits.",
                )
            )
        else:
            title = "A weak public key is authorized" if _unique_count(weak) == 1 else f"{_unique_count(weak)} weak public keys are authorized"
            findings.append(Finding("weak-algorithm", "fail", title, _describe(weak)))

    push_set = {key.fingerprint for key in push}
    if not push:
        findings.append(
            Finding(
                "outside-push",
                "warn",
                "No keys were supplied for this run",
                "Daemon, root, and permission checks still ran. Pass --allow with the public keys you push to compare what the host accepts.",
            )
        )
    elif policy.flag_outside_push:
        outside = [
            _with_user(key, account.user)
            for account in host.accounts
            if account.user != "root" and account.read_state == "ok"
            for key in account.keys
            if key.fingerprint not in push_set
        ]
        if not outside:
            findings.append(
                Finding(
                    "outside-push",
                    "pass",
                    "Authorized keys match the push",
                    "Every non-root key on this host is in the set you supplied. The key bodies were not kept.",
                )
            )
        else:
            title = "A key is not in the push" if _unique_count(outside) == 1 else f"{_unique_count(outside)} keys are not in the push"
            findings.append(Finding("outside-push", "fail", title, _describe(outside)))

    all_keys = [_with_user(key, account.user) for account in host.accounts for key in account.keys]
    authorities = [key for key in all_keys if key.cert_authority]
    if not authorities:
        findings.append(
            Finding(
                "cert-authority",
                "pass",
                "No key is a certificate authority",
                "Nothing in authorized_keys is marked cert-authority, so one line cannot sign in extra keys.",
            )
        )
    else:
        title = "A line trusts a certificate authority" if _unique_count(authorities) == 1 else f"{_unique_count(authorities)} lines trust a certificate authority"
        findings.append(
            Finding(
                "cert-authority",
                "fail",
                title,
                _describe(authorities) + ". A cert-authority line lets any certificate that CA signs log in, including keys you did not push.",
            )
        )

    now = int(time.time())
    by_fingerprint: dict[str, list[KeyRef]] = {}
    for key in all_keys:
        if not key.cert:
            continue
        by_fingerprint.setdefault(key.fingerprint, []).append(key)
    problems = []
    for fingerprint, items in by_fingerprint.items():
        key = items[0]
        cert = key.cert
        users: list[str] = []
        for item in items:
            if item.user and item.user not in users:
                users.append(item.user)
        who = f"{', '.join(users)} · {fingerprint}" if users else fingerprint
        if cert and cert.unreadable:
            problems.append(f"{who} could not be read")
        elif cert and cert.cert_type == "host":
            problems.append(f"{who} is a host certificate")
        elif cert and cert.valid_after > now:
            problems.append(f"{who} is not valid yet")
        elif cert and cert.valid_before is not None and cert.valid_before < now:
            problems.append(f"{who} has expired")
    if problems:
        title = "An SSH certificate is not acceptable" if len(problems) == 1 else f"{len(problems)} SSH certificates are not acceptable"
        findings.append(Finding("ssh-certificate", "fail", title, "; ".join(problems)))
    elif any(key.cert for key in all_keys):
        findings.append(
            Finding(
                "ssh-certificate",
                "pass",
                "SSH certificates are inside their validity window",
                "Each certificate is a user certificate, currently valid. The certificate body was not kept.",
            )
        )
    else:
        findings.append(
            Finding(
                "ssh-certificate",
                "pass",
                "No SSH certificates are authorized",
                "authorized_keys has no certificate. A trusted user CA is checked separately when sshd -T includes it.",
            )
        )

    def seen(value: str) -> bool:
        return bool(value) and value.lower() != "unknown"

    def weak_tokens(value: str) -> list[str]:
        return [token for token in value.lower().replace(",", " ").split() if token in {"ssh-rsa", "ssh-dss"} or "sha1" in token]

    if seen(host.sshd.pubkey_accepted_algorithms):
        weak = weak_tokens(host.sshd.pubkey_accepted_algorithms)
        if not weak:
            findings.append(Finding("accepted-algorithms", "pass", "sshd rejects weak public-key algorithms", "PubkeyAcceptedAlgorithms does not include ssh-rsa, ssh-dss, or SHA-1."))
        else:
            findings.append(Finding("accepted-algorithms", "fail", "sshd still accepts a weak public-key algorithm", f"PubkeyAcceptedAlgorithms includes {', '.join(weak)}."))

    if seen(host.sshd.ca_signature_algorithms):
        weak = weak_tokens(host.sshd.ca_signature_algorithms)
        if not weak:
            findings.append(Finding("ca-algorithms", "pass", "CA signatures do not use SHA-1", "CASignatureAlgorithms does not include ssh-rsa, ssh-dss, or SHA-1."))
        else:
            findings.append(Finding("ca-algorithms", "fail", "A CA may still sign with a weak algorithm", f"CASignatureAlgorithms includes {', '.join(weak)}."))

    if seen(host.sshd.trusted_user_ca_keys):
        trusted = host.sshd.trusted_user_ca_keys.strip().lower() not in {"", "none"}
        if trusted:
            findings.append(Finding("trusted-user-ca", "fail", "A user CA can authorize keys that were not pushed", f"TrustedUserCAKeys is {host.sshd.trusted_user_ca_keys}."))
        else:
            findings.append(Finding("trusted-user-ca", "pass", "No user CA is trusted", "TrustedUserCAKeys is none."))
        if trusted and seen(host.sshd.revoked_keys):
            if host.sshd.revoked_keys.strip().lower() in {"", "none"}:
                findings.append(Finding("revoked-keys", "warn", "The trusted CA has no revocation list", "RevokedKeys is none."))
            else:
                findings.append(Finding("revoked-keys", "pass", "A revocation list is configured", f"RevokedKeys is {host.sshd.revoked_keys}."))

    if seen(host.sshd.authorized_keys_command):
        if host.sshd.authorized_keys_command.strip().lower() in {"", "none"}:
            findings.append(Finding("authorized-keys-command", "pass", "No command injects authorized keys", "AuthorizedKeysCommand is none."))
        else:
            findings.append(Finding("authorized-keys-command", "fail", "A command can add keys that are not on disk", f"AuthorizedKeysCommand is {host.sshd.authorized_keys_command}."))

    if seen(host.sshd.authorized_keys_file):
        standard = {".ssh/authorized_keys", ".ssh/authorized_keys2"}
        files = [part for part in host.sshd.authorized_keys_file.replace(",", " ").split() if part]
        extra = [part for part in files if part not in standard]
        if not extra:
            findings.append(Finding("authorized-keys-file", "pass", "Authorized keys are read from the standard files", " ".join(files) or ".ssh/authorized_keys"))
        else:
            findings.append(Finding("authorized-keys-file", "warn", "sshd also reads authorized keys from another path", f"AuthorizedKeysFile includes {', '.join(extra)}."))

    if seen(host.sshd.hostbased_authentication):
        if host.sshd.hostbased_authentication.lower() == "no":
            findings.append(Finding("hostbased-auth", "pass", "Host-based authentication is off", "HostbasedAuthentication is no."))
        else:
            findings.append(Finding("hostbased-auth", "fail", "Host-based authentication is on", "HostbasedAuthentication is yes."))

    if seen(host.sshd.authentication_methods):
        methods = host.sshd.authentication_methods.lower().replace(",", " ")
        tokens = methods.split()
        if methods.strip() == "any" or "password" in tokens or "keyboard-interactive" in tokens:
            findings.append(Finding("auth-methods", "fail", "Authentication methods still allow a password", f"AuthenticationMethods is {host.sshd.authentication_methods}."))
        else:
            findings.append(Finding("auth-methods", "pass", "Authentication methods do not include a password", f"AuthenticationMethods is {host.sshd.authentication_methods}."))

    root_account = _root_account(host)
    if root_account is not None:
        findings.append(root_account)

    from keywarden.access import access_findings

    findings.extend(access_findings(host, push, policy))
    return findings


def worst(findings: list[Finding]) -> str:
    """accepted (a waived finding) counts as a pass."""
    if any(item.severity == "fail" for item in findings):
        return "fail"
    if any(item.severity == "warn" for item in findings):
        return "warn"
    return "pass"


PriorFindings = dict[str, tuple[str, set[str]]]


def apply_drift(findings: list[Finding], prior: PriorFindings | None) -> list[Finding]:
    """Mark changes against an earlier report.

    regressed: was pass, now fail. new: no earlier result, now fail.
    new-keys: was already failing, and now names a fingerprint it did not name before.
    cleared: was fail, now pass.
    """
    if not prior:
        return findings
    adjusted: list[Finding] = []
    for item in findings:
        before = prior.get(item.code)
        drift = None
        added: list[str] = []
        if before is None:
            drift = "new" if item.severity == "fail" else None
        else:
            severity, prints = before
            if severity == "pass" and item.severity == "fail":
                drift = "regressed"
            elif severity == "fail" and item.severity == "pass":
                drift = "cleared"
            elif severity == "fail" and item.severity == "fail":
                added = [fingerprint for fingerprint in item.fingerprints if fingerprint not in prints]
                if added:
                    drift = "new-keys"
        adjusted.append(Finding(item.code, item.severity, item.title, item.detail, drift, added))
    return adjusted
