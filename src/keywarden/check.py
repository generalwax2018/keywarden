"""Posture rules. Findings name fingerprints, never key bodies."""

from __future__ import annotations

from dataclasses import dataclass

from keywarden.parse import KeyRef

WEAK_RSA_BITS = 3072


@dataclass
class SshdFacts:
    permit_root_login: str = "unknown"
    password_authentication: str = "unknown"
    kbd_interactive_authentication: str = "unknown"
    pubkey_authentication: str = "unknown"
    permit_empty_passwords: str = "unknown"

    def as_dict(self) -> dict:
        return {
            "permitRootLogin": self.permit_root_login,
            "passwordAuthentication": self.password_authentication,
            "kbdInteractiveAuthentication": self.kbd_interactive_authentication,
            "pubkeyAuthentication": self.pubkey_authentication,
            "permitEmptyPasswords": self.permit_empty_passwords,
        }


@dataclass
class Account:
    user: str
    dir_mode: str
    file_mode: str
    keys: list[KeyRef]
    read_state: str  # ok, absent, unreadable


@dataclass
class HostObservation:
    name: str
    address: str
    role: str
    observed_at: str
    sshd: SshdFacts
    accounts: list[Account]


@dataclass
class Finding:
    code: str
    severity: str
    title: str
    detail: str
    drift: str | None = None

    def as_dict(self) -> dict:
        data = {
            "code": self.code,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
        }
        if self.drift:
            data["drift"] = self.drift
        return data


@dataclass
class Policy:
    flag_outside_push: bool = True
    flag_weak: bool = True


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
    )


def _mode_too_open(mode: str) -> bool | None:
    if not mode or mode in {"absent", "unknown"}:
        return None
    if len(mode) not in (3, 4) or any(char not in "01234567" for char in mode):
        return None
    last = mode[-3:]
    return last[1] != "0" or last[2] != "0"


def _describe(keys: list[KeyRef]) -> str:
    parts = []
    for key in keys:
        who = key.comment or "no comment"
        where = f"{key.user} · " if key.user else ""
        bits = f" {key.bits}-bit" if key.bits else ""
        parts.append(f"{where}{key.type}{bits} {key.fingerprint} ({who})")
    return "; ".join(parts)


def _with_user(key: KeyRef, user: str) -> KeyRef:
    return KeyRef(key.fingerprint, key.type, key.kind, key.bits, key.comment, user)


def evaluate(host: HostObservation, push: list[KeyRef], policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    root = host.sshd.permit_root_login.lower()

    if root == "no":
        findings.append(
            Finding(
                "permit-root",
                "pass",
                "Root login is disabled",
                "PermitRootLogin is no. Named accounts must log in, then escalate.",
            )
        )
    elif root in {"prohibit-password", "without-password"}:
        findings.append(
            Finding(
                "permit-root",
                "fail",
                "Root can still log in with a key",
                f"PermitRootLogin is {host.sshd.permit_root_login}. Password is blocked, but a root public key still opens a root shell. Set it to no.",
            )
        )
    elif root == "forced-commands-only":
        findings.append(
            Finding(
                "permit-root",
                "warn",
                "Root login is forced-commands-only",
                "Root SSH is limited to a command pinned on the key. Confirm that command is the only one you intend.",
            )
        )
    elif root in {"unknown", ""}:
        findings.append(
            Finding(
                "permit-root",
                "warn",
                "PermitRootLogin was not in the observation",
                "sshd -T did not include PermitRootLogin.",
            )
        )
    else:
        findings.append(
            Finding(
                "permit-root",
                "fail",
                "Root login is enabled",
                f"PermitRootLogin is {host.sshd.permit_root_login}. Set it to no.",
            )
        )

    password = host.sshd.password_authentication.lower()
    if password == "no":
        findings.append(Finding("password-auth", "pass", "Password authentication is off", "PasswordAuthentication is no."))
    elif password == "unknown":
        findings.append(
            Finding(
                "password-auth",
                "warn",
                "Password authentication was not observed",
                "sshd -T did not include PasswordAuthentication.",
            )
        )
    else:
        findings.append(
            Finding(
                "password-auth",
                "fail",
                "Password authentication is on",
                "PasswordAuthentication is yes. Keys do not help if a password still works.",
            )
        )

    kbd = host.sshd.kbd_interactive_authentication.lower()
    if kbd == "yes":
        findings.append(
            Finding(
                "keyboard-interactive",
                "fail",
                "Keyboard-interactive authentication is on",
                "KbdInteractiveAuthentication yes is another password path. Turn it off.",
            )
        )
    elif kbd == "no":
        findings.append(
            Finding(
                "keyboard-interactive",
                "pass",
                "Keyboard-interactive authentication is off",
                "KbdInteractiveAuthentication is no.",
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
            title = "A key is authorized for root" if len(root_keys) == 1 else f"{len(root_keys)} keys are authorized for root"
            findings.append(Finding("root-authorized-key", "fail", title, _describe(root_keys)))

    loose = []
    unseen = []
    for account in host.accounts:
        if account.read_state == "unreadable":
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
                "Modes were checked only where authorized_keys was readable.",
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
            title = "A weak public key is authorized" if len(weak) == 1 else f"{len(weak)} weak public keys are authorized"
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
            title = "A key is not in the push" if len(outside) == 1 else f"{len(outside)} keys are not in the push"
            findings.append(Finding("outside-push", "fail", title, _describe(outside)))

    return findings


def worst(findings: list[Finding]) -> str:
    if any(item.severity == "fail" for item in findings):
        return "fail"
    if any(item.severity == "warn" for item in findings):
        return "warn"
    return "pass"


def apply_drift(findings: list[Finding], prior: dict[str, str] | None) -> list[Finding]:
    if not prior:
        return findings
    adjusted: list[Finding] = []
    for item in findings:
        before = prior.get(item.code)
        drift = None
        if before is None:
            drift = "new" if item.severity == "fail" else None
        elif before == "pass" and item.severity == "fail":
            drift = "regressed"
        elif before == "fail" and item.severity == "pass":
            drift = "cleared"
        adjusted.append(Finding(item.code, item.severity, item.title, item.detail, drift))
    return adjusted
