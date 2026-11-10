"""Posture rules. Findings name fingerprints, never key bodies."""

from __future__ import annotations

import time
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
    authentication_methods: str = "unknown"
    hostbased_authentication: str = "unknown"
    pubkey_accepted_algorithms: str = "unknown"
    ca_signature_algorithms: str = "unknown"
    trusted_user_ca_keys: str = "unknown"
    revoked_keys: str = "unknown"
    authorized_keys_command: str = "unknown"
    authorized_keys_file: str = "unknown"

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
    return KeyRef(key.fingerprint, key.type, key.kind, key.bits, key.comment, user, key.cert_authority, key.cert)


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
        title = "A line trusts a certificate authority" if len(authorities) == 1 else f"{len(authorities)} lines trust a certificate authority"
        findings.append(
            Finding(
                "cert-authority",
                "fail",
                title,
                _describe(authorities) + ". A cert-authority line lets any certificate that CA signs log in, including keys you did not push.",
            )
        )

    now = int(time.time())
    problems = []
    for key in all_keys:
        cert = key.cert
        if not cert:
            continue
        who = f"{key.user + ' · ' if key.user else ''}{key.fingerprint}"
        if cert.unreadable:
            problems.append(f"{who} could not be read")
        elif cert.cert_type == "host":
            problems.append(f"{who} is a host certificate")
        elif cert.valid_after > now:
            problems.append(f"{who} is not valid yet")
        elif cert.valid_before is not None and cert.valid_before < now:
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
