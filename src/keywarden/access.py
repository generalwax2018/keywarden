"""Access review: who each key lets in, as what, from where, and whether it is still used."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from keywarden.check import Account, Finding, HostObservation, Login, Policy
from keywarden.parse import KeyRef

DAY = 86400

# Groups that are root in all but name.
ROOT_EQUIVALENT_GROUPS = {"docker", "lxd", "lxc", "disk", "incus-admin"}
# Groups that usually grant sudo with a password.
SUDO_GROUPS = {"sudo", "wheel", "admin"}
# Commands that give a shell or write any file when run through sudo.
# Not exhaustive: a limited rule that is not on this list is still only "limited".
SHELL_ESCAPES = {
    "ALL", "sh", "bash", "dash", "zsh", "ksh", "fish", "su", "sudo", "sudoedit", "env", "vi", "vim", "nvim",
    "nano", "ed", "emacs", "less", "more", "man", "find", "awk", "gawk", "mawk", "sed", "perl", "python",
    "python2", "python3", "ruby", "lua", "node", "php", "tee", "cp", "mv", "dd", "chmod", "chown", "tar",
    "zip", "rsync", "git", "docker", "podman", "systemctl", "journalctl", "crontab", "install", "ln",
    "nmap", "ssh", "scp", "script", "socat", "nc", "ncat", "xargs", "flock", "taskset", "nice", "time",
    "timeout", "watch", "strace", "gdb", "apt", "apt-get", "yum", "dnf", "pip", "pip3", "npm", "make",
    "mount", "busybox", "openssl", "run-parts", "visudo",
}
_ROOT_RUNAS = re.compile(r"^\(\s*(ALL|root)\b", re.IGNORECASE)
_TAGS = re.compile(r"^((?:NOPASSWD|PASSWD|SETENV|NOSETENV|EXEC|NOEXEC|LOG_INPUT|NOLOG_INPUT|LOG_OUTPUT|NOLOG_OUTPUT|MAIL|NOMAIL|FOLLOW|NOFOLLOW|INTERCEPT|NOINTERCEPT)\s*:\s*)+")
_ACCEPTED = re.compile(
    r"Accepted publickey for (?P<user>\S+) from (?P<source>\S+) port \d+ \S+: (?P<type>\S+) "
    r"(?P<fp>SHA256:[A-Za-z0-9+/]+)(?:.*? CA \S+ (?P<ca>SHA256:[A-Za-z0-9+/]+))?"
)
_SYSLOG_TIME = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})(?:\s|$)")
_MONTHS = {name: index for index, name in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}
_QUIET_LOG_LEVELS = {"quiet", "fatal", "error"}


@dataclass(frozen=True)
class Reach:
    """What logging in as this account leads to."""

    level: str  # root, root-nopasswd, root-password, limited, none, unknown
    via: str = ""

    @property
    def privileged(self) -> bool:
        return self.level in {"root", "root-nopasswd"}


def _command_name(command: str) -> str:
    first = command.strip().split()[0] if command.strip() else ""
    return first.rsplit("/", 1)[-1]


def classify_sudo(lines: list[str]) -> Reach | None:
    """Read `sudo -l -U user` output. None when the output says nothing usable."""
    text = "\n".join(lines)
    if "is not allowed to run sudo" in text:
        return Reach("none", "not in sudoers")
    if "may run the following commands" not in text:
        return None
    entries: list[str] = []
    collecting = False
    for line in lines:
        if "may run the following commands" in line:
            collecting = True
            continue
        if collecting and line.strip():
            entries.append(line.strip())
    best = Reach("none", "no sudo rules")
    rank = {"none": 0, "limited": 1, "root-password": 2, "root-nopasswd": 3}
    for entry in entries:
        runas_root = bool(_ROOT_RUNAS.match(entry))
        rest = re.sub(r"^\([^)]*\)\s*", "", entry)
        tags = _TAGS.match(rest)
        tag_text = tags.group(0) if tags else ""
        nopasswd = "NOPASSWD" in tag_text.upper()
        commands = [part.strip() for part in rest[len(tag_text):].split(",") if part.strip()]
        escapes = [command for command in commands if _command_name(command) in SHELL_ESCAPES or command.strip() == "ALL"]
        if runas_root and escapes:
            shown = "ALL" if any(command.strip() == "ALL" for command in escapes) else _command_name(escapes[0])
            level = "root-nopasswd" if nopasswd else "root-password"
            via = f"sudo {shown}" + (" without a password" if nopasswd else " with a password")
            candidate = Reach(level, via)
        else:
            candidate = Reach("limited", "sudo " + ", ".join(_command_name(command) for command in commands[:3]))
        if rank[candidate.level] > rank[best.level]:
            best = candidate
    return best


def reach_of(account: Account) -> Reach:
    if account.user == "root" or account.uid == 0:
        return Reach("root", "is root" if account.user == "root" else "uid 0")
    groups = set(account.groups or [])
    root_groups = sorted(groups & ROOT_EQUIVALENT_GROUPS)
    sudo = classify_sudo(account.sudo_lines) if account.sudo_state == "ok" else None
    if sudo is not None and sudo.level == "root-nopasswd":
        return sudo
    if root_groups:
        return Reach("root-nopasswd", f"member of {root_groups[0]}, which is root-equivalent")
    if sudo is not None:
        return sudo
    if account.sudo_state == "absent":
        return Reach("none", "sudo is not installed")
    sudo_groups = sorted(groups & SUDO_GROUPS)
    if sudo_groups:
        return Reach("root-password", f"member of {sudo_groups[0]}; sudo rules could not be read")
    return Reach("unknown", "sudo rules could not be read")


def parse_log_time(line: str, now: int | None, offset: str | None) -> int | None:
    """Timestamp of a journal (short-unix), RFC 3339, or classic syslog line."""
    head = line.split(" ", 1)[0]
    try:
        return int(float(head))
    except ValueError:
        pass
    if len(head) >= 19 and head[4] == "-" and head[10] == "T":
        text = head[:-1] + "+00:00" if head.endswith("Z") else head
        try:
            moment = datetime.fromisoformat(text)
        except ValueError:
            moment = None
        if moment is not None:
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=_zone(offset))
            return int(moment.timestamp())
    match = _SYSLOG_TIME.match(line)
    if not match or match.group("mon") not in _MONTHS:
        return None
    zone = _zone(offset)
    reference = datetime.fromtimestamp(now, zone) if now else datetime.now(zone)
    hour, minute, second = (int(part) for part in match.group("time").split(":"))
    try:
        moment = datetime(reference.year, _MONTHS[match.group("mon")], int(match.group("day")), hour, minute, second, tzinfo=zone)
    except ValueError:
        return None
    if moment - reference > timedelta(days=1):
        # Classic syslog has no year. A date ahead of the host clock is last year.
        moment = moment.replace(year=moment.year - 1)
    return int(moment.timestamp())


def _zone(offset: str | None) -> timezone:
    if offset and re.fullmatch(r"[+-]\d{4}", offset):
        sign = 1 if offset[0] == "+" else -1
        return timezone(sign * timedelta(hours=int(offset[1:3]), minutes=int(offset[3:5])))
    return timezone.utc


def parse_login_lines(lines: list[str], now: int | None, offset: str | None) -> dict[tuple[str, str], Login]:
    """Lines are "<count> <log line>": the newest accepted login per account and key, with a count."""
    logins: dict[tuple[str, str], Login] = {}
    for raw in lines:
        count_text, _space, line = raw.partition(" ")
        if not count_text.isdigit():
            continue
        match = _ACCEPTED.search(line)
        if not match:
            continue
        when = parse_log_time(line, now, offset)
        count = int(count_text)
        keys = [(match.group("user"), match.group("fp"))]
        if match.group("ca"):
            keys.append((match.group("user"), "CA:" + match.group("ca")))
        for key in keys:
            known = logins.get(key)
            if known is None:
                logins[key] = Login(when, count, match.group("source"))
                continue
            newer = when is not None and (known.last is None or when > known.last)
            logins[key] = Login(
                when if newer else known.last,
                known.count + count,
                match.group("source") if newer else known.source,
            )
    return logins


def _iso(epoch: int | None) -> str | None:
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, timezone.utc).replace(microsecond=0).isoformat()


def _login_for(host: HostObservation, user: str, key: KeyRef) -> Login | None:
    if key.cert_authority:
        return host.logins.get((user, "CA:" + key.fingerprint))
    return host.logins.get((user, key.fingerprint))


def logs_usable(host: HostObservation) -> bool:
    return host.log_source in {"journal", "file"} and host.now is not None


def usage_status(host: HostObservation, user: str, key: KeyRef, policy: Policy) -> tuple[str, Login | None]:
    """fresh, stale, unseen (logs too short to say), unmatched (a certificate line), or unknown."""
    if not logs_usable(host):
        return "unknown", None
    if key.cert is not None and not key.cert_authority:
        # sshd logs the certificate's key, not the line as written; it cannot be matched.
        return "unmatched", None
    login = _login_for(host, user, key)
    now = host.now or 0
    window = policy.stale_days * DAY
    if login is not None and login.last is not None and now - login.last <= window:
        return "fresh", login
    covered = now - host.log_since if host.log_since is not None else 0
    if covered >= window:
        return "stale", login
    return "unseen", login


def key_rows(host: HostObservation, push: list[KeyRef], policy: Policy) -> list[dict]:
    """One row per authorized key: the access review table."""
    allowed = {key.fingerprint for key in push}
    rows: list[dict] = []
    for account in host.accounts:
        if account.read_state != "ok":
            continue
        reach = reach_of(account)
        for key in account.keys:
            status, login = usage_status(host, account.user, key, policy)
            row = {
                "host": host.name,
                "account": account.user,
                "uid": account.uid,
                "fingerprint": key.fingerprint,
                "type": key.type,
                "bits": key.bits,
                "comment": key.comment,
                "inAllow": (key.fingerprint in allowed) if push else None,
                "reach": reach.level,
                "reachVia": reach.via,
                "certAuthority": key.cert_authority,
                "options": key.options.public(),
                "usage": status,
                "lastUsed": _iso(login.last) if login else None,
                "uses": login.count if login else 0,
                "lastFrom": login.source if login else None,
            }
            rows.append(row)
    return rows


def _line(account: Account, key: KeyRef, extra: str = "") -> str:
    who = key.comment or "no comment"
    tail = f" ({extra})" if extra else ""
    return f"{account.user} · {key.type} {key.fingerprint} ({who}){tail}"


def _on(value: str) -> bool:
    """sshd forwarding settings: anything but "no" leaves the capability available."""
    return value.lower() not in {"no"}


def access_findings(host: HostObservation, push: list[KeyRef], policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    readable = [account for account in host.accounts if account.read_state == "ok" and account.keys]

    # Logging in with this key leads to root without another secret.
    to_root = []
    unknown_reach = []
    for account in readable:
        if account.user == "root" or account.uid == 0:
            continue
        reach = reach_of(account)
        if reach.level == "root-nopasswd":
            to_root.extend(_line(account, key, reach.via) for key in account.keys)
        elif reach.level == "unknown" and account.sudo_state == "unreadable":
            unknown_reach.append(account.user)
    if to_root:
        findings.append(
            Finding(
                "key-to-root",
                "warn",
                "A key leads to root without another password" if len(to_root) == 1 else f"{len(to_root)} keys lead to root without another password",
                "; ".join(to_root) + ". Treat these keys like root keys: restrict them with from= and review who holds them.",
            )
        )
    elif unknown_reach:
        findings.append(
            Finding(
                "key-to-root",
                "warn",
                "Sudo rights could not be read",
                "Run as root or with passwordless sudo to see what these accounts can do: " + ", ".join(unknown_reach[:10]) + ".",
            )
        )
    elif any(account.sudo_state != "unknown" or account.groups is not None for account in readable):
        findings.append(Finding("key-to-root", "pass", "No key reaches root without a password", "No account with a key has passwordless root through sudo or a root-equivalent group."))

    # Privileged keys that can be used from anywhere.
    open_source = []
    for account in readable:
        reach = reach_of(account)
        if not reach.privileged:
            continue
        for key in account.keys:
            if not key.options.source:
                open_source.append(_line(account, key, reach.via))
    if open_source:
        findings.append(
            Finding(
                "key-source",
                "warn",
                "A root-level key works from any address" if len(open_source) == 1 else f"{len(open_source)} root-level keys work from any address",
                "; ".join(open_source) + ". Add from=\"<jump host or admin network>\" so a copied key is useless elsewhere.",
            )
        )
    elif any(reach_of(account).privileged for account in readable):
        findings.append(Finding("key-source", "pass", "Root-level keys are limited by source address", "Every key that reaches root has a from= restriction."))

    # A forced command does not stop forwarding.
    tcp_on = _on(host.sshd.allow_tcp_forwarding)
    agent_on = _on(host.sshd.allow_agent_forwarding)
    loose_commands = []
    for account in readable:
        for key in account.keys:
            options = key.options
            if not options.forced_command:
                continue
            open_paths = []
            if "port" in options.allows and tcp_on and not options.permit_open:
                open_paths.append("port forwarding")
            if "agent" in options.allows and agent_on:
                open_paths.append("agent forwarding")
            if open_paths:
                loose_commands.append(_line(account, key, " and ".join(open_paths) + " still allowed"))
    if loose_commands:
        findings.append(
            Finding(
                "forced-command-forwarding",
                "warn",
                "A forced-command key can still forward" if len(loose_commands) == 1 else f"{len(loose_commands)} forced-command keys can still forward",
                "; ".join(loose_commands) + ". command= limits the shell, not tunnels. Add restrict (or no-port-forwarding,no-agent-forwarding).",
            )
        )

    # environment= only matters when sshd honors it.
    if host.sshd.permit_user_environment.lower() not in {"no", "unknown"}:
        env_keys = [_line(account, key) for account in readable for key in account.keys if key.options.environment]
        if env_keys:
            findings.append(
                Finding(
                    "key-environment",
                    "fail",
                    "A key sets environment variables sshd will honor",
                    "; ".join(env_keys) + f". PermitUserEnvironment is {host.sshd.permit_user_environment}, so a key can set LD_PRELOAD and similar.",
                )
            )

    # Lines sshd already refuses are clutter that hides real changes.
    now = host.now
    expired = []
    for account in readable:
        for key in account.keys:
            if key.options.expiry_unreadable:
                expired.append(_line(account, key, "expiry-time is not a date sshd reads"))
            elif key.options.expires is not None and now is not None and key.options.expires < now:
                expired.append(_line(account, key, f"expired {_iso(key.options.expires)}"))
    if expired:
        findings.append(
            Finding(
                "expired-key",
                "warn",
                "A key line has expired" if len(expired) == 1 else f"{len(expired)} key lines have expired",
                "; ".join(expired) + ". sshd refuses them; remove the lines.",
            )
        )

    # Logging must be on for anyone to tell which key was used.
    level = host.sshd.log_level.lower()
    if level in _QUIET_LOG_LEVELS:
        findings.append(
            Finding(
                "log-level",
                "fail",
                "sshd does not log logins",
                f"LogLevel is {host.sshd.log_level}. Accepted logins and their key fingerprints are not recorded. Use INFO or VERBOSE.",
            )
        )
    elif level not in {"unknown", ""}:
        findings.append(Finding("log-level", "pass", "sshd logs which key was used", f"LogLevel is {host.sshd.log_level}."))

    findings.extend(_usage_findings(host, readable, policy))
    return findings


def _usage_findings(host: HostObservation, readable: list[Account], policy: Policy) -> list[Finding]:
    if host.log_source == "unknown":
        return []
    if not logs_usable(host):
        reasons = {
            "unreadable": "The sshd log could not be read. Run as root, or with passwordless sudo, or in the adm or systemd-journal group.",
            "none": "No sshd log was found in the journal (ssh.service or sshd.service) or in /var/log/auth.log or /var/log/secure.",
        }
        detail = reasons.get(host.log_source, f"The log source was {host.log_source}.")
        if host.log_source == "none" and host.privilege == "none":
            detail = reasons["unreadable"]
        return [Finding("auth-log", "warn", "Key usage could not be checked", detail + " stale-key was skipped, not passed.")]
    findings: list[Finding] = []
    covered_days = int(((host.now or 0) - (host.log_since or host.now or 0)) / DAY)
    source = "the systemd journal (sshd units only)" if host.log_source == "journal" else "syslog files, which any local user can write to"
    findings.append(
        Finding(
            "auth-log",
            "pass",
            "sshd logins were read",
            f"Read {covered_days} day(s) of logins from {source}.",
        )
    )
    stale = []
    unseen = []
    for account in readable:
        for key in account.keys:
            status, login = usage_status(host, account.user, key, policy)
            if status == "stale":
                last = f"last used {_iso(login.last)}" if login and login.last else "no login in the logs"
                stale.append(_line(account, key, last))
            elif status == "unseen":
                unseen.append(_line(account, key, f"no login in {covered_days} day(s) of logs"))
    if stale:
        findings.append(
            Finding(
                "stale-key",
                "fail",
                f"A key has not been used in {policy.stale_days} days" if len(stale) == 1 else f"{len(stale)} keys have not been used in {policy.stale_days} days",
                "; ".join(stale) + ". Remove keys nobody uses; they are access nobody is watching.",
            )
        )
    elif unseen:
        findings.append(
            Finding(
                "stale-key",
                "warn",
                "Some keys were not used in the logs available",
                "; ".join(unseen) + f". The logs cover less than {policy.stale_days} days, so these are not called stale yet.",
            )
        )
    elif readable:
        findings.append(Finding("stale-key", "pass", f"Every key was used in the last {policy.stale_days} days", "Each authorized key has a login in the sshd log."))
    return findings
