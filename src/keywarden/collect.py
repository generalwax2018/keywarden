"""Read sshd and authorized_keys. Key text stays in this process only."""

from __future__ import annotations

import getpass
import glob
import gzip
import os
import time
import re
import shutil
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from keywarden.check import Account, HostObservation, SshdFacts, parse_sshd
from keywarden.parse import parse_public_keys

PROTOCOL_VERSION = 3
SUPPORTED_PROTOCOLS = {2, 3}

# Address and user that sshd -T -C uses to evaluate Match blocks for root.
# 192.0.2.1 is TEST-NET-1 and keywarden.invalid cannot resolve, so only
# "Match User root" style blocks apply, not address or host blocks.
ROOT_MATCH_SPEC = "user=root,host=keywarden.invalid,addr=192.0.2.1"
SSHD_CANDIDATES = ("sshd", "/usr/sbin/sshd", "/usr/local/sbin/sshd", "/sbin/sshd")
SSHD_CONFIG_GLOBS = ("/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*.conf")
_MATCH_LINE = re.compile(r"^\s*Match\s", re.IGNORECASE | re.MULTILINE)
_ROOT_FIELDS = (
    "permitrootlogin",
    "passwordauthentication",
    "kbdinteractiveauthentication",
    "authenticationmethods",
    "pubkeyauthentication",
)

# Fixed script. Usernames arrive as arguments, never interpolated.
# Every line read from an authorized_keys file is prefixed with "K " so a user
# who controls their own file cannot write protocol markers into the stream.
REMOTE_SCRIPT = r"""
set -u
echo KEYWARDEN 3
echo "HOST $(hostname 2>/dev/null || echo unknown)"
echo "NOW $(date +%s 2>/dev/null || echo unknown) $(date +%z 2>/dev/null || echo +0000)"
P=""
if [ "$(id -u 2>/dev/null)" = "0" ]; then
  echo PRIV root
elif sudo -n true </dev/null >/dev/null 2>&1; then
  P=sudo
  echo PRIV sudo
else
  echo PRIV none
fi
p() {
  if [ -n "$P" ]; then
    sudo -n "$@" </dev/null
  else
    "$@" </dev/null
  fi
}
SSHD_BIN=""
for candidate in sshd /usr/sbin/sshd /usr/local/sbin/sshd /sbin/sshd; do
  if command -v "$candidate" >/dev/null 2>&1; then
    SSHD_BIN=$(command -v "$candidate")
    break
  fi
done
sshd_state=missing
sshd_out=""
if [ -n "$SSHD_BIN" ]; then
  if sshd_out=$(p "$SSHD_BIN" -T 2>/dev/null); then
    sshd_state=ok
  elif sshd_out=$(sudo -n "$SSHD_BIN" -T </dev/null 2>/dev/null); then
    sshd_state=ok
  else
    sshd_state=failed
    sshd_out=""
  fi
fi
echo "SSHDRUN $sshd_state"
echo SSHD
if [ -n "$sshd_out" ]; then
  printf '%s\n' "$sshd_out"
fi
echo ENDSSHD
cfgs=/etc/ssh/sshd_config
for extra in /etc/ssh/sshd_config.d/*.conf; do
  if [ -e "$extra" ]; then
    cfgs="$cfgs $extra"
  fi
done
match=unknown
if p grep -Eqs '^[[:space:]]*[Mm][Aa][Tt][Cc][Hh][[:space:]]' $cfgs; then
  match=yes
else
  status=$?
  if [ "$status" -eq 1 ]; then
    match=no
  fi
fi
echo "MATCH $match"
echo SSHDROOT
if [ "$sshd_state" = "ok" ] && [ "$match" = "yes" ]; then
  root_out=""
  if root_out=$(p "$SSHD_BIN" -T -C user=root,host=keywarden.invalid,addr=192.0.2.1 2>/dev/null); then
    :
  else
    root_out=$(sudo -n "$SSHD_BIN" -T -C user=root,host=keywarden.invalid,addr=192.0.2.1 </dev/null 2>/dev/null || true)
  fi
  if [ -n "$root_out" ]; then
    printf '%s\n' "$root_out" | grep -Ei '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|authenticationmethods|pubkeyauthentication) ' || true
  fi
fi
echo ENDSSHDROOT
# Successful public-key logins: newest line and a count per account and key.
# The journal is read only for sshd's own units as root (_UID=0), which a local
# user cannot forge with logger. Syslog files can be forged; the report says which was used.
LOGAWK='
NR == 1 { print "AUTHFIRST " $1 " " $2 " " $3 }
/Accepted publickey for / {
  user = ""
  for (i = 1; i < NF; i++) if ($i == "publickey" && $(i + 1) == "for") { user = $(i + 2); break }
  if (user == "" || !match($0, /SHA256:[A-Za-z0-9+\/]+/)) next
  key = user " " substr($0, RSTART, RLENGTH)
  count[key]++
  last[key] = $0
}
END { for (key in count) print "L " count[key] " " last[key] }
'
log_source=none
log_out=""
if command -v journalctl >/dev/null 2>&1; then
  log_out=$(p journalctl -q --no-pager -o short-unix _UID=0 _SYSTEMD_UNIT=ssh.service _SYSTEMD_UNIT=sshd.service 2>/dev/null | awk "$LOGAWK")
  if [ -n "$log_out" ]; then
    log_source=journal
  fi
fi
if [ "$log_source" = "none" ]; then
  log_files=""
  for base in /var/log/auth.log /var/log/secure; do
    rotated=$(ls -1 "$base".[0-9]* 2>/dev/null | sed 's/^\(.*\.\)\([0-9][0-9]*\)\(\.gz\)\{0,1\}$/\2 &/' | sort -k1,1nr | cut -d' ' -f2)
    dated=$(ls -1 "$base"-[0-9]* 2>/dev/null | sort)
    for candidate in $rotated $dated "$base"; do
      if [ -e "$candidate" ]; then
        log_files="$log_files $candidate"
      fi
    done
  done
  if [ -n "$log_files" ]; then
    log_source=file
    for candidate in $log_files; do
      if ! p test -r "$candidate"; then
        log_source=unreadable
      fi
    done
    if [ "$log_source" = "file" ]; then
      log_out=$(for candidate in $log_files; do p gzip -cdf "$candidate" 2>/dev/null; done | awk "$LOGAWK")
    else
      log_out=""
    fi
  fi
fi
echo "AUTHLOG $log_source"
echo LOGINS
if [ -n "$log_out" ]; then
  printf '%s\n' "$log_out"
fi
echo ENDLOGINS
emit_sudo() {
  echo "GROUPS $(id -nG "$1" 2>/dev/null)"
  if ! command -v sudo >/dev/null 2>&1; then
    echo "SUDOSTATE absent"
    return
  fi
  sudo_out=$(p sudo -n -l -U "$1" 2>&1)
  case $sudo_out in
    *"may run the following"*|*"not allowed to run sudo"*)
      echo "SUDOSTATE ok"
      echo SUDO
      printf '%s\n' "$sudo_out" | awk '{ print "S " $0 }'
      echo ENDSUDO
      ;;
    *) echo "SUDOSTATE unreadable" ;;
  esac
}
mode_of() {
  target=$1
  if [ "$(access_of "$target")" = "absent" ]; then
    echo absent
    return
  fi
  if p stat -c %a "$target" >/dev/null 2>&1; then
    p stat -c %a "$target" 2>/dev/null || echo unknown
    return
  fi
  p stat -f %OLp "$target" 2>/dev/null || echo unknown
}
access_of() {
  target=$1
  if p test -e "$target" || p test -L "$target"; then
    echo present
    return
  fi
  err=$(p ls -ld "$target" 2>&1 >/dev/null)
  case $err in
    *[Pp]ermission*denied*|*[Nn]ot\ permitted*) echo unreadable ;;
    *) echo absent ;;
  esac
}
emit_keys() {
  keyfile=$1
  if [ "$(access_of "$keyfile")" = "absent" ]; then
    echo STATE absent
    echo KEYS
    echo ENDKEYS
    return
  fi
  if p test -r "$keyfile" && p cat "$keyfile" >/dev/null 2>&1; then
    echo STATE ok
    echo KEYS
    p cat "$keyfile" 2>/dev/null | awk '{ print "K " $0 }'
    echo ENDKEYS
    return
  fi
  if [ -z "$P" ] && sudo -n cat "$keyfile" </dev/null >/dev/null 2>&1; then
    echo STATE ok
    echo KEYS
    sudo -n cat "$keyfile" </dev/null 2>/dev/null | awk '{ print "K " $0 }'
    echo ENDKEYS
    return
  fi
  echo STATE unreadable
  echo KEYS
  echo ENDKEYS
}
emit_account() {
  user=$1
  home=$2
  uid=$3
  locked=$4
  echo "ACCOUNT $user"
  if [ -n "$uid" ]; then
    echo "UID $uid"
  fi
  if [ -n "$locked" ]; then
    echo "LOCKED $locked"
  fi
  dir_access=$(access_of "$home/.ssh")
  if [ "$dir_access" = "absent" ]; then
    echo DIR absent
    echo FILE absent
    echo STATE absent
    echo KEYS
    echo ENDKEYS
    return
  fi
  emit_sudo "$user"
  if [ "$dir_access" = "present" ]; then
    echo "DIR $(mode_of "$home/.ssh")"
    echo "FILE $(mode_of "$home/.ssh/authorized_keys")"
  else
    echo DIR unknown
    echo FILE unknown
  fi
  emit_keys "$home/.ssh/authorized_keys"
}
seen_users=" "
mark() { seen_users="$seen_users$1 "; }
already() {
  case $seen_users in
    *" $1 "*) return 0 ;;
    *) return 1 ;;
  esac
}
locked_of() {
  case $1 in
    "") echo no ;;
    x) echo unknown ;;
    *) echo yes ;;
  esac
}
for user in "$@"; do
  [ -n "$user" ] || continue
  already "$user" && continue
  entry=$(getent passwd "$user" 2>/dev/null | head -n 1)
  home=$(printf '%s' "$entry" | awk -F: 'NR==1 { print $6 }')
  uid=$(printf '%s' "$entry" | awk -F: 'NR==1 { print $3 }')
  pass=$(printf '%s' "$entry" | awk -F: 'NR==1 { print $2 }')
  if [ -z "${home:-}" ]; then
    echo "ACCOUNT $user"
    echo DIR unknown
    echo FILE unknown
    echo STATE unreadable
    echo KEYS
    echo ENDKEYS
    mark "$user"
    continue
  fi
  emit_account "$user" "$home" "$uid" "$(locked_of "$pass")"
  mark "$user"
done
if [ -r /etc/passwd ]; then
  echo "PASSWD ok"
  while IFS=: read -r user pass uid _gid _gecos home _shell; do
    [ -n "${user:-}" ] || continue
    already "$user" && continue
    if [ -z "${home:-}" ]; then
      if [ "${uid:-}" = "0" ]; then
        echo "ACCOUNT $user"
        echo "UID $uid"
        echo "LOCKED $(locked_of "$pass")"
        echo DIR absent
        echo FILE absent
        echo STATE absent
        echo KEYS
        echo ENDKEYS
        mark "$user"
      fi
      continue
    fi
    want=0
    if [ "${uid:-}" = "0" ]; then
      want=1
    elif [ "$(access_of "$home/.ssh/authorized_keys")" != "absent" ]; then
      want=1
    fi
    [ "$want" -eq 1 ] || continue
    emit_account "$user" "$home" "$uid" "$(locked_of "$pass")"
    mark "$user"
  done < /etc/passwd
else
  echo "PASSWD unreadable"
fi
echo END
"""

FINGERPRINT_TEXT = re.compile(r"SHA256:[A-Za-z0-9+/]+")
LOCAL_SUPPORTED = os.name == "posix" and hasattr(os, "geteuid")
LOCAL_UNSUPPORTED_MESSAGE = (
    "--local reads this machine's sshd and user accounts, which only exist on Linux and other POSIX systems. "
    "Run Keywarden on the server itself, or from here use --host user@server, --inventory hosts.ini, "
    "or keywarden ui and its lab hosts."
)


def _euid() -> int:
    return os.geteuid() if hasattr(os, "geteuid") else -1


_DESTINATION = re.compile(r"^[A-Za-z0-9._:-]+@[A-Za-z0-9._:-]+$|^[A-Za-z0-9._:-]+$")
_USERNAME = re.compile(r"^[a-z_][-a-z0-9_.]*\$?$", re.IGNORECASE)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def file_mode(path: Path) -> str:
    try:
        mode = path.lstat().st_mode & 0o7777
    except FileNotFoundError:
        return "absent"
    except OSError:
        return "unknown"
    return format(mode, "04o") if mode > 0o777 else format(mode, "03o")


def _access(path: Path) -> str:
    """present, absent, or unreadable. Permission errors are not treated as missing."""
    try:
        path.lstat()
    except FileNotFoundError:
        return "absent"
    except NotADirectoryError:
        return "absent"
    except OSError:
        return "unreadable"
    return "present"


def inspect_account(user: str, home: Path) -> Account:
    home_state = _access(home)
    if home_state == "absent":
        return Account(user, "absent", "absent", [], "absent")
    if home_state == "unreadable":
        return Account(user, "unknown", "unknown", [], "unreadable")
    ssh_dir = home / ".ssh"
    dir_state = _access(ssh_dir)
    if dir_state == "absent":
        return Account(user, "absent", "absent", [], "absent")
    if dir_state == "unreadable":
        return Account(user, "unknown", "unknown", [], "unreadable")
    key_file = ssh_dir / "authorized_keys"
    file_state = _access(key_file)
    if file_state == "absent":
        return Account(user, file_mode(ssh_dir), "absent", [], "absent")
    if file_state == "unreadable":
        return Account(user, file_mode(ssh_dir), "unknown", [], "unreadable")
    try:
        text = key_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return Account(user, file_mode(ssh_dir), file_mode(key_file), [], "unreadable")
    try:
        keys, _issues = parse_public_keys(text, user)
    finally:
        del text
    return Account(user, file_mode(ssh_dir), file_mode(key_file), keys, "ok")


def _password_locked(field: str) -> bool | None:
    if field == "":
        return False
    if field == "x":
        return None
    return True


def _passwd_records() -> tuple[dict[str, tuple[Path | None, int | None, bool | None]], str]:
    records: dict[str, tuple[Path | None, int | None, bool | None]] = {}
    try:
        text = Path("/etc/passwd").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return records, "unreadable"
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) < 6 or not parts[0]:
            continue
        uid = int(parts[2]) if parts[2].isdigit() else None
        home = Path(parts[5]) if parts[5] else None
        if home is None and uid != 0:
            continue
        records[parts[0]] = (home, uid, _password_locked(parts[1]))
    return records, "ok"


def _sshd_binary() -> str | None:
    for candidate in SSHD_CANDIDATES:
        found = shutil.which(candidate)
        if found:
            return found
    return None


def _run(command: list[str]) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def _sshd_output(binary: str, extra: list[str]) -> str | None:
    attempts = [[binary, "-T", *extra]]
    if _euid() != 0 and shutil.which("sudo"):
        attempts.append(["sudo", "-n", binary, "-T", *extra])
    for command in attempts:
        completed = _run(command)
        if completed is not None and completed.returncode == 0 and completed.stdout:
            return completed.stdout
    return None


def _match_state() -> str:
    paths: list[str] = []
    for pattern in SSHD_CONFIG_GLOBS:
        paths.extend(sorted(glob.glob(pattern)))
    if not paths:
        return "unknown"
    unreadable = False
    for path in paths:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            unreadable = True
            continue
        if _MATCH_LINE.search(text):
            return "yes"
    return "unknown" if unreadable else "no"


def _root_lines(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if line.split(" ", 1)[0].lower() in _ROOT_FIELDS)


def _local_sshd() -> tuple[SshdFacts, str, str, SshdFacts | None]:
    binary = _sshd_binary()
    match = _match_state()
    if binary is None:
        return parse_sshd(""), "missing", match, None
    text = _sshd_output(binary, [])
    if text is None:
        return parse_sshd(""), "failed", match, None
    root = None
    if match == "yes":
        root_text = _sshd_output(binary, ["-C", ROOT_MATCH_SPEC])
        if root_text:
            root = parse_sshd(_root_lines(root_text))
    return parse_sshd(text), "ok", match, root


def _ordered_users(extra: list[str], records: dict[str, tuple[Path | None, int | None, bool | None]]) -> list[str]:
    wanted: list[str] = []

    def add(user: str) -> None:
        if user and user not in wanted:
            wanted.append(user)

    add("root")
    add(getpass.getuser())
    for user in extra:
        if not _USERNAME.fullmatch(user):
            raise ValueError(f"not a username: {user}")
        add(user)
    for user, (home, uid, _locked) in records.items():
        if uid == 0:
            add(user)
        elif home is not None and _access(home / ".ssh" / "authorized_keys") != "absent":
            # Present, or hidden behind a permission error. A hidden file is
            # reported as unreadable, never skipped.
            add(user)
    return wanted


_LOGIN_UNITS = ["_UID=0", "_SYSTEMD_UNIT=ssh.service", "_SYSTEMD_UNIT=sshd.service"]
_ACCEPTED_MARK = "Accepted publickey for "


def _group_names(user: str) -> list[str] | None:
    completed = _run(["id", "-nG", user])
    if completed is None or completed.returncode != 0:
        return None
    return completed.stdout.split()


def _sudo_rules(user: str) -> tuple[str, list[str]]:
    if not shutil.which("sudo"):
        return "absent", []
    attempts = [["sudo", "-n", "-l", "-U", user]]
    for command in attempts:
        completed = _run(command)
        if completed is None:
            continue
        text = (completed.stdout or "") + (completed.stderr or "")
        if "may run the following" in text or "not allowed to run sudo" in text:
            return "ok", text.splitlines()
    return "unreadable", []


def _aggregate_logins(lines) -> tuple[str | None, list[str]]:
    """Same reduction the remote awk does: newest line and a count per account and key."""
    first: str | None = None
    newest: dict[tuple[str, str], str] = {}
    counts: dict[tuple[str, str], int] = {}
    for line in lines:
        line = line.rstrip("\n")
        if first is None:
            first = " ".join(line.split()[:3])
        position = line.find(_ACCEPTED_MARK)
        if position == -1:
            continue
        rest = line[position + len(_ACCEPTED_MARK):].split(" ", 1)
        found = FINGERPRINT_TEXT.search(line)
        if not rest or not found:
            continue
        key = (rest[0], found.group(0))
        counts[key] = counts.get(key, 0) + 1
        newest[key] = line
    return first, [f"{counts[key]} {newest[key]}" for key in counts]


def _log_files() -> list[str]:
    ordered: list[str] = []
    for base in ("/var/log/auth.log", "/var/log/secure"):
        rotated = []
        for path in glob.glob(base + ".[0-9]*"):
            suffix = path[len(base) + 1 :].split(".", 1)[0]
            if suffix.isdigit():
                rotated.append((int(suffix), path))
        ordered.extend(path for _number, path in sorted(rotated, reverse=True))
        ordered.extend(sorted(glob.glob(base + "-[0-9]*")))
        if os.path.exists(base):
            ordered.append(base)
    return ordered


def _read_log_file(path: str):
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
        yield from handle


def _local_logins(now: int, offset: str):
    from keywarden.access import parse_log_time, parse_login_lines

    if shutil.which("journalctl"):
        completed = _run_long(["journalctl", "-q", "--no-pager", "-o", "short-unix", *_LOGIN_UNITS])
        if completed is not None and completed.returncode == 0 and completed.stdout.strip():
            first, rows = _aggregate_logins(completed.stdout.splitlines())
            since = parse_log_time(first, now, offset) if first else None
            return "journal", since, parse_login_lines(rows, now, offset)
    files = _log_files()
    if not files:
        return "none", None, {}
    if any(not os.access(path, os.R_OK) for path in files):
        return "unreadable", None, {}

    def stream():
        for path in files:
            try:
                yield from _read_log_file(path)
            except OSError:
                continue

    first, rows = _aggregate_logins(stream())
    since = parse_log_time(first, now, offset) if first else None
    return "file", since, parse_login_lines(rows, now, offset)


def _run_long(command: list[str]) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=60, check=False, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None


def collect_local(extra_users: list[str] | None = None) -> HostObservation:
    if not LOCAL_SUPPORTED:
        raise ValueError(LOCAL_UNSUPPORTED_MESSAGE)
    records, passwd_state = _passwd_records()
    accounts = []
    for user in _ordered_users(extra_users or [], records):
        record = records.get(user)
        if record is None:
            accounts.append(Account(user, "unknown", "unknown", [], "unreadable"))
            continue
        home, uid, locked = record
        if home is None:
            account = Account(user, "absent", "absent", [], "absent")
        else:
            account = inspect_account(user, home)
        account.uid = uid
        account.password_locked = locked
        if account.read_state != "absent":
            account.groups = _group_names(user)
            account.sudo_state, account.sudo_lines = _sudo_rules(user)
        accounts.append(account)
    sshd, sshd_state, match, root = _local_sshd()
    now = int(time.time())
    offset = time.strftime("%z")
    log_source, log_since, logins = _local_logins(now, offset)
    return HostObservation(
        name=socket.gethostname(),
        address="local",
        role="local",
        observed_at=now_iso(),
        sshd=sshd,
        accounts=accounts,
        passwd_state=passwd_state,
        sshd_state=sshd_state,
        match_blocks=match,
        sshd_root=root,
        privilege="root" if _euid() == 0 else "none",
        now=now,
        log_source=log_source,
        log_since=log_since,
        logins=logins,
    )


class ProtocolError(ValueError):
    """Collector output was not well formed. Nothing from it is trusted."""


def _malformed(index: int, why: str) -> ProtocolError:
    return ProtocolError(f"observation is malformed at line {index + 1}: {why}")


_ACCOUNT_FIELDS = ("DIR ", "FILE ", "STATE ", "UID ", "LOCKED ", "GROUPS ", "SUDOSTATE ")


def parse_protocol(text: str, address: str = "observation") -> HostObservation:
    """Parse collector output strictly.

    Each section may appear once, key lines must carry the "K " prefix, and the
    stream must end with END. Anything else is refused rather than guessed at,
    so text inside an authorized_keys file cannot rewrite the observation.
    """
    lines = text.splitlines()
    if not lines:
        raise ProtocolError("observation is empty")
    header = lines[0].strip()
    if header == "KEYWARDEN 1":
        raise ProtocolError("observation is from an older collector (protocol 1); run the current collector again")
    version_text = header[len("KEYWARDEN "):] if header.startswith("KEYWARDEN ") else ""
    if not version_text.isdigit() or int(version_text) not in SUPPORTED_PROTOCOLS:
        raise ProtocolError("observation is not keywarden collector output this version can read")

    name = "unknown"
    privilege = "unknown"
    sshd_state = "unknown"
    match = "unknown"
    sshd_lines: list[str] | None = None
    root_lines: list[str] | None = None
    passwd_state = "unknown"
    now: int | None = None
    offset: str | None = None
    log_source = "unknown"
    login_lines: list[str] | None = None
    accounts: list[Account] = []
    seen_users: set[str] = set()
    seen: set[str] = set()
    ended = False

    def once(tag: str, index: int) -> None:
        if tag in seen:
            raise _malformed(index, f"{tag} appears twice")
        seen.add(tag)

    def block(index: int, end: str) -> tuple[list[str], int]:
        body: list[str] = []
        index += 1
        while index < len(lines) and lines[index] != end:
            body.append(lines[index])
            index += 1
        if index >= len(lines):
            raise _malformed(index - 1, f"missing {end}")
        return body, index + 1

    index = 1
    while index < len(lines):
        line = lines[index]
        if ended:
            if line.strip():
                raise _malformed(index, "text after END")
            index += 1
            continue
        if not line.strip():
            index += 1
            continue
        if line.startswith("HOST "):
            once("HOST", index)
            name = line[5:].strip() or "unknown"
            index += 1
        elif line.startswith("PRIV "):
            once("PRIV", index)
            privilege = line[5:].strip() or "unknown"
            index += 1
        elif line.startswith("SSHDRUN "):
            once("SSHDRUN", index)
            sshd_state = line[8:].strip() or "unknown"
            index += 1
        elif line.startswith("MATCH "):
            once("MATCH", index)
            match = line[6:].strip() or "unknown"
            index += 1
        elif line.startswith("NOW "):
            once("NOW", index)
            parts = line[4:].split()
            now = int(parts[0]) if parts and parts[0].isdigit() else None
            offset = parts[1] if len(parts) > 1 else None
            index += 1
        elif line.startswith("AUTHLOG "):
            once("AUTHLOG", index)
            log_source = line[8:].strip() or "unknown"
            index += 1
        elif line == "LOGINS":
            once("LOGINS", index)
            login_lines, index = block(index, "ENDLOGINS")
        elif line.startswith("PASSWD "):
            once("PASSWD", index)
            passwd_state = line[7:].strip() or "unknown"
            index += 1
        elif line == "SSHD":
            once("SSHD", index)
            sshd_lines, index = block(index, "ENDSSHD")
        elif line == "SSHDROOT":
            once("SSHDROOT", index)
            root_lines, index = block(index, "ENDSSHDROOT")
        elif line.startswith("ACCOUNT "):
            account, index = _parse_account(lines, index)
            if account.user in seen_users:
                raise _malformed(index - 1, f"account {account.user} appears twice")
            seen_users.add(account.user)
            accounts.append(account)
        elif line == "END":
            ended = True
            index += 1
        else:
            raise _malformed(index, "unexpected line")
    if not ended:
        raise ProtocolError("observation is incomplete: END is missing")
    root = parse_sshd(_root_lines("\n".join(root_lines))) if root_lines else None
    log_since, logins = _read_logins(login_lines or [], now, offset, start=0)
    return HostObservation(
        name=name,
        address=address,
        role="observed",
        observed_at=now_iso(),
        sshd=parse_sshd("\n".join(sshd_lines or [])),
        accounts=accounts,
        passwd_state=passwd_state,
        sshd_state=sshd_state,
        match_blocks=match,
        sshd_root=root,
        privilege=privilege,
        now=now,
        log_source=log_source,
        log_since=log_since,
        logins=logins,
    )


def _read_logins(lines: list[str], now: int | None, offset: str | None, start: int):
    """LOGINS holds one AUTHFIRST line and "L <count> <log line>" rows. Nothing else."""
    from keywarden.access import parse_log_time, parse_login_lines

    since: int | None = None
    rows: list[str] = []
    for position, line in enumerate(lines):
        if line.startswith("AUTHFIRST "):
            since = parse_log_time(line[10:], now, offset)
        elif line.startswith("L "):
            rows.append(line[2:])
        elif line.strip():
            raise ProtocolError(f"observation is malformed in LOGINS (row {position + 1}): unexpected line")
    return since, parse_login_lines(rows, now, offset)


def _parse_account(lines: list[str], index: int) -> tuple[Account, int]:
    user = lines[index][8:].strip()
    if not _USERNAME.fullmatch(user):
        raise _malformed(index, "account name is not a username")
    index += 1
    fields: dict[str, str] = {}
    key_lines: list[str] | None = None
    sudo_lines: list[str] | None = None
    while index < len(lines):
        current = lines[index]
        if current == "SUDO":
            if sudo_lines is not None:
                raise _malformed(index, "SUDO appears twice for one account")
            sudo_lines = []
            index += 1
            while index < len(lines) and lines[index] != "ENDSUDO":
                entry = lines[index]
                if entry == "S":
                    sudo_lines.append("")
                elif entry.startswith("S "):
                    sudo_lines.append(entry[2:])
                else:
                    raise _malformed(index, "sudo line without the S prefix")
                index += 1
            if index >= len(lines):
                raise _malformed(index - 1, "missing ENDSUDO")
            index += 1
            continue
        if current == "KEYS":
            if key_lines is not None:
                raise _malformed(index, "KEYS appears twice for one account")
            key_lines = []
            index += 1
            while index < len(lines) and lines[index] != "ENDKEYS":
                entry = lines[index]
                if entry == "K":
                    key_lines.append("")
                elif entry.startswith("K "):
                    key_lines.append(entry[2:])
                else:
                    raise _malformed(index, "key line without the K prefix")
                index += 1
            if index >= len(lines):
                raise _malformed(index - 1, "missing ENDKEYS")
            index += 1
            break
        tag = next((prefix for prefix in _ACCOUNT_FIELDS if current.startswith(prefix)), None)
        if tag is None:
            break
        if tag in fields:
            raise _malformed(index, f"{tag.strip()} appears twice for one account")
        fields[tag] = current[len(tag) :].strip()
        index += 1
    state = fields.get("STATE ", "unreadable")
    uid_text = fields.get("UID ")
    uid = int(uid_text) if uid_text and uid_text.isdigit() else None
    locked = {"yes": True, "no": False}.get(fields.get("LOCKED ", "").lower())
    if state == "ok":
        joined = "\n".join(key_lines or [])
        try:
            keys, _issues = parse_public_keys(joined, user)
        finally:
            del joined
    else:
        keys = []
    if key_lines is not None:
        key_lines.clear()
    account = Account(user, fields.get("DIR ", "unknown"), fields.get("FILE ", "unknown"), keys, state, uid, locked)
    if "GROUPS " in fields:
        account.groups = fields["GROUPS "].split()
    account.sudo_state = fields.get("SUDOSTATE ", "unknown")
    account.sudo_lines = sudo_lines or []
    return account, index


def _text(data) -> str:
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data or ""


def collect_remote(
    destination: str,
    extra_users: list[str] | None = None,
    port: int | None = None,
    *,
    accept_new: bool = False,
    identity_file: str | None = None,
) -> HostObservation:
    if not _DESTINATION.fullmatch(destination) or destination.startswith("-"):
        raise ValueError("host must look like user@hostname")
    users = ["root"]
    if "@" in destination:
        login = destination.split("@", 1)[0]
        if login not in users:
            users.append(login)
    for user in extra_users or []:
        if not _USERNAME.fullmatch(user):
            raise ValueError(f"not a username: {user}")
        if user not in users:
            users.append(user)
    options = [
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "StrictHostKeyChecking=accept-new" if accept_new else "StrictHostKeyChecking=yes",
    ]
    if port is not None:
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("port is out of range")
        options[0:0] = ["-p", str(port)]
    if identity_file is not None:
        if not identity_file or identity_file.startswith("-") or "\n" in identity_file:
            raise ValueError("identity file path is not usable")
        # The path is handed to ssh. Keywarden never opens it.
        options.extend(["-i", os.path.expanduser(identity_file), "-o", "IdentitiesOnly=yes"])
    command = ["ssh", *options, "--", destination, "sh", "-s", "--", *users]
    try:
        # Bytes, not text: in text mode Windows would turn every newline in the
        # script into CRLF on the way to the remote sh, and the script would fail.
        completed = subprocess.run(
            command,
            input=REMOTE_SCRIPT.encode("utf-8"),
            capture_output=True,
            timeout=60,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("ssh timed out before a check could finish") from exc
    except OSError as exc:
        raise RuntimeError("ssh is not available on this machine") from exc
    stderr = _text(completed.stderr)
    if completed.returncode != 0:
        tail = ""
        for line in reversed(stderr.splitlines()):
            if line.strip() and "PRIVATE KEY" not in line and "ssh-" not in line:
                tail = line.strip()[:180]
                break
        raise RuntimeError(tail or f"ssh exited {completed.returncode}")
    output = _text(completed.stdout)
    try:
        return parse_protocol(output, address=destination)
    finally:
        del output


def read_observation(path: str) -> str:
    if path == "-":
        import sys

        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8", errors="replace")
