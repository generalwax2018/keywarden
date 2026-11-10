"""Read sshd and authorized_keys. Key text stays in this process only."""

from __future__ import annotations

import getpass
import re
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from keywarden.check import Account, HostObservation, parse_sshd
from keywarden.parse import parse_public_keys

# Fixed script. Usernames arrive as arguments, never interpolated.
REMOTE_SCRIPT = r"""
set -u
echo KEYWARDEN 1
echo "HOST $(hostname 2>/dev/null || echo unknown)"
echo SSHD
if command -v sshd >/dev/null 2>&1; then
  sshd -T 2>/dev/null || sudo -n sshd -T 2>/dev/null || true
fi
echo ENDSSHD
mode_of() {
  target=$1
  if [ ! -e "$target" ]; then
    echo absent
    return
  fi
  if stat -c %a "$target" >/dev/null 2>&1; then
    stat -c %a "$target" 2>/dev/null || echo unknown
    return
  fi
  stat -f %OLp "$target" 2>/dev/null || echo unknown
}
access_of() {
  target=$1
  if [ -e "$target" ] || [ -L "$target" ]; then
    echo present
    return
  fi
  err=$(ls -ld "$target" 2>&1 >/dev/null)
  case $err in
    *[Pp]ermission*denied*|*[Nn]ot\ permitted*) echo unreadable ;;
    *) echo absent ;;
  esac
}
emit_keys() {
  keyfile=$1
  access=$(access_of "$keyfile")
  if [ "$access" = "absent" ]; then
    echo STATE absent
    echo KEYS
    echo ENDKEYS
    return
  fi
  if [ "$access" = "unreadable" ]; then
    echo STATE unreadable
    echo KEYS
    echo ENDKEYS
    return
  fi
  if [ -r "$keyfile" ]; then
    echo STATE ok
    echo KEYS
    cat "$keyfile"
    echo
    echo ENDKEYS
    return
  fi
  if sudo -n test -r "$keyfile" 2>/dev/null; then
    echo STATE ok
    echo KEYS
    sudo -n cat "$keyfile"
    echo
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
  home_access=$(access_of "$home")
  dir_access=$(access_of "$home/.ssh")
  if [ "$home_access" = "unreadable" ] || [ "$dir_access" = "unreadable" ]; then
    echo DIR unknown
    echo FILE unknown
    echo STATE unreadable
    echo KEYS
    echo ENDKEYS
    return
  fi
  if [ "$dir_access" = "absent" ]; then
    echo DIR absent
    echo FILE absent
    echo STATE absent
    echo KEYS
    echo ENDKEYS
    return
  fi
  echo "DIR $(mode_of "$home/.ssh")"
  echo "FILE $(mode_of "$home/.ssh/authorized_keys")"
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
      echo "ACCOUNT $user"
      echo "UID $uid"
      echo "LOCKED $(locked_of "$pass")"
      echo DIR absent
      echo FILE absent
      echo STATE absent
      echo KEYS
      echo ENDKEYS
      mark "$user"
      continue
    fi
    want=0
    if [ "${uid:-}" = "0" ]; then
      want=1
    fi
    if [ -n "${home:-}" ] && [ -e "$home/.ssh/authorized_keys" ]; then
      want=1
    fi
    [ "$want" -eq 1 ] || continue
    emit_account "$user" "${home:-/}" "$uid" "$(locked_of "$pass")"
    mark "$user"
  done < /etc/passwd
else
  echo "PASSWD unreadable"
fi
echo END
"""

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
    except OSError:
        return "unreadable"
    return "present"


def inspect_account(user: str, home: Path) -> Account:
    if _access(home) == "absent":
        return Account(user, "absent", "absent", [], "absent")
    if _access(home) == "unreadable":
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


def _passwd_records() -> tuple[dict[str, tuple[Path, int | None, bool | None]], str]:
    records: dict[str, tuple[Path, int | None, bool | None]] = {}
    try:
        text = Path("/etc/passwd").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return records, "unreadable"
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) < 6 or not parts[0] or not parts[5]:
            continue
        uid = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else None
        records[parts[0]] = (Path(parts[5]), uid, _password_locked(parts[1] if len(parts) > 1 else "x"))
    return records, "ok"


def _sshd_text() -> str:
    try:
        completed = subprocess.run(
            ["sshd", "-T"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout or ""


def _ordered_users(extra: list[str], records: dict[str, tuple[Path, int | None, bool | None]]) -> list[str]:
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
        if uid == 0 or (home / ".ssh" / "authorized_keys").exists():
            add(user)
    return wanted


def collect_local(extra_users: list[str] | None = None) -> HostObservation:
    records, passwd_state = _passwd_records()
    accounts = []
    for user in _ordered_users(extra_users or [], records):
        record = records.get(user)
        if record is None:
            accounts.append(Account(user, "unknown", "unknown", [], "unreadable"))
            continue
        home, uid, locked = record
        account = inspect_account(user, home)
        account.uid = uid
        account.password_locked = locked
        accounts.append(account)
    return HostObservation(
        name=socket.gethostname(),
        address="local",
        role="local",
        observed_at=now_iso(),
        sshd=parse_sshd(_sshd_text()),
        accounts=accounts,
        passwd_state=passwd_state,
    )


def parse_protocol(text: str, address: str = "observation") -> HostObservation:
    lines = text.splitlines()
    if not lines or not lines[0].startswith("KEYWARDEN "):
        raise ValueError("observation is not keywarden collector output")
    name = "unknown"
    sshd_lines: list[str] = []
    accounts: list[Account] = []
    passwd_state = "unknown"
    index = 1
    while index < len(lines):
        line = lines[index]
        if line.startswith("HOST "):
            name = line[5:].strip() or "unknown"
            index += 1
            continue
        if line.startswith("PASSWD "):
            passwd_state = line[7:].strip() or "unknown"
            index += 1
            continue
        if line == "SSHD":
            index += 1
            while index < len(lines) and lines[index] != "ENDSSHD":
                sshd_lines.append(lines[index])
                index += 1
            index += 1
            continue
        if line.startswith("ACCOUNT "):
            user = line[8:].strip() or "unknown"
            index += 1
            dir_mode = "unknown"
            file_mode = "unknown"
            state = "unreadable"
            uid: int | None = None
            locked: bool | None = None
            key_lines: list[str] = []
            while index < len(lines) and not lines[index].startswith("ACCOUNT ") and lines[index] != "END":
                current = lines[index]
                if current.startswith("DIR "):
                    dir_mode = current[4:].strip()
                elif current.startswith("FILE "):
                    file_mode = current[5:].strip()
                elif current.startswith("STATE "):
                    state = current[6:].strip()
                elif current.startswith("UID "):
                    raw_uid = current[4:].strip()
                    uid = int(raw_uid) if raw_uid.isdigit() else None
                elif current.startswith("LOCKED "):
                    locked = {"yes": True, "no": False}.get(current[7:].strip().lower())
                elif current == "KEYS":
                    index += 1
                    while index < len(lines) and lines[index] != "ENDKEYS":
                        key_lines.append(lines[index])
                        index += 1
                index += 1
            if state == "ok":
                keys, _issues = parse_public_keys("\n".join(key_lines), user)
            else:
                keys = []
            accounts.append(Account(user, dir_mode, file_mode, keys, state, uid, locked))
            continue
        index += 1
    return HostObservation(
        name=name,
        address=address,
        role="observed",
        observed_at=now_iso(),
        sshd=parse_sshd("\n".join(sshd_lines)),
        accounts=accounts,
        passwd_state=passwd_state,
    )


def collect_remote(
    destination: str,
    extra_users: list[str] | None = None,
    port: int | None = None,
    *,
    accept_new: bool = False,
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
    command = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "StrictHostKeyChecking=accept-new" if accept_new else "StrictHostKeyChecking=yes",
        destination,
        "sh",
        "-s",
        "--",
        *users,
    ]
    if port is not None:
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("port is out of range")
        command[1:1] = ["-p", str(port)]
    try:
        completed = subprocess.run(
            command,
            input=REMOTE_SCRIPT,
            capture_output=True,
            text=True,
            timeout=40,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("ssh timed out before a check could finish") from exc
    except OSError as exc:
        raise RuntimeError("ssh is not available on this machine") from exc
    if completed.returncode != 0:
        tail = ""
        for line in reversed((completed.stderr or "").splitlines()):
            if line.strip() and "PRIVATE KEY" not in line and "ssh-" not in line:
                tail = line.strip()[:180]
                break
        raise RuntimeError(tail or f"ssh exited {completed.returncode}")
    host = parse_protocol(completed.stdout, address=destination)
    return host


def read_observation(path: str) -> str:
    if path == "-":
        import sys

        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8", errors="replace")
