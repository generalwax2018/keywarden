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
  echo "ACCOUNT $user"
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
for user in "$@"; do
  [ -n "$user" ] || continue
  home=$(getent passwd "$user" 2>/dev/null | awk -F: 'NR==1 { print $6 }')
  if [ -z "${home:-}" ]; then
    echo "ACCOUNT $user"
    echo DIR unknown
    echo FILE unknown
    echo STATE unreadable
    echo KEYS
    echo ENDKEYS
    continue
  fi
  emit_account "$user" "$home"
done
if [ -r /etc/passwd ]; then
  while IFS=: read -r user _pass _uid _gid _gecos home _shell; do
    [ -n "${home:-}" ] || continue
    [ -e "$home/.ssh/authorized_keys" ] || continue
    skip=0
    for seen in "$@"; do
      if [ "$seen" = "$user" ]; then
        skip=1
      fi
    done
    [ "$skip" -eq 1 ] && continue
    emit_account "$user" "$home"
  done < /etc/passwd
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
    keys, _issues = parse_public_keys(text, user)
    return Account(user, file_mode(ssh_dir), file_mode(key_file), keys, "ok")


def _passwd_homes() -> dict[str, Path]:
    homes: dict[str, Path] = {}
    try:
        text = Path("/etc/passwd").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return homes
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) < 6 or not parts[0] or not parts[5]:
            continue
        homes[parts[0]] = Path(parts[5])
    return homes


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


def _ordered_users(extra: list[str], homes: dict[str, Path]) -> list[str]:
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
    for user, home in homes.items():
        if (home / ".ssh" / "authorized_keys").exists():
            add(user)
    return wanted


def collect_local(extra_users: list[str] | None = None) -> HostObservation:
    homes = _passwd_homes()
    accounts = []
    for user in _ordered_users(extra_users or [], homes):
        home = homes.get(user)
        if home is None:
            accounts.append(Account(user, "unknown", "unknown", [], "unreadable"))
        else:
            accounts.append(inspect_account(user, home))
    return HostObservation(
        name=socket.gethostname(),
        address="local",
        role="local",
        observed_at=now_iso(),
        sshd=parse_sshd(_sshd_text()),
        accounts=accounts,
    )


def parse_protocol(text: str, address: str = "observation") -> HostObservation:
    lines = text.splitlines()
    if not lines or not lines[0].startswith("KEYWARDEN "):
        raise ValueError("observation is not keywarden collector output")
    name = "unknown"
    sshd_lines: list[str] = []
    accounts: list[Account] = []
    index = 1
    while index < len(lines):
        line = lines[index]
        if line.startswith("HOST "):
            name = line[5:].strip() or "unknown"
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
            key_lines: list[str] = []
            while index < len(lines) and not lines[index].startswith("ACCOUNT ") and lines[index] != "END":
                current = lines[index]
                if current.startswith("DIR "):
                    dir_mode = current[4:].strip()
                elif current.startswith("FILE "):
                    file_mode = current[5:].strip()
                elif current.startswith("STATE "):
                    state = current[6:].strip()
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
            accounts.append(Account(user, dir_mode, file_mode, keys, state))
            continue
        index += 1
    return HostObservation(
        name=name,
        address=address,
        role="observed",
        observed_at=now_iso(),
        sshd=parse_sshd("\n".join(sshd_lines)),
        accounts=accounts,
    )


def collect_remote(destination: str, extra_users: list[str] | None = None) -> HostObservation:
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
        "StrictHostKeyChecking=accept-new",
        destination,
        "sh",
        "-s",
        "--",
        *users,
    ]
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
