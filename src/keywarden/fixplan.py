"""A fix plan: an Ansible playbook that removes flagged keys. Keywarden never runs it.

The playbook matches keys by fingerprint on the host itself (ssh-keygen -lf), so it
needs no key bodies. By default it only lists what it would remove; it changes
files only with -e keywarden_apply=true, and backs each file up first.
"""

from __future__ import annotations

import json
import re

from keywarden.check import FINGERPRINT
from keywarden.inventory import _NAME, _USER

REASONS = ("leaver", "outside", "stale", "unowned", "expired", "revoked")
DEFAULT_REASONS = ("leaver", "outside", "revoked")

# Runs on the managed host as: sh -c "$script" keywarden-remove <account> <fingerprint>...
REMOVER = r"""set -eu
user=$1
shift
home=""
if command -v getent >/dev/null 2>&1; then
  home=$(getent passwd "$user" | cut -d: -f6)
fi
if [ -z "$home" ] && command -v dscl >/dev/null 2>&1; then
  home=$(dscl . -read "/Users/$user" NFSHomeDirectory 2>/dev/null | awk '{ print $2 }')
fi
if [ -z "$home" ]; then
  echo "no home directory for $user"
  exit 1
fi
file="$home/.ssh/authorized_keys"
if [ ! -f "$file" ]; then
  echo "removed=0 ($file is absent)"
  exit 0
fi
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
removed=0
while IFS= read -r line || [ -n "$line" ]; do
  fp=$(printf '%s\n' "$line" | ssh-keygen -lf - 2>/dev/null | awk '{ print $2 }') || fp=""
  drop=0
  if [ -n "$fp" ]; then
    for want in "$@"; do
      if [ "$fp" = "$want" ]; then
        drop=1
      fi
    done
  fi
  if [ "$drop" -eq 1 ]; then
    removed=$((removed + 1))
    echo "match $user $fp"
  else
    printf '%s\n' "$line" >> "$tmp"
  fi
done < "$file"
if [ "$removed" -gt 0 ] && [ "${KEYWARDEN_APPLY:-0}" = "1" ]; then
  cp -p "$file" "$file.keywarden-$(date +%Y%m%d%H%M%S)"
  cat "$tmp" > "$file"
  echo "removed=$removed"
else
  echo "would-remove=$removed"
fi
"""


def _reasons_for(row: dict, wanted: set[str], revoked: set[tuple[str, str, str]], now: int) -> list[str]:
    reasons: list[str] = []
    if "leaver" in wanted and row.get("ownerLeft"):
        reasons.append(f"leaver {row.get('owner')}")
    if "outside" in wanted and row.get("inAllow") is False and row.get("account") != "root":
        reasons.append("not in the push")
    if "stale" in wanted and row.get("usage") == "stale":
        reasons.append("stale")
    if "unowned" in wanted and "owner" in row and not row.get("owner"):
        reasons.append("no owner")
    expiry = row.get("options", {}).get("expiryTime")
    if "expired" in wanted and isinstance(expiry, int) and expiry < now:
        reasons.append("expired")
    if (row.get("host"), row.get("account"), row.get("fingerprint")) in revoked:
        reasons.append("revoked in review")
    return reasons


def removals(document: dict, wanted: set[str], review: dict | None = None) -> list[dict]:
    import time

    now = int(time.time())
    revoked = set()
    for decision in (review or {}).get("decisions", []):
        if decision.get("decision") == "revoke":
            revoked.add((decision.get("host"), decision.get("account"), decision.get("fingerprint")))
    hosts = document.get("hosts") or ([document["host"]] if document.get("host") else [])
    grouped: dict[tuple[str, str], dict] = {}
    for host in hosts:
        for row in host.get("keys", []):
            reasons = _reasons_for(row, wanted, revoked, now)
            if not reasons:
                continue
            name, account, fingerprint = row.get("host", host.get("name")), row.get("account"), row.get("fingerprint")
            if not (isinstance(name, str) and _NAME.fullmatch(name)):
                raise ValueError(f"host name cannot go in a playbook: {name!r}")
            if not (isinstance(account, str) and _USER.fullmatch(account)):
                raise ValueError(f"account name cannot go in a playbook: {account!r}")
            if not (isinstance(fingerprint, str) and FINGERPRINT.fullmatch(fingerprint)):
                raise ValueError(f"not a fingerprint: {fingerprint!r}")
            entry = grouped.setdefault((name, account), {"host": name, "account": account, "keys": {}})
            entry["keys"].setdefault(fingerprint, [])
            for reason in reasons:
                if reason not in entry["keys"][fingerprint]:
                    entry["keys"][fingerprint].append(reason)
    return list(grouped.values())


def _q(value: str) -> str:
    """A YAML double-quoted scalar. json.dumps output is valid YAML."""
    return json.dumps(value)


_SAFE_COMMENT = re.compile(r"[^A-Za-z0-9 @._:+/=,-]")


def render_playbook(items: list[dict], *, generated: str, version: str) -> str:
    if not items:
        return f"# Keywarden {version} fix plan, {generated}: nothing to remove.\n"
    hosts = sorted({item["host"] for item in items})
    lines = [
        "---",
        f"# Keywarden {version} fix plan, generated {generated}.",
        "# Review every task before running it. Keywarden did not run this.",
        "#",
        "# Dry run (lists matching keys, changes nothing):",
        "#   ansible-playbook -i <inventory> keywarden-fix.yml",
        "# Apply (backs up each authorized_keys file first):",
        "#   ansible-playbook -i <inventory> keywarden-fix.yml -e keywarden_apply=true",
        "#",
    ]
    for item in items:
        for fingerprint, reasons in item["keys"].items():
            lines.append(f"# {item['host']} {item['account']} {fingerprint}: {_SAFE_COMMENT.sub('', ', '.join(reasons))}")
    lines += [
        "- name: Keywarden fix plan",
        f"  hosts: {_q(','.join(hosts))}",
        "  become: true",
        "  gather_facts: false",
        "  vars:",
        "    keywarden_apply: false",
        "    keywarden_remover: |",
    ]
    lines += [("      " + line) if line else "" for line in REMOVER.splitlines()]
    lines.append("  tasks:")
    for item in items:
        prints = list(item["keys"])
        label = f"{item['host']} {item['account']}: {len(prints)} key(s)"
        command = "sh -c {{ keywarden_remover | quote }} keywarden-remove " + " ".join([item["account"], *prints])
        lines += [
            f"    - name: {_q(label)}",
            f"      when: inventory_hostname == {_q(item['host'])}",
            f"      ansible.builtin.shell: {_q(command)}",
            "      environment:",
            "        KEYWARDEN_APPLY: \"{{ '1' if keywarden_apply | bool else '0' }}\"",
            "      register: keywarden_result",
            "      changed_when: \"'removed=' in keywarden_result.stdout and 'removed=0' not in keywarden_result.stdout\"",
            f"    - name: {_q('result: ' + label)}",
            f"      when: inventory_hostname == {_q(item['host'])}",
            "      ansible.builtin.debug:",
            "        var: keywarden_result.stdout_lines",
        ]
    return "\n".join(lines) + "\n"
