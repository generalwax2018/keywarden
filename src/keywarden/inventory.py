"""Ansible INI inventory, enough to know where to SSH. Passwords in the file are ignored."""

from __future__ import annotations

import re
from dataclasses import dataclass

_RANGE = re.compile(r"\[(\d+):(\d+)\]")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,253}$")
_GROUP = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")
_USER = re.compile(r"^[a-z_][-a-z0-9_.]*\$?$", re.IGNORECASE)

# Only connection fields are kept. Passwords, become settings, and everything
# else in the inventory are dropped as the line is read.
_ALIASES = {
    "ansible_host": "host",
    "ansible_ssh_host": "host",
    "ansible_user": "user",
    "ansible_ssh_user": "user",
    "ansible_port": "port",
    "ansible_ssh_port": "port",
    "ansible_ssh_private_key_file": "key",
    "ansible_private_key_file": "key",
}


@dataclass(frozen=True)
class InventoryHost:
    name: str
    address: str
    user: str | None
    port: int | None
    identity_file: str | None = None

    @property
    def destination(self) -> str:
        if self.user:
            return f"{self.user}@{self.address}"
        return self.address


def _expand(token: str) -> list[str]:
    match = _RANGE.search(token)
    if not match:
        return [token]
    start, end = match.group(1), match.group(2)
    first, last = int(start), int(end)
    if last < first or last - first > 256:
        raise ValueError(f"inventory range is too large: {token}")
    width = len(start)
    prefix, suffix = token[: match.start()], token[match.end() :]
    return [f"{prefix}{index:0{width}d}{suffix}" for index in range(first, last + 1)]


def _port(value: str, name: str) -> int:
    if not value.isdigit() or not 1 <= int(value) <= 65535:
        raise ValueError(f"{name} has a port that is not 1-65535")
    return int(value)


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value


def _keep(key: str, value: str, into: dict[str, str]) -> None:
    field = _ALIASES.get(key.strip())
    if field:
        into[field] = _unquote(value)


def _looks_like_yaml(text: str, source: str | None) -> bool:
    if source and source.lower().endswith((".yml", ".yaml", ".json")):
        return True
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        stripped = line.strip()
        return stripped.startswith("{") or stripped == "---" or (stripped.endswith(":") and "=" not in stripped)
    return False


def _ancestors(group: str, parents: dict[str, list[str]]) -> list[str]:
    """Parent groups, farthest first, so nearer groups override them like Ansible does."""
    levels: dict[str, int] = {}
    frontier = [(group, 0)]
    while frontier:
        current, depth = frontier.pop()
        for parent in parents.get(current, []):
            if parent == group or levels.get(parent, -1) >= depth + 1:
                continue
            if depth + 1 > 64:
                raise ValueError("inventory group nesting is too deep or circular")
            levels[parent] = depth + 1
            frontier.append((parent, depth + 1))
    return sorted(levels, key=lambda name: (-levels[name], name))


def parse_inventory(text: str, source: str | None = None) -> list[InventoryHost]:
    if _looks_like_yaml(text, source):
        raise ValueError(
            "only INI inventories are supported in this release. For a YAML inventory, write an INI copy; "
            "'ansible-inventory -i <file> --list' shows each host and its ansible_* connection vars"
        )
    group = "ungrouped"
    kind = "hosts"
    group_vars: dict[str, dict[str, str]] = {"all": {}}
    parents: dict[str, list[str]] = {}
    membership: dict[str, list[str]] = {}
    inline_vars: dict[str, dict[str, str]] = {}
    order: list[str] = []

    for raw in text.splitlines():
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            header = line[1:-1].strip()
            if header.endswith(":vars"):
                group = header[: -len(":vars")] or "all"
                kind = "vars"
                group_vars.setdefault(group, {})
            elif header.endswith(":children"):
                group = header[: -len(":children")]
                kind = "children"
                group_vars.setdefault(group, {})
            elif ":" in header:
                kind = "skip"
            else:
                group = header or "ungrouped"
                kind = "hosts"
                group_vars.setdefault(group, {})
            continue
        if kind == "skip":
            continue
        if kind == "vars":
            if "=" in line:
                key, value = line.split("=", 1)
                _keep(key, value, group_vars.setdefault(group, {}))
            continue
        if kind == "children":
            child = line.split()[0]
            if not _GROUP.fullmatch(child):
                raise ValueError(f"not a group name: {child}")
            if group not in parents.setdefault(child, []):
                parents[child].append(group)
            continue
        parts = line.split()
        names = _expand(parts[0])
        chosen: dict[str, str] = {}
        for part in parts[1:]:
            if "=" in part:
                key, value = part.split("=", 1)
                _keep(key, value, chosen)
        for name in names:
            if not _NAME.fullmatch(name):
                raise ValueError(f"not a hostname: {name}")
            if name not in inline_vars:
                order.append(name)
                inline_vars[name] = {}
                membership[name] = []
            if group not in membership[name] and group != "ungrouped":
                membership[name].append(group)
            inline_vars[name].update(chosen)

    hosts: list[InventoryHost] = []
    for name in order:
        merged: dict[str, str] = dict(group_vars.get("all", {}))
        applied: list[str] = []
        for owned in membership[name]:
            for parent in _ancestors(owned, parents):
                if parent not in applied and parent != "all":
                    applied.append(parent)
        for owned in membership[name]:
            if owned not in applied:
                applied.append(owned)
            else:
                # A direct group beats the same group reached as a parent.
                applied.remove(owned)
                applied.append(owned)
        for owned in applied:
            merged.update(group_vars.get(owned, {}))
        merged.update(inline_vars[name])
        user = merged.get("user") or None
        if user is not None and not _USER.fullmatch(user):
            raise ValueError(f"{name} has a username that is not usable")
        address = merged.get("host", name)
        if not _NAME.fullmatch(address):
            raise ValueError(f"{name} has an address that is not usable")
        port_text = merged.get("port")
        port = _port(port_text, name) if port_text else None
        identity = merged.get("key") or None
        if identity is not None and (identity.startswith("-") or "{{" in identity):
            raise ValueError(f"{name} has a private-key path Keywarden cannot pass to ssh")
        hosts.append(InventoryHost(name, address, user, port, identity))
    return hosts
