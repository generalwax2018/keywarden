"""Ansible INI inventory, enough to know where to SSH. Passwords in the file are ignored."""

from __future__ import annotations

import re
from dataclasses import dataclass

_RANGE = re.compile(r"\[(\d+):(\d+)\]")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,253}$")
_USER = re.compile(r"^[a-z_][-a-z0-9_.]*\$?$", re.IGNORECASE)

_KEEP = ("ansible_host", "ansible_user", "ansible_port", "ansible_ssh_port")


@dataclass(frozen=True)
class InventoryHost:
    name: str
    address: str
    user: str | None
    port: int | None

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


def parse_inventory(text: str) -> list[InventoryHost]:
    group = "ungrouped"
    kind = "hosts"
    group_vars: dict[str, dict[str, str]] = {"all": {}}
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
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            if key in _KEEP:
                group_vars.setdefault(group, {})[key] = value.strip()
            continue
        parts = line.split()
        names = _expand(parts[0])
        chosen: dict[str, str] = {}
        for part in parts[1:]:
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            if key in _KEEP:
                chosen[key] = value
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
        for owned in membership[name]:
            merged.update(group_vars.get(owned, {}))
        merged.update(inline_vars[name])
        user = merged.get("ansible_user") or None
        if user is not None and not _USER.fullmatch(user):
            raise ValueError(f"{name} has a username that is not usable")
        address = merged.get("ansible_host", name)
        if not _NAME.fullmatch(address):
            raise ValueError(f"{name} has an address that is not usable")
        port_text = merged.get("ansible_port") or merged.get("ansible_ssh_port")
        port = _port(port_text, name) if port_text else None
        hosts.append(InventoryHost(name, address, user, port))
    return hosts
