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
    "ansible_ssh_common_args": "sshargs",
    "ansible_ssh_extra_args": "sshargs2",
}
_HOP = re.compile(r"^(?:[A-Za-z0-9_][A-Za-z0-9_.-]*@)?[A-Za-z0-9][A-Za-z0-9._-]{0,253}(?::\d{1,5})?$")


def jump_from_args(text: str | None) -> str | None:
    """ProxyJump from ansible_ssh_common_args: -J, -o ProxyJump=, or ProxyCommand 'ssh -W %h:%p bastion'."""
    if not text:
        return None
    import shlex

    try:
        tokens = shlex.split(text)
    except ValueError:
        return None
    found: str | None = None
    index = 0
    while index < len(tokens):
        token = tokens[index]
        option = None
        if token == "-J" and index + 1 < len(tokens):
            found = tokens[index + 1]
            index += 2
            continue
        if token.startswith("-J") and len(token) > 2:
            found = token[2:]
        elif token == "-o" and index + 1 < len(tokens):
            option = tokens[index + 1]
            index += 1
        elif token.startswith("-o") and len(token) > 2:
            option = token[2:]
        if option:
            name, _, value = option.replace("=", " ", 1).partition(" ")
            if name.lower() == "proxyjump":
                found = value.strip()
            elif name.lower() == "proxycommand":
                parts = value.split()
                if parts and parts[0].rsplit("/", 1)[-1] == "ssh" and "-W" in parts:
                    hosts = [part for part in parts[1:] if not part.startswith("-") and "%" not in part]
                    if hosts:
                        found = hosts[-1]
        index += 1
    if found and found.lower() != "none" and all(_HOP.fullmatch(hop) for hop in found.split(",")):
        return found
    return None


@dataclass(frozen=True)
class InventoryHost:
    name: str
    address: str
    user: str | None
    port: int | None
    identity_file: str | None = None
    jump: str | None = None

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
        inner = value[1:-1]
        return inner.replace('\\"', '"') if value[0] == '"' else inner
    return value


def _split_host_line(line: str) -> list[str]:
    """Split on spaces outside quotes, so key="a b" stays one token. Quotes are kept for _unquote."""
    tokens: list[str] = []
    current: list[str] = []
    quote = ""
    index = 0
    while index < len(line):
        char = line[index]
        if quote:
            if char == "\\" and index + 1 < len(line):
                current.append(line[index : index + 2])
                index += 2
                continue
            if char == quote:
                quote = ""
            current.append(char)
        elif char in "'\"":
            quote = char
            current.append(char)
        elif char.isspace():
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(char)
        index += 1
    if current:
        tokens.append("".join(current))
    return tokens


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
            "this looks like a YAML inventory. Install Ansible so Keywarden can read it with ansible-inventory, "
            "or run 'ansible-inventory -i <file> --list > inventory.json' and pass --inventory inventory.json"
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
        parts = _split_host_line(line)
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
        jump = jump_from_args(merged.get("sshargs")) or jump_from_args(merged.get("sshargs2"))
        hosts.append(InventoryHost(name, address, user, port, identity, jump))
    return hosts


def looks_like_yaml(text: str, source: str | None = None) -> bool:
    return _looks_like_yaml(text, source)


def _host_from_vars(name: str, values: dict) -> InventoryHost:
    chosen: dict[str, str] = {}
    for key, value in (values or {}).items():
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            _keep(str(key), str(value), chosen)
    if not _NAME.fullmatch(name):
        raise ValueError(f"not a hostname: {name}")
    user = chosen.get("user") or None
    if user is not None and not _USER.fullmatch(user):
        raise ValueError(f"{name} has a username that is not usable")
    address = chosen.get("host", name)
    if not _NAME.fullmatch(address):
        raise ValueError(f"{name} has an address that is not usable")
    port = _port(chosen["port"], name) if chosen.get("port") else None
    identity = chosen.get("key") or None
    if identity is not None and (identity.startswith("-") or "{{" in identity):
        raise ValueError(f"{name} has a private-key path Keywarden cannot pass to ssh")
    jump = jump_from_args(chosen.get("sshargs")) or jump_from_args(chosen.get("sshargs2"))
    return InventoryHost(name, address, user, port, identity, jump)


def parse_inventory_json(text: str) -> list[InventoryHost]:
    """The output of `ansible-inventory --list`: groups with hosts and children, and _meta.hostvars.

    Ansible has already merged group and host vars into hostvars, so only the
    connection fields are read from there. Everything else is dropped.
    """
    import json

    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"inventory JSON could not be read: {exc.msg} at line {exc.lineno}") from exc
    if not isinstance(document, dict):
        raise ValueError("inventory JSON must be an object, as ansible-inventory --list prints")
    hostvars = (document.get("_meta") or {}).get("hostvars") or {}
    order: list[str] = []
    seen_groups: set[str] = set()

    def walk(group: str, depth: int = 0) -> None:
        if group in seen_groups or depth > 64:
            return
        seen_groups.add(group)
        body = document.get(group) or {}
        if not isinstance(body, dict):
            return
        for host in body.get("hosts") or []:
            if isinstance(host, str) and host not in order:
                order.append(host)
        for child in body.get("children") or []:
            if isinstance(child, str):
                walk(child, depth + 1)

    walk("all")
    for group in document:
        if group != "_meta":
            walk(group)
    for host in hostvars:
        if host not in order:
            order.append(host)
    return [_host_from_vars(host, hostvars.get(host) or {}) for host in order]
