"""Who each key belongs to, and who has left.

Owner sources, all read into fingerprints at once so no key body is kept:

* CSV with an ``owner`` column and a ``fingerprint`` or ``key`` column (plus optional
  ``email``, ``github``, ``status``)
* JSON: ``{"owners": [{"name", "email", "github", "status", "fingerprints", "keys"}]}``
* LDIF, as ``ldapsearch ... uid mail sshPublicKey`` prints it
* a directory of ``.pub`` files, one per person, named after them (``keys/alice.pub``)
* GitHub: a ``github`` username fetches https://github.com/<user>.keys

A leavers list is one person per line: a name, an email, or a GitHub username.
"""

from __future__ import annotations

import base64
import csv
import io
import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from keywarden.check import FINGERPRINT
from keywarden.parse import PrivateKeyError, contains_private_key, parse_public_keys

MAX_OWNER_BYTES = 5_000_000
GITHUB_USER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
GITHUB_KEYS_URL = "https://github.com/{}.keys"
LEFT = {"left", "leaver", "terminated", "departed", "inactive", "disabled", "offboarded"}


@dataclass
class Owner:
    name: str
    email: str = ""
    github: str = ""
    left: bool = False
    fingerprints: set[str] = field(default_factory=set)

    def handles(self) -> set[str]:
        return {value.strip().lower() for value in (self.name, self.email, self.github) if value and value.strip()}


@dataclass
class OwnerBook:
    owners: list[Owner] = field(default_factory=list)
    leavers: set[str] = field(default_factory=set)  # lower-cased names, emails, GitHub users
    notes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._index: dict[str, Owner] | None = None

    def _by_fingerprint(self) -> dict[str, Owner]:
        if self._index is None:
            index: dict[str, Owner] = {}
            for owner in self.owners:
                for fingerprint in owner.fingerprints:
                    index.setdefault(fingerprint, owner)
            self._index = index
        return self._index

    def owner_of(self, fingerprint: str) -> Owner | None:
        return self._by_fingerprint().get(fingerprint)

    def has_left(self, owner: Owner) -> bool:
        return owner.left or bool(owner.handles() & self.leavers)

    def unmatched_leavers(self) -> list[str]:
        known: set[str] = set()
        for owner in self.owners:
            if owner.fingerprints:
                known |= owner.handles()
        return sorted(handle for handle in self.leavers if handle not in known)

    @property
    def active(self) -> bool:
        return bool(self.owners)


def _read(path: Path) -> str:
    if path.stat().st_size > MAX_OWNER_BYTES:
        raise ValueError(f"{path.name} is larger than 5 MB")
    text = path.read_text(encoding="utf-8", errors="replace")
    if contains_private_key(text):
        raise PrivateKeyError("private key material was present and was not recorded")
    return text


def _prints_from_keys(text: str) -> set[str]:
    keys, _issues = parse_public_keys(text)
    return {key.fingerprint for key in keys}


def _fingerprints(value) -> set[str]:
    found: set[str] = set()
    values = value if isinstance(value, list) else [value]
    for item in values:
        text = str(item or "")
        if FINGERPRINT.fullmatch(text.strip()):
            found.add(text.strip())
        else:
            found |= _prints_from_keys(text)
    return found


def _status_left(value) -> bool:
    return str(value or "").strip().lower() in LEFT


def _merge(book: dict[str, Owner], owner: Owner) -> None:
    key = (owner.email or owner.name or owner.github).strip().lower()
    if not key:
        return
    existing = book.get(key)
    if existing is None:
        book[key] = owner
        return
    existing.fingerprints |= owner.fingerprints
    existing.left = existing.left or owner.left
    existing.email = existing.email or owner.email
    existing.github = existing.github or owner.github


def _from_csv(text: str) -> list[Owner]:
    reader = csv.DictReader(io.StringIO(text))
    fields = {name.strip().lower(): name for name in (reader.fieldnames or [])}
    if "owner" not in fields and "name" not in fields:
        raise ValueError("owners CSV needs an 'owner' (or 'name') column")
    name_field = fields.get("owner") or fields.get("name")
    owners = []
    for row in reader:
        get = lambda column: (row.get(fields[column]) or "").strip() if column in fields else ""  # noqa: E731
        prints = _fingerprints(get("fingerprint")) | _fingerprints(get("key"))
        owners.append(
            Owner(
                name=(row.get(name_field) or "").strip(),
                email=get("email"),
                github=get("github"),
                left=_status_left(get("status")),
                fingerprints=prints,
            )
        )
    return owners


def _from_json(text: str) -> list[Owner]:
    document = json.loads(text)
    items = document.get("owners") if isinstance(document, dict) else document
    if not isinstance(items, list):
        raise ValueError('owners JSON must be a list, or {"owners": [...]}')
    owners = []
    for item in items:
        if not isinstance(item, dict):
            continue
        prints = _fingerprints(item.get("fingerprints") or []) | _fingerprints(item.get("keys") or [])
        owners.append(
            Owner(
                name=str(item.get("name") or item.get("owner") or "").strip(),
                email=str(item.get("email") or "").strip(),
                github=str(item.get("github") or "").strip(),
                left=_status_left(item.get("status")) or item.get("left") is True,
                fingerprints=prints,
            )
        )
    return owners


def _ldif_records(text: str) -> list[list[tuple[str, str]]]:
    # Unfold continuation lines (a line starting with one space continues the previous).
    lines: list[str] = []
    for raw in text.splitlines():
        if raw.startswith(" ") and lines:
            lines[-1] += raw[1:]
        else:
            lines.append(raw)
    records: list[list[tuple[str, str]]] = []
    current: list[tuple[str, str]] = []
    for line in lines:
        if not line.strip():
            if current:
                records.append(current)
                current = []
            continue
        if line.startswith("#") or ":" not in line:
            continue
        name, _, value = line.partition(":")
        if value.startswith(":"):
            try:
                value = base64.b64decode(value[1:].strip()).decode("utf-8", errors="replace")
            except (ValueError, TypeError):
                continue
        current.append((name.strip().lower(), value.strip()))
    if current:
        records.append(current)
    return records


def _from_ldif(text: str) -> list[Owner]:
    owners = []
    for record in _ldif_records(text):
        values: dict[str, list[str]] = {}
        for name, value in record:
            values.setdefault(name, []).append(value)
        prints: set[str] = set()
        for key in values.get("sshpublickey", []):
            prints |= _prints_from_keys(key)
        name = (values.get("uid") or values.get("cn") or [""])[0]
        disabled = any(_status_left(value) for value in values.get("employeestatus", []))
        owners.append(Owner(name=name, email=(values.get("mail") or [""])[0], left=disabled, fingerprints=prints))
    return owners


def _from_directory(path: Path) -> list[Owner]:
    owners = []
    for item in sorted(path.glob("*.pub")):
        owners.append(Owner(name=item.stem, fingerprints=_prints_from_keys(_read(item))))
    if not owners:
        raise ValueError(f"{path} has no .pub files")
    return owners


def fetch_github_keys(user: str, opener=urllib.request.urlopen) -> set[str]:
    if not GITHUB_USER.fullmatch(user):
        raise ValueError(f"not a GitHub username: {user}")
    request = urllib.request.Request(GITHUB_KEYS_URL.format(user), headers={"User-Agent": "keywarden"})
    try:
        with opener(request, timeout=10) as response:
            body = response.read(MAX_OWNER_BYTES + 1)
    except (urllib.error.URLError, OSError) as exc:
        raise ValueError(f"could not fetch GitHub keys for {user}: {exc}") from exc
    if len(body) > MAX_OWNER_BYTES:
        raise ValueError(f"GitHub keys for {user} are larger than 5 MB")
    text = body.decode("utf-8", errors="replace")
    try:
        return _prints_from_keys(text)
    finally:
        del text


def load_owners(path: Path, *, fetch_github: bool = True, opener=urllib.request.urlopen) -> list[Owner]:
    if path.is_dir():
        owners = _from_directory(path)
    else:
        text = _read(path)
        try:
            suffix = path.suffix.lower()
            stripped = text.lstrip()
            if suffix == ".json" or stripped.startswith(("{", "[")):
                owners = _from_json(text)
            elif suffix == ".ldif" or stripped.startswith(("dn:", "version:")):
                owners = _from_ldif(text)
            else:
                owners = _from_csv(text)
        finally:
            del text
    merged: dict[str, Owner] = {}
    for owner in owners:
        if fetch_github and owner.github:
            owner.fingerprints |= fetch_github_keys(owner.github, opener)
        _merge(merged, owner)
    return list(merged.values())


def parse_leavers(text: str) -> set[str]:
    found: set[str] = set()
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if not row:
            continue
        first = row[0].split("#", 1)[0].strip()
        if not first or first.lower() in {"name", "owner", "email", "user", "username"}:
            continue
        for cell in row:
            cell = cell.split("#", 1)[0].strip()
            if cell:
                found.add(cell.lower())
    return found


def load_book(owners: Path | None, leavers: Path | None, *, fetch_github: bool = True) -> OwnerBook | None:
    if owners is None and leavers is None:
        return None
    book = OwnerBook()
    if owners is not None:
        book.owners = load_owners(owners, fetch_github=fetch_github)
    if leavers is not None:
        book.leavers = parse_leavers(_read(leavers))
        if owners is None:
            raise ValueError("--leavers needs --owners, so Keywarden knows which keys belong to whom")
    return book


def book_from_texts(owners_text: str, leavers_text: str = "", name_hint: str = "owners.csv") -> OwnerBook | None:
    """The GUI sends owner and leaver lists as text. GitHub lookups stay a CLI feature."""
    if not owners_text.strip():
        return None
    if contains_private_key(owners_text) or contains_private_key(leavers_text):
        raise PrivateKeyError("private key material was present and was not recorded")
    stripped = owners_text.lstrip()
    if stripped.startswith(("{", "[")):
        owners = _from_json(owners_text)
    elif stripped.startswith(("dn:", "version:")) or name_hint.lower().endswith(".ldif"):
        owners = _from_ldif(owners_text)
    else:
        owners = _from_csv(owners_text)
    merged: dict[str, Owner] = {}
    for owner in owners:
        _merge(merged, owner)
    return OwnerBook(owners=list(merged.values()), leavers=parse_leavers(leavers_text))


def owner_summary(rows: list[dict]) -> list[dict]:
    """Per person: hosts, accounts, and the highest reach their keys give."""
    rank = {"root": 5, "root-nopasswd": 4, "root-password": 3, "limited": 2, "none": 1, "unknown": 0}
    people: dict[str, dict] = {}
    for row in rows:
        owner = row.get("owner")
        if not owner:
            continue
        entry = people.setdefault(owner, {"owner": owner, "left": False, "hosts": set(), "accounts": set(), "rootHosts": set(), "keys": set(), "reach": "unknown"})
        entry["left"] = entry["left"] or bool(row.get("ownerLeft"))
        entry["hosts"].add(row["host"])
        entry["accounts"].add(f"{row['account']}@{row['host']}")
        entry["keys"].add(row["fingerprint"])
        if row.get("reach") in {"root", "root-nopasswd"}:
            entry["rootHosts"].add(row["host"])
        if rank.get(row.get("reach"), 0) > rank.get(entry["reach"], 0):
            entry["reach"] = row["reach"]
    summary = []
    for entry in people.values():
        summary.append(
            {
                "owner": entry["owner"],
                "left": entry["left"],
                "hosts": len(entry["hosts"]),
                "rootHosts": len(entry["rootHosts"]),
                "accounts": sorted(entry["accounts"]),
                "keys": sorted(entry["keys"]),
                "highestReach": entry["reach"],
            }
        )
    summary.sort(key=lambda item: (not item["left"], -item["rootHosts"], -item["hosts"], item["owner"].lower()))
    return summary
