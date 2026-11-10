"""Accepted risks: a finding that someone owns, with a reason and an end date.

A waiver turns a warn or fail into "accepted" only while it is in date. Every
waiver must say why, who owns it, and when it ends, so nothing is accepted forever.
"""

from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from keywarden.check import FINGERPRINT, Finding

MAX_WAIVER_BYTES = 1_000_000


@dataclass(frozen=True)
class Waiver:
    code: str
    reason: str
    expires: date
    owner: str = ""
    ticket: str = ""
    host: str = "*"
    fingerprint: str = ""
    index: int = 0

    @property
    def label(self) -> str:
        return self.ticket or self.owner or f"waiver {self.index + 1}"

    def public(self) -> dict:
        data = {"code": self.code, "reason": self.reason, "expires": self.expires.isoformat()}
        for name in ("owner", "ticket", "fingerprint"):
            value = getattr(self, name)
            if value:
                data[name] = value
        if self.host != "*":
            data["host"] = self.host
        return data


def _text(entry: dict, name: str, index: int, required: bool = False) -> str:
    value = entry.get(name, "")
    if not isinstance(value, str):
        raise ValueError(f"waiver {index + 1}: {name} must be text")
    value = value.strip()
    if required and not value:
        raise ValueError(f"waiver {index + 1}: {name} is required")
    return value


def _date(entry: dict, index: int) -> date:
    value = entry.get("expires")
    if isinstance(value, date):
        return value
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"waiver {index + 1}: expires is required (YYYY-MM-DD); nothing is accepted forever")
    try:
        return date.fromisoformat(value.strip())
    except ValueError as exc:
        raise ValueError(f"waiver {index + 1}: expires must be YYYY-MM-DD") from exc


def load_waivers(path: Path) -> list[Waiver]:
    if path.stat().st_size > MAX_WAIVER_BYTES:
        raise ValueError("waivers file is larger than 1 MB")
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".toml":
        try:
            import tomllib  # Python 3.11+
        except ImportError as exc:
            raise ValueError("a TOML waivers file needs Python 3.11 or newer; use the JSON form instead") from exc
        document = tomllib.loads(text)
    else:
        document = json.loads(text)
    entries = document.get("waiver", document.get("waivers")) if isinstance(document, dict) else document
    if not isinstance(entries, list):
        raise ValueError("waivers file must hold a list named waiver (TOML [[waiver]]) or waivers (JSON)")
    waivers: list[Waiver] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"waiver {index + 1}: must be a table of fields")
        owner = _text(entry, "owner", index)
        ticket = _text(entry, "ticket", index)
        if not owner and not ticket:
            raise ValueError(f"waiver {index + 1}: owner or ticket is required")
        fingerprint = _text(entry, "fingerprint", index)
        if fingerprint and not FINGERPRINT.fullmatch(fingerprint):
            raise ValueError(f"waiver {index + 1}: fingerprint must look like SHA256:...")
        waivers.append(
            Waiver(
                code=_text(entry, "code", index, required=True),
                reason=_text(entry, "reason", index, required=True),
                expires=_date(entry, index),
                owner=owner,
                ticket=ticket,
                host=_text(entry, "host", index) or "*",
                fingerprint=fingerprint,
                index=index,
            )
        )
    return waivers


def apply_waivers(findings: list[Finding], host: str, waivers: list[Waiver], today: date, used: set[int]) -> list[Finding]:
    if not waivers:
        return findings
    adjusted: list[Finding] = []
    for item in findings:
        if item.severity not in {"warn", "fail"}:
            adjusted.append(item)
            continue
        matching = [
            waiver
            for waiver in waivers
            if waiver.code == item.code and fnmatch.fnmatchcase(host, waiver.host)
            and (not waiver.fingerprint or waiver.fingerprint in item.fingerprints)
        ]
        if not matching:
            adjusted.append(item)
            continue
        active = [waiver for waiver in matching if waiver.expires >= today]
        expired = [waiver for waiver in matching if waiver.expires < today]
        for waiver in matching:
            used.add(waiver.index)
        prints = item.fingerprints
        covered: set[str] = set()
        whole = False
        for waiver in active:
            if waiver.fingerprint:
                covered.add(waiver.fingerprint)
            else:
                whole = True
        notes = [f"Waiver {waiver.label} expired {waiver.expires.isoformat()}." for waiver in expired]
        if active and (whole or (prints and covered >= set(prints))):
            accepted = Finding(
                item.code,
                "accepted",
                item.title,
                item.detail + " " + " ".join(
                    [f"Accepted under {waiver.label} until {waiver.expires.isoformat()}: {waiver.reason}" for waiver in active]
                ),
                item.drift,
                item.new_fingerprints,
            )
            accepted.waivers = [waiver.public() for waiver in active]
            accepted.was = item.severity
            adjusted.append(accepted)
            continue
        if covered:
            notes.append("Waived: " + ", ".join(sorted(covered)) + "; the rest are not.")
        changed = Finding(
            item.code,
            item.severity,
            item.title,
            item.detail + (" " + " ".join(notes) if notes else ""),
            item.drift,
            item.new_fingerprints,
        )
        changed.waivers = [waiver.public() for waiver in matching]
        adjusted.append(changed)
    return adjusted
