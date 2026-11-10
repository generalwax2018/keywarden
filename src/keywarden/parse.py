"""Turn public-key text into fingerprints. The key blob is not kept."""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass

KEY_TYPES = (
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-ed25519",
    "ssh-rsa",
    "ssh-dss",
)


class PrivateKeyError(Exception):
    """The input contained a private key. Nothing from it was retained."""


@dataclass(frozen=True)
class KeyRef:
    fingerprint: str
    type: str
    kind: str
    bits: int | None
    comment: str
    user: str | None = None

    def public(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "type": self.type,
            "bits": self.bits,
            "comment": self.comment,
        }


@dataclass(frozen=True)
class ParseIssue:
    line: int
    text: str


def fingerprint_bytes(raw: bytes) -> str:
    digest = hashlib.sha256(raw).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _b64_to_bytes(blob: str) -> bytes | None:
    padded = blob + "=" * ((4 - len(blob) % 4) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except Exception:
        return None


def _read_string(buf: bytes, offset: int) -> tuple[bytes, int] | None:
    if offset + 4 > len(buf):
        return None
    length = int.from_bytes(buf[offset : offset + 4], "big")
    start = offset + 4
    if start + length > len(buf):
        return None
    return buf[start : start + length], start + length


def _mpint_bits(number: bytes) -> int:
    index = 0
    while index < len(number) - 1 and number[index] == 0:
        index += 1
    top = 0
    for bit in range(7, -1, -1):
        if (number[index] >> bit) & 1:
            top = bit + 1
            break
    return (len(number) - index - 1) * 8 + top


def rsa_bits(raw: bytes) -> int | None:
    type_part = _read_string(raw, 0)
    if not type_part:
        return None
    exponent = _read_string(raw, type_part[1])
    if not exponent:
        return None
    modulus = _read_string(raw, exponent[1])
    if not modulus:
        return None
    return _mpint_bits(modulus[0])


def kind_of(key_type: str) -> str:
    if key_type == "ssh-ed25519":
        return "ed25519"
    if key_type == "ssh-rsa":
        return "rsa"
    if key_type == "ssh-dss":
        return "dsa"
    if key_type.startswith("ecdsa-"):
        return "ecdsa"
    if key_type.startswith("sk-"):
        return "security-key"
    return "unknown"


def _split_line(line: str) -> tuple[str, str, str] | None:
    for key_type in KEY_TYPES:
        token = f"{key_type} "
        start = 0
        while start < len(line):
            index = line.find(token, start)
            if index == -1:
                break
            if index == 0 or line[index - 1].isspace():
                rest = line[index + len(token) :].strip()
                space = re.search(r"\s", rest)
                blob = rest if space is None else rest[: space.start()]
                comment = "" if space is None else rest[space.end() :].strip()
                if re.fullmatch(r"[A-Za-z0-9+/]+=*", blob) and len(blob) >= 16:
                    return key_type, blob, comment
            start = index + 1
    return None


def parse_public_keys(text: str, user: str | None = None) -> tuple[list[KeyRef], list[ParseIssue]]:
    if "PRIVATE KEY" in text or "-----BEGIN" in text:
        raise PrivateKeyError("private key material was present and was not recorded")
    keys: list[KeyRef] = []
    issues: list[ParseIssue] = []
    seen: set[str] = set()
    for index, raw_line in enumerate(text.splitlines()):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = _split_line(line)
        if not parts:
            issues.append(ParseIssue(index + 1, "Not a recognized public key"))
            continue
        raw = _b64_to_bytes(parts[1])
        if raw is None:
            issues.append(ParseIssue(index + 1, "Key blob is not valid base64"))
            continue
        fingerprint = fingerprint_bytes(raw)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        if parts[0] == "ssh-rsa":
            bits: int | None = rsa_bits(raw)
        elif parts[0] == "ssh-dss":
            bits = 1024
        else:
            bits = None
        keys.append(KeyRef(fingerprint, parts[0], kind_of(parts[0]), bits, parts[2], user))
    return keys, issues
