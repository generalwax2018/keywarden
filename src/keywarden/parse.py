"""Turn public-key text into fingerprints. The key blob is not kept."""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass

KEY_TYPES = (
    "sk-ssh-ed25519-cert-v01@openssh.com",
    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "ssh-ed25519-cert-v01@openssh.com",
    "ssh-rsa-cert-v01@openssh.com",
    "ssh-dss-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-ed25519",
    "ssh-rsa",
    "ssh-dss",
)


class PrivateKeyError(Exception):
    """The input contained a private key. Nothing from it was retained."""


def contains_private_key(text: str) -> bool:
    return "PRIVATE KEY" in text or "-----BEGIN" in text or "PuTTY-User-Key-File" in text


@dataclass(frozen=True)
class CertInfo:
    cert_type: str
    valid_after: int
    valid_before: int | None
    key_id: str
    ca_fingerprint: str
    unreadable: bool = False

    def public(self) -> dict:
        return {
            "certType": self.cert_type,
            "validAfter": self.valid_after,
            "validBefore": self.valid_before,
            "keyId": self.key_id,
            "caFingerprint": self.ca_fingerprint,
        }


@dataclass(frozen=True)
class KeyRef:
    fingerprint: str
    type: str
    kind: str
    bits: int | None
    comment: str
    user: str | None = None
    cert_authority: bool = False
    cert: CertInfo | None = None

    def public(self) -> dict:
        data = {
            "fingerprint": self.fingerprint,
            "type": self.type,
            "bits": self.bits,
            "comment": self.comment,
            "certAuthority": self.cert_authority,
        }
        if self.cert and not self.cert.unreadable:
            data["cert"] = self.cert.public()
        return data


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
    base = key_type.replace("-cert-v01@openssh.com", "")
    if base == "ssh-ed25519":
        return "ed25519"
    if base == "ssh-rsa":
        return "rsa"
    if base == "ssh-dss":
        return "dsa"
    if base.startswith("ecdsa-"):
        return "ecdsa"
    if base.startswith("sk-"):
        return "security-key"
    return "unknown"


def _read_u32(buf: bytes, offset: int) -> tuple[int, int] | None:
    if offset + 4 > len(buf):
        return None
    return int.from_bytes(buf[offset : offset + 4], "big"), offset + 4


def _read_u64(buf: bytes, offset: int) -> tuple[int | None, int] | None:
    hi = _read_u32(buf, offset)
    lo = _read_u32(buf, offset + 4)
    if not hi or not lo:
        return None
    if hi[0] == 0xFFFFFFFF:
        return None, offset + 8
    return hi[0] * 4294967296 + lo[0], offset + 8


def _cert_lead(key_type: str) -> int | None:
    if key_type == "ssh-ed25519-cert-v01@openssh.com":
        return 3
    if key_type == "ssh-rsa-cert-v01@openssh.com":
        return 4
    if key_type == "ssh-dss-cert-v01@openssh.com":
        return 6
    if key_type.startswith("ecdsa-") and "-cert-" in key_type:
        return 4
    if key_type == "sk-ssh-ed25519-cert-v01@openssh.com":
        return 4
    if key_type.startswith("sk-ecdsa-") and "-cert-" in key_type:
        return 5
    return None


def read_certificate(key_type: str, raw: bytes) -> CertInfo | None:
    lead = _cert_lead(key_type)
    if lead is None:
        return None
    offset = 0
    for _ in range(lead):
        part = _read_string(raw, offset)
        if not part:
            return None
        offset = part[1]
    serial = _read_u64(raw, offset)
    if not serial:
        return None
    offset = serial[1]
    cert_type = _read_u32(raw, offset)
    if not cert_type:
        return None
    offset = cert_type[1]
    key_id = _read_string(raw, offset)
    if not key_id:
        return None
    offset = key_id[1]
    principals = _read_string(raw, offset)
    if not principals:
        return None
    offset = principals[1]
    valid_after = _read_u64(raw, offset)
    if not valid_after or valid_after[0] is None:
        return None
    offset = valid_after[1]
    valid_before = _read_u64(raw, offset)
    if not valid_before:
        return None
    offset = valid_before[1]
    for _ in range(3):
        skipped = _read_string(raw, offset)
        if not skipped:
            return None
        offset = skipped[1]
    ca = _read_string(raw, offset)
    if not ca:
        return None
    label = {1: "user", 2: "host"}.get(cert_type[0], "unknown")
    ident = key_id[0].decode("utf-8", errors="replace").replace("\x00", "").strip()[:80]
    return CertInfo(label, valid_after[0], valid_before[0], ident, fingerprint_bytes(ca[0]), False)


def _cert_authority(options: str) -> bool:
    return any(part.strip() == "cert-authority" for part in options.split(","))


def _split_line(line: str) -> tuple[str, str, str, str] | None:
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
                    return key_type, blob, comment, line[:index].strip()
            start = index + 1
    return None


def parse_public_keys(text: str, user: str | None = None) -> tuple[list[KeyRef], list[ParseIssue]]:
    if contains_private_key(text):
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
        is_cert = "-cert-" in parts[0]
        cert = read_certificate(parts[0], raw) if is_cert else None
        if parts[0] == "ssh-rsa":
            bits: int | None = rsa_bits(raw)
        elif parts[0] == "ssh-dss" or parts[0].startswith("ssh-dss-cert-"):
            bits = 1024
        elif parts[0].startswith("ssh-rsa-cert-"):
            lead = _read_string(raw, 0)
            nonce = _read_string(raw, lead[1]) if lead else None
            exponent = _read_string(raw, nonce[1]) if nonce else None
            modulus = _read_string(raw, exponent[1]) if exponent else None
            bits = _mpint_bits(modulus[0]) if modulus else None
        else:
            bits = None
        if is_cert and cert is None:
            cert = CertInfo("unknown", 0, 0, "", "", True)
        keys.append(KeyRef(fingerprint, parts[0], kind_of(parts[0]), bits, parts[2], user, _cert_authority(parts[3]), cert))
    return keys, issues
