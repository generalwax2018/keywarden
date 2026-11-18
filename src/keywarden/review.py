"""Access review records: a reviewer's approve or revoke decision for every key.

A record is JSON with a SHA-256 over its canonical form, so any later edit shows.
`keywarden review sign` adds an SSH signature (ssh-keygen -Y sign) from the
reviewer's own key; `keywarden review verify` checks both.
"""

from __future__ import annotations

import hashlib
import html
import json
import shutil
import subprocess
from pathlib import Path

from keywarden import __version__
from keywarden.check import FINGERPRINT
from keywarden.collect import now_iso

NAMESPACE = "keywarden-review"
DECISIONS = {"approve", "revoke"}
MAX_DECISIONS = 50_000


def _canonical(record: dict) -> bytes:
    body = {key: value for key, value in record.items() if key != "sha256"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(record: dict) -> str:
    return hashlib.sha256(_canonical(record)).hexdigest()


def _text(value, limit: int) -> str:
    return str(value or "").replace("\r", " ").replace("\n", " ").strip()[:limit]


def build_record(report: dict, reviewer: dict, decisions: list[dict]) -> dict:
    """Validate the decisions against the report's keys and seal the record."""
    if not isinstance(report, dict):
        raise ValueError("review needs the report it covers")
    name = _text((reviewer or {}).get("name"), 120)
    if not name:
        raise ValueError("a review needs the reviewer's name")
    if not isinstance(decisions, list) or len(decisions) > MAX_DECISIONS:
        raise ValueError("decisions must be a list")
    hosts = report.get("hosts") or ([report["host"]] if report.get("host") else [])
    rows = {}
    for host in hosts:
        for row in host.get("keys", []):
            rows[(row.get("host"), row.get("account"), row.get("fingerprint"))] = row
    chosen: dict[tuple, dict] = {}
    for item in decisions:
        if not isinstance(item, dict):
            continue
        key = (item.get("host"), item.get("account"), item.get("fingerprint"))
        if key not in rows:
            raise ValueError(f"decision for a key that is not in the report: {key[0]} {key[1]} {key[2]}")
        decision = item.get("decision")
        if decision not in DECISIONS:
            raise ValueError(f"decision must be approve or revoke, not {decision!r}")
        row = rows[key]
        chosen[key] = {
            "host": key[0],
            "account": key[1],
            "fingerprint": key[2],
            "owner": row.get("owner"),
            "reach": row.get("reach"),
            "lastUsed": row.get("lastUsed"),
            "decision": decision,
            "note": _text(item.get("note"), 500),
        }
    pending = [key for key in rows if key not in chosen]
    report_hash = hashlib.sha256(json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    record = {
        "product": "keywarden-review",
        "version": __version__,
        "reviewer": {"name": name, "role": _text((reviewer or {}).get("role"), 120)},
        "reviewedAt": now_iso(),
        "report": {"generatedAt": report.get("generatedAt"), "version": report.get("version"), "sha256": report_hash, "hosts": len(hosts)},
        "summary": {
            "keys": len(rows),
            "approved": sum(1 for item in chosen.values() if item["decision"] == "approve"),
            "revoked": sum(1 for item in chosen.values() if item["decision"] == "revoke"),
            "undecided": len(pending),
        },
        "decisions": sorted(chosen.values(), key=lambda item: (item["host"] or "", item["account"] or "", item["fingerprint"] or "")),
        "undecided": [{"host": key[0], "account": key[1], "fingerprint": key[2]} for key in sorted(pending, key=lambda k: tuple(str(v) for v in k))],
    }
    record["sha256"] = digest(record)
    return record


def check_record(record: dict) -> None:
    if not isinstance(record, dict) or record.get("product") != "keywarden-review":
        raise ValueError("not a Keywarden review record")
    if record.get("sha256") != digest(record):
        raise ValueError("the review record was changed after it was sealed (SHA-256 does not match)")
    for item in record.get("decisions", []):
        if not FINGERPRINT.fullmatch(str(item.get("fingerprint", ""))):
            raise ValueError("review record has a decision without a valid fingerprint")


def render_html(record: dict) -> str:
    e = html.escape
    rows = []
    for item in record["decisions"]:
        colour = "#b42318" if item["decision"] == "revoke" else "#067647"
        rows.append(
            "<tr>"
            f"<td>{e(str(item['host']))}</td><td>{e(str(item['account']))}</td>"
            f"<td><code>{e(item['fingerprint'])}</code></td><td>{e(str(item.get('owner') or '—'))}</td>"
            f"<td>{e(str(item.get('reach') or ''))}</td><td>{e(str(item.get('lastUsed') or '—')[:10])}</td>"
            f"<td style=\"color:{colour};font-weight:600\">{e(item['decision'])}</td><td>{e(item.get('note') or '')}</td>"
            "</tr>"
        )
    summary = record["summary"]
    reviewer = record["reviewer"]
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Keywarden access review</title>
<style>
body{{font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:#1d1d1f;background:#fff;margin:32px;}}
h1{{font-size:22px;margin:0 0 4px}} .meta{{color:#6e6e73;margin:0 0 20px}}
table{{border-collapse:collapse;width:100%}} th,td{{text-align:left;padding:6px 8px;border-bottom:1px solid #e5e5ea;vertical-align:top}}
th{{font-size:12px;color:#6e6e73;text-transform:uppercase;letter-spacing:.04em}} code{{font-size:12px}}
.box{{display:inline-block;margin:0 16px 16px 0}} .box b{{display:block;font-size:20px}}
.seal{{margin-top:24px;color:#6e6e73;font-size:12px;word-break:break-all}}
</style></head><body>
<h1>SSH key access review</h1>
<p class="meta">Reviewed by <b>{e(reviewer['name'])}</b>{(' · ' + e(reviewer['role'])) if reviewer.get('role') else ''} on {e(record['reviewedAt'])}
 · report generated {e(str(record['report'].get('generatedAt')))} · {record['report']['hosts']} host(s)</p>
<div class="box"><b>{summary['keys']}</b>keys</div><div class="box"><b>{summary['approved']}</b>approved</div>
<div class="box"><b>{summary['revoked']}</b>revoked</div><div class="box"><b>{summary['undecided']}</b>undecided</div>
<table><thead><tr><th>Host</th><th>Account</th><th>Fingerprint</th><th>Owner</th><th>Reach</th><th>Last used</th><th>Decision</th><th>Note</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<p class="seal">Record SHA-256 {e(record['sha256'])} · report SHA-256 {e(record['report']['sha256'])}. Key material omitted; keys are identified by fingerprint.
Verify with <code>keywarden review verify</code>.</p>
</body></html>
"""


def _ssh_keygen() -> str:
    binary = shutil.which("ssh-keygen")
    if binary is None:
        raise ValueError("ssh-keygen is not installed; it signs and verifies review records")
    return binary


def sign(path: Path, key: Path) -> Path:
    """ssh-keygen -Y sign. Prompts for the key's passphrase in the terminal if it has one."""
    check_record(json.loads(path.read_text(encoding="utf-8")))
    if str(key).startswith("-") or str(path).startswith("-"):
        raise ValueError("paths must not start with -")
    completed = subprocess.run([_ssh_keygen(), "-Y", "sign", "-n", NAMESPACE, "-f", str(key), str(path)], check=False)
    signature = path.with_name(path.name + ".sig")
    if completed.returncode != 0 or not signature.exists():
        raise ValueError("ssh-keygen could not sign the record")
    return signature


def verify(path: Path, signers: Path | None, identity: str | None) -> str:
    record = json.loads(path.read_text(encoding="utf-8"))
    check_record(record)
    if signers is None:
        return f"sealed: SHA-256 matches; reviewed by {record['reviewer']['name']} (no signature checked)"
    signature = path.with_name(path.name + ".sig")
    if not signature.exists():
        raise ValueError(f"{signature.name} is missing")
    principal = identity or record["reviewer"]["name"]
    with path.open("rb") as handle:
        completed = subprocess.run(
            [_ssh_keygen(), "-Y", "verify", "-f", str(signers), "-I", principal, "-n", NAMESPACE, "-s", str(signature)],
            stdin=handle,
            capture_output=True,
            text=True,
            check=False,
        )
    if completed.returncode != 0:
        raise ValueError("signature does not verify: " + (completed.stderr or completed.stdout).strip()[:200])
    return f"verified: signed by {principal}, SHA-256 matches"
