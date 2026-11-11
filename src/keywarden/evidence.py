"""An evidence report: one self-contained HTML file to hand an assessor.

It records scope, who ran the check and with what visibility, each finding
with the framework controls it bears on, the access review table, accepted
risks, and a SHA-256 of the JSON report it was built from. No key bodies.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import socket
from html import escape

from keywarden.controls import FRAMEWORKS, MAPPING, NAMES

_RANK = {"fail": 3, "warn": 2, "accepted": 1, "pass": 0}
_STATUS = {3: ("fail", "Checks failed"), 2: ("warn", "Checks to review"), 1: ("accepted", "Accepted risk"), 0: ("pass", "Checks passed")}


def _hosts(document: dict) -> list[dict]:
    return document.get("hosts") or ([document["host"]] if document.get("host") else [])


def _operator() -> str:
    try:
        return f"{getpass.getuser()}@{socket.gethostname()}"
    except Exception:
        return "unknown"


def control_matrix(document: dict) -> dict[str, list[dict]]:
    """framework -> rows of {id, name, status, codes, hosts}."""
    seen: dict[str, dict] = {}
    for host in _hosts(document):
        for item in host.get("findings", []):
            for key in MAPPING.get(item.get("code", ""), []):
                entry = seen.setdefault(key, {"rank": -1, "codes": set(), "hosts": set()})
                rank = _RANK.get(item.get("severity"), 0)
                entry["codes"].add(item["code"])
                if rank > 0:
                    entry["hosts"].add(host.get("name", "?"))
                entry["rank"] = max(entry["rank"], rank)
    matrix: dict[str, list[dict]] = {}
    for framework in FRAMEWORKS:
        rows = []
        for key in sorted({k for codes in MAPPING.values() for k in codes if k.startswith(framework + ":")}, key=_sort_key):
            entry = seen.get(key)
            if entry is None:
                status, label = "none", "Not assessed in this run"
                codes, hosts = [], []
            else:
                status, label = _STATUS[entry["rank"]]
                codes, hosts = sorted(entry["codes"]), sorted(entry["hosts"])
            rows.append({"id": key.split(":", 1)[1], "name": NAMES[key], "status": status, "label": label, "codes": codes, "hosts": hosts})
        matrix[framework] = rows
    return matrix


def _sort_key(key: str):
    control = key.split(":", 1)[1]
    parts = []
    for token in control.replace("(", ".").replace(")", "").replace("-", ".").replace(" ", ".").split("."):
        parts.append((0, int(token), "") if token.isdigit() else (1, 0, token))
    return parts


def render_evidence(document: dict) -> str:
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    hosts = _hosts(document)
    keys = [row for host in hosts for row in host.get("keys", [])]
    counts = {name: sum(1 for host in hosts if host.get("posture") == name) for name in ("fail", "warn", "pass")}
    failed_checks = sum(1 for host in hosts for item in host.get("findings", []) if item.get("severity") == "fail")
    waivers = [(host.get("name"), item) for host in hosts for item in host.get("findings", []) if item.get("severity") == "accepted"]
    matrix = control_matrix(document)
    out: list[str] = []
    add = out.append
    add("<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>")
    add("<title>Keywarden evidence report</title><style>")
    add(_CSS)
    add("</style></head><body><main>")
    add("<header><p class='eyebrow'>Keywarden evidence report</p><h1>SSH access and configuration</h1>")
    add(f"<p class='lede'>{len(hosts)} host{'s' if len(hosts) != 1 else ''} checked. Generated {escape(document.get('generatedAt', ''))} by Keywarden {escape(str(document.get('version', '')))}.</p></header>")
    add("<section><h2>Run</h2><dl class='facts'>")
    for label, value in (
        ("Run by", _operator()),
        ("Generated", document.get("generatedAt", "")),
        ("Keywarden version", document.get("version", "")),
        ("Keys compared against", f"{len(document.get('push', []))} pushed public key fingerprint(s)"),
        ("Key material", "Omitted. Fingerprints identify keys; no key bodies are in this report."),
        ("Report SHA-256", digest),
    ):
        add(f"<dt>{escape(label)}</dt><dd>{escape(str(value))}</dd>")
    add("</dl><p class='note'>The SHA-256 is computed over the JSON report embedded at the end of this file (keys sorted, no whitespace). Recompute it to show the findings were not edited.</p></section>")

    add("<section><h2>Summary</h2><div class='tiles'>")
    for label, value, cls in (
        ("Hosts", len(hosts), ""),
        ("Failing hosts", counts["fail"], "fail"),
        ("Hosts to review", counts["warn"], "warn"),
        ("Failed checks", failed_checks, "fail"),
        ("Keys reaching root", sum(1 for row in keys if row.get("reach") in ("root", "root-nopasswd")), "warn"),
        ("Stale keys", sum(1 for row in keys if row.get("usage") == "stale"), "warn"),
    ):
        add(f"<div class='tile {cls}'><span>{escape(label)}</span><b>{value}</b></div>")
    add("</div></section>")

    add("<section><h2>Scope</h2><table><thead><tr><th>Host</th><th>Address</th><th>Result</th><th>Read as</th><th>sshd -T</th><th>Login log</th><th>Observed</th></tr></thead><tbody>")
    for host in hosts:
        posture = host.get("posture", "")
        add(
            f"<tr><td>{escape(host.get('name', ''))}</td><td class='mono'>{escape(str(host.get('address', '')))}</td>"
            f"<td><span class='pill {escape(posture)}'>{escape(posture)}</span></td><td>{escape(str(host.get('privilege', '–')))}</td>"
            f"<td>{escape(str(host.get('sshdRead', '–')))}</td><td>{escape(str(host.get('authLog', '–')))}</td><td class='mono'>{escape(str(host.get('observedAt', '')))}</td></tr>"
        )
    add("</tbody></table><p class='note'>Read as: root, sudo, or none. Checks that could not see something are reported as warnings, never as passes.</p></section>")

    add("<section><h2>Control coverage</h2><p class='note'>Each control lists the Keywarden checks that bear on it for the hosts above. A passing check is evidence toward a control, not proof that the control is met; controls also cover process and people that a host scan cannot see. Requirement names are paraphrased.</p>")
    for framework, title in FRAMEWORKS.items():
        add(f"<h3>{escape(title)}</h3><table><thead><tr><th>Control</th><th>Requirement</th><th>Status</th><th>Checks</th><th>Hosts with issues</th></tr></thead><tbody>")
        for row in matrix[framework]:
            add(
                f"<tr><td class='mono'>{escape(row['id'])}</td><td>{escape(row['name'])}</td><td><span class='pill {row['status']}'>{escape(row['label'])}</span></td>"
                f"<td class='mono'>{escape(', '.join(row['codes']) or '–')}</td><td>{escape(', '.join(row['hosts']) or '–')}</td></tr>"
            )
        add("</tbody></table>")
    add("</section>")

    add("<section><h2>Findings</h2>")
    order = {"fail": 0, "warn": 1, "accepted": 2, "pass": 3}
    for host in hosts:
        items = sorted(host.get("findings", []), key=lambda item: order.get(item.get("severity"), 4))
        add(f"<h3>{escape(host.get('name', ''))} <span class='pill {escape(host.get('posture', ''))}'>{escape(host.get('posture', ''))}</span></h3>")
        add("<table class='findings'><thead><tr><th>Result</th><th>Check</th><th>Detail</th><th>Controls</th></tr></thead><tbody>")
        for item in items:
            controls = ", ".join(f"{FRAMEWORKS[c['framework']].split()[0]} {c['id']}" for c in item.get("controls", []))
            badge = f" <span class='pill warn'>{escape(item['drift'])}</span>" if item.get("drift") else ""
            add(
                f"<tr><td><span class='pill {escape(item.get('severity', ''))}'>{escape(item.get('severity', ''))}</span></td>"
                f"<td><b>{escape(item.get('title', ''))}</b>{badge}<br><span class='mono dim'>{escape(item.get('code', ''))}</span></td>"
                f"<td class='detail'>{escape(item.get('detail', ''))}</td><td class='small'>{escape(controls or '–')}</td></tr>"
            )
        add("</tbody></table>")
    add("</section>")

    add("<section><h2>Access review</h2>")
    if keys:
        add("<table><thead><tr><th>Host</th><th>Account</th><th>Fingerprint</th><th>Reach</th><th>Usage</th><th>Last used</th><th>From</th><th>In push</th><th>Comment</th></tr></thead><tbody>")
        for row in keys:
            in_push = "–" if row.get("inAllow") is None else ("yes" if row["inAllow"] else "no")
            add(
                f"<tr><td>{escape(row['host'])}</td><td>{escape(row['account'])}</td><td class='mono'>{escape(row['fingerprint'])}</td>"
                f"<td>{escape(row['reach'])}</td><td>{escape(row['usage'])}</td><td class='mono'>{escape((row.get('lastUsed') or '–')[:10])}</td>"
                f"<td class='mono'>{escape(', '.join(row['options'].get('from', [])) or 'any')}</td><td>{in_push}</td><td>{escape(row.get('comment') or '–')}</td></tr>"
            )
        add("</tbody></table>")
    else:
        add("<p>No authorized keys were readable.</p>")
    add("</section>")

    add("<section><h2>Accepted risks</h2>")
    if waivers:
        add("<table><thead><tr><th>Host</th><th>Check</th><th>Was</th><th>Owner / ticket</th><th>Until</th><th>Reason</th></tr></thead><tbody>")
        for name, item in waivers:
            for waiver in item.get("waivers", []):
                owner = " / ".join(filter(None, [waiver.get("owner"), waiver.get("ticket")]))
                add(
                    f"<tr><td>{escape(str(name))}</td><td class='mono'>{escape(item['code'])}</td><td>{escape(str(item.get('was', '')))}</td>"
                    f"<td>{escape(owner)}</td><td class='mono'>{escape(waiver.get('expires', ''))}</td><td>{escape(waiver.get('reason', ''))}</td></tr>"
                )
        add("</tbody></table>")
    else:
        add("<p>No findings were accepted under a waiver in this run.</p>")
    add("</section>")

    payload = json.dumps(document, indent=1).replace("</", "<\\/")
    add(f"<section><h2>Report data</h2><p class='note'>The JSON report this page was built from. Its SHA-256 is above.</p><script type='application/json' id='keywarden-report'>{payload}</script></section>")
    add("<footer>Generated by Keywarden, an open-source SSH access review tool. This report maps findings to controls to help an assessment; it is not a certification.</footer>")
    add("</main></body></html>")
    return "".join(out)


_CSS = """
:root { --ink:#111827; --muted:#4b5563; --line:#e5e7eb; --bg:#f8fafc; --card:#fff; --fail:#c4001a; --warn:#b54700; --pass:#1f7a35; --acpt:#3634a3; --none:#6b7280;
  font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; color: var(--ink); background: var(--bg); }
body { margin: 0; } main { max-width: 1100px; margin: 0 auto; padding: 32px 20px 48px; }
.eyebrow { text-transform: uppercase; letter-spacing: .08em; font-size: 12px; color: #0a6cff; font-weight: 600; margin: 0; }
h1 { font-size: 28px; margin: 4px 0 6px; letter-spacing: -.02em; } h2 { font-size: 19px; margin: 32px 0 10px; } h3 { font-size: 15px; margin: 22px 0 8px; }
.lede { color: var(--muted); margin: 0; } .note { color: var(--muted); font-size: 12.5px; max-width: 80ch; }
section { break-inside: auto; }
.facts { display: grid; grid-template-columns: 200px 1fr; gap: 6px 16px; background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 14px 16px; margin: 0; }
.facts dt { color: var(--muted); } .facts dd { margin: 0; overflow-wrap: anywhere; font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12.5px; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; }
.tile { background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 10px 14px; } .tile span { color: var(--muted); font-size: 12px; display: block; }
.tile b { font-size: 24px; font-variant-numeric: tabular-nums; } .tile.fail b { color: var(--fail); } .tile.warn b { color: var(--warn); }
table { width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--line); border-radius: 12px; overflow: hidden; font-size: 12.5px; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { background: #f1f5f9; font-weight: 600; color: var(--muted); font-size: 12px; }
.mono { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px; overflow-wrap: anywhere; } .dim { color: var(--muted); } .small { font-size: 11.5px; color: var(--muted); }
.detail { overflow-wrap: anywhere; max-width: 520px; }
.pill { display: inline-block; font-size: 11px; font-weight: 600; padding: 1px 8px; border-radius: 999px; border: 1px solid currentColor; white-space: nowrap; }
.pill.fail { color: var(--fail); } .pill.warn { color: var(--warn); } .pill.pass { color: var(--pass); } .pill.accepted { color: var(--acpt); } .pill.none { color: var(--none); }
footer { margin-top: 36px; color: var(--muted); font-size: 12px; }
@media print { :root { background: #fff; } main { padding: 0; } table, .facts, .tile { border-color: #cbd5e1; } h2 { break-after: avoid; } tr { break-inside: avoid; } }
"""
