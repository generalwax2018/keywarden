"""Machine outputs: SARIF for code-scanning dashboards, JSON Lines for a SIEM.

Neither carries key bodies; both are built from the same report as the JSON output.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from keywarden.controls import MAPPING

REPO = "https://github.com/generalwax2018/keywarden"
_LEVEL = {"fail": "error", "warn": "warning", "accepted": "note"}
_SECURITY_SEVERITY = {"fail": "7.0", "warn": "4.0", "accepted": "1.0"}
_RANK = {"fail": 3, "warn": 2, "accepted": 1}


def _hosts(document: dict) -> list[dict]:
    return document.get("hosts") or ([document["host"]] if document.get("host") else [])


def _host_lines(inventory: Path | None) -> dict[str, int]:
    """Line of each host's first mention in the inventory, so a code-scanning alert points at it."""
    if inventory is None:
        return {}
    try:
        lines = inventory.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {}
    found: dict[str, int] = {}
    for number, line in enumerate(lines, start=1):
        for token in line.replace(":", " ").replace('"', " ").split():
            found.setdefault(token, number)
    return found


def to_sarif(document: dict, inventory: Path | None = None) -> dict:
    uri = inventory.as_posix() if inventory is not None else "keywarden-report.json"
    lines = _host_lines(inventory)
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for host in _hosts(document):
        name = host.get("name", "?")
        for item in host.get("findings", []):
            severity = item.get("severity")
            if severity not in _LEVEL:
                continue
            code = item["code"]
            rule = rules.setdefault(
                code,
                {
                    "id": code,
                    "name": code,
                    "shortDescription": {"text": item.get("title", code)},
                    "helpUri": f"{REPO}/blob/main/README.md#what-is-checked",
                    "defaultConfiguration": {"level": _LEVEL[severity]},
                    "properties": {
                        "tags": ["security", "ssh", *[key.replace(":", " ") for key in MAPPING.get(code, [])]],
                        "security-severity": _SECURITY_SEVERITY[severity],
                        "_rank": _RANK[severity],
                    },
                },
            )
            if _RANK[severity] > rule["properties"]["_rank"]:
                rule["properties"]["_rank"] = _RANK[severity]
                rule["properties"]["security-severity"] = _SECURITY_SEVERITY[severity]
                rule["defaultConfiguration"]["level"] = _LEVEL[severity]
            prints = sorted(item.get("fingerprints", []))
            identity = hashlib.sha256(f"{name}|{code}|{','.join(prints)}".encode()).hexdigest()
            results.append(
                {
                    "ruleId": code,
                    "level": _LEVEL[severity],
                    "message": {"text": f"{name}: {item.get('title', '')}. {item.get('detail', '')}"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": uri},
                                "region": {"startLine": lines.get(name, 1)},
                            },
                            "logicalLocations": [{"name": name, "kind": "host"}],
                        }
                    ],
                    "partialFingerprints": {"keywardenFinding/v1": identity},
                    "properties": {
                        "host": name,
                        "address": host.get("address"),
                        "fingerprints": prints,
                        "controls": [f"{c['framework']}:{c['id']}" for c in item.get("controls", [])],
                        **({"drift": item["drift"]} if item.get("drift") else {}),
                    },
                }
            )
    for rule in rules.values():
        rule["properties"].pop("_rank", None)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Keywarden",
                        "version": str(document.get("version", "")),
                        "informationUri": REPO,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [{"executionSuccessful": True, "endTimeUtc": document.get("generatedAt")}],
            }
        ],
    }


def to_jsonl(document: dict) -> str:
    """One finding or key per line, flat, for Splunk, Sentinel, Elastic, and the like."""
    stamp = document.get("generatedAt")
    common = {"product": "keywarden", "version": document.get("version")}
    lines: list[str] = []
    for host in _hosts(document):
        for item in host.get("findings", []):
            event = {
                "timestamp": stamp,
                "type": "finding",
                **common,
                "host": host.get("name"),
                "address": host.get("address"),
                "posture": host.get("posture"),
                "code": item.get("code"),
                "severity": item.get("severity"),
                "title": item.get("title"),
                "detail": item.get("detail"),
                "fingerprints": item.get("fingerprints", []),
                "controls": [f"{c['framework']}:{c['id']}" for c in item.get("controls", [])],
            }
            if item.get("drift"):
                event["drift"] = item["drift"]
            lines.append(json.dumps(event, separators=(",", ":")))
        for row in host.get("keys", []):
            event = {"timestamp": stamp, "type": "key", **common}
            # The row's own "type" is the key algorithm; keep "type" for the event kind.
            event.update({("keyType" if key == "type" else key): value for key, value in row.items() if key != "options"})
            event["from"] = row.get("options", {}).get("from", [])
            event["forcedCommand"] = bool(row.get("options", {}).get("command"))
            lines.append(json.dumps(event, separators=(",", ":")))
    return "\n".join(lines) + ("\n" if lines else "")
