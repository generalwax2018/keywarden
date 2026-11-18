"""Post a short summary to a chat webhook when a run finds something new.

The message carries host names, check codes, counts and fingerprints. It never
carries key comments, login addresses, or anything from authorized_keys beyond
fingerprints.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

DRIFT = {"new", "regressed", "new-keys"}
FORMATS = ("auto", "slack", "teams", "discord", "json")
WHEN = ("drift", "fail", "always")
MAX_LINES = 15


def check_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    local = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and local):
        raise ValueError("--notify needs an https:// webhook URL (http is allowed only to localhost)")
    if not parsed.hostname:
        raise ValueError("--notify URL has no host")
    return url


def guess_format(url: str) -> str:
    host = (urllib.parse.urlparse(url).hostname or "").lower()
    if host.endswith("slack.com"):
        return "slack"
    if host.endswith(("discord.com", "discordapp.com")):
        return "discord"
    if host.endswith(("logic.azure.com", "webhook.office.com", "powerplatform.com")) or "powerautomate" in host:
        return "teams"
    return "json"


def _hosts(document: dict) -> list[dict]:
    return document.get("hosts") or ([document["host"]] if document.get("host") else [])


def events(document: dict) -> list[dict]:
    found = []
    for host in _hosts(document):
        for item in host.get("findings", []):
            if item.get("drift") in DRIFT or item.get("severity") == "fail":
                found.append(
                    {
                        "host": host.get("name"),
                        "code": item.get("code"),
                        "severity": item.get("severity"),
                        "drift": item.get("drift"),
                        "title": item.get("title"),
                        "fingerprints": item.get("newFingerprints") or item.get("fingerprints") or [],
                    }
                )
    return found


def should_send(document: dict, when: str) -> bool:
    if when == "always":
        return True
    found = events(document)
    if when == "fail":
        return any(event["severity"] == "fail" for event in found)
    return any(event["drift"] for event in found)


def summary_text(document: dict, when: str) -> str:
    hosts = _hosts(document)
    found = events(document)
    drifted = [event for event in found if event["drift"]]
    shown = drifted if when == "drift" else found
    failing = sum(1 for host in hosts if host.get("posture") == "fail")
    head = f"Keywarden {document.get('version', '')}: {len(hosts)} host(s), {failing} failing"
    if drifted:
        head += f", {len(drifted)} change(s) since the last run"
    lines = [head]
    for event in shown[:MAX_LINES]:
        tag = event["drift"] or event["severity"]
        prints = " ".join(event["fingerprints"][:3])
        lines.append(f"• {event['host']} · {event['code']} ({tag}): {event['title']}" + (f" {prints}" if prints else ""))
    if len(shown) > MAX_LINES:
        lines.append(f"…and {len(shown) - MAX_LINES} more")
    return "\n".join(lines)


def payload(document: dict, style: str, when: str) -> dict:
    text = summary_text(document, when)
    if style == "slack":
        return {"text": text}
    if style == "discord":
        return {"content": text[:1990]}
    if style == "teams":
        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [{"type": "TextBlock", "text": line, "wrap": True} for line in text.splitlines()],
                    },
                }
            ],
        }
    return {"product": "keywarden", "version": document.get("version"), "text": text, "events": events(document)}


def send(url: str, document: dict, *, style: str = "auto", when: str = "drift", opener=urllib.request.urlopen) -> bool:
    """True when a message was sent. Network errors are raised as ValueError."""
    check_url(url)
    if not should_send(document, when):
        return False
    style = guess_format(url) if style == "auto" else style
    body = json.dumps(payload(document, style, when)).encode("utf-8")
    request = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json", "User-Agent": "keywarden"})
    try:
        with opener(request, timeout=15) as response:
            status = getattr(response, "status", 200)
    except (urllib.error.URLError, OSError) as exc:
        raise ValueError(f"webhook could not be reached: {exc}") from exc
    if status >= 300:
        raise ValueError(f"webhook answered HTTP {status}")
    return True
