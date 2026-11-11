"""keywarden ui: the same checks in a browser tab, served from this machine only.

The server listens on 127.0.0.1, answers only requests that carry the session
token and a localhost Host header, and keeps nothing between requests. Public
key text is fingerprinted on arrival and dropped; the page holds fingerprints.
"""

from __future__ import annotations

import json
import secrets
import sys
import threading
import time
import webbrowser
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

from keywarden import __version__
from keywarden.access import key_rows
from keywarden.check import FINGERPRINT, HostObservation, Policy, apply_drift, evaluate
from keywarden.cli import (
    _envelope,
    _host_report,
    _matches,
    _observe_target,
    _targets,
    _unreachable,
    csv_text,
    prior_from_document,
)
from keywarden.collect import (
    LOCAL_SUPPORTED,
    LOCAL_UNSUPPORTED_MESSAGE,
    REMOTE_SCRIPT,
    ProtocolError,
    collect_local,
    collect_remote,
    parse_protocol,
)
from keywarden.parse import KeyRef, PrivateKeyError, kind_of, parse_public_keys
from keywarden.ui_lab import LAB_PUSH, lab_hosts
from keywarden.ui_page import render_page
from keywarden.waivers import apply_waivers, load_waivers

MAX_BODY = 2_000_000
TARGETS = {"lab", "local", "host", "inventory", "paste"}


class BadRequest(ValueError):
    pass


def _push_from(body: dict) -> list[KeyRef]:
    """New key text replaces the set. Without it, the fingerprints the page already holds are used."""
    text = body.get("allowText") or ""
    if not isinstance(text, str):
        raise BadRequest("allowText must be text")
    if text.strip():
        try:
            keys, _issues = parse_public_keys(text)
        finally:
            del text
        if not keys:
            raise BadRequest("No public keys were found in the push box.")
        return keys
    keys = []
    for item in body.get("allowFingerprints") or []:
        if not isinstance(item, dict) or not FINGERPRINT.fullmatch(str(item.get("fingerprint", ""))):
            raise BadRequest("allowFingerprints holds something that is not a fingerprint")
        key_type = str(item.get("type") or "unknown")
        bits = item.get("bits") if isinstance(item.get("bits"), int) else None
        keys.append(KeyRef(item["fingerprint"], key_type, kind_of(key_type), bits, str(item.get("comment") or "")))
    return keys


def _policy(body: dict) -> Policy:
    stale = body.get("staleDays", 90)
    if not isinstance(stale, int) or stale < 1 or stale > 3650:
        raise BadRequest("Stale after must be between 1 and 3650 days.")
    return Policy(
        flag_outside_push=bool(body.get("flagOutside", True)),
        flag_weak=bool(body.get("flagWeak", True)),
        stale_days=stale,
    )


def _args(body: dict) -> SimpleNamespace:
    accounts = body.get("accounts") or []
    if not isinstance(accounts, list) or not all(isinstance(item, str) for item in accounts):
        raise BadRequest("accounts must be a list of names")
    return SimpleNamespace(account=accounts, accept_new=bool(body.get("acceptNew", False)))


def _observations(body: dict):
    """Yield (name, observation or error dict, role, prior) for the chosen target."""
    target = body.get("target")
    if target not in TARGETS:
        raise BadRequest("Pick what to check.")
    args = _args(body)
    if target == "lab":
        for observation, address, role, prior in lab_hosts(int(time.time())):
            observation.address = address
            yield observation.name, observation, role, prior
        return
    if target == "local":
        if not LOCAL_SUPPORTED:
            raise BadRequest(LOCAL_UNSUPPORTED_MESSAGE.replace("--local", "This machine").replace(" or keywarden ui and its lab hosts", " or the lab hosts"))
        observation = collect_local(args.account)
        yield observation.name, observation, "This machine", None
        return
    if target == "host":
        destination = str(body.get("host") or "").strip()
        if not destination:
            raise BadRequest("Enter a host as user@hostname.")
        try:
            observation = collect_remote(destination, args.account, accept_new=args.accept_new)
        except ProtocolError as exc:
            yield destination, _unreachable(destination, destination, str(exc), code="collector-output"), "", None
            return
        except (OSError, RuntimeError, ValueError) as exc:
            yield destination, _unreachable(destination, destination, str(exc)), "", None
            return
        yield observation.name, observation, "", None
        return
    if target == "paste":
        text = str(body.get("observation") or "")
        if not text.strip():
            raise BadRequest("Paste the collector output first.")
        if len(text) > 1_000_000:
            raise BadRequest("The pasted output is larger than 1 MB.")
        try:
            observation = parse_protocol(text, address="pasted")
        finally:
            del text
        yield observation.name, observation, "Pasted", None
        return
    path = Path(str(body.get("inventoryPath") or "").strip()).expanduser()
    if not str(path) or not path.is_file():
        raise BadRequest("Enter the path to an INI inventory on this machine.")
    for target_host in _targets(path):
        try:
            observation = _observe_target(target_host, args)
        except ProtocolError as exc:
            yield target_host.name, _unreachable(target_host.name, target_host.destination, str(exc), code="collector-output"), "", None
            continue
        except (OSError, RuntimeError, ValueError) as exc:
            yield target_host.name, _unreachable(target_host.name, target_host.destination, str(exc)), "", None
            continue
        yield target_host.name, observation, "", None


def run_check(body: dict) -> dict:
    push = _push_from(body)
    policy = _policy(body)
    waivers = []
    waiver_path = str(body.get("waiversPath") or "").strip()
    if waiver_path:
        waivers = load_waivers(Path(waiver_path).expanduser())
    uploaded_prior = body.get("prior")
    used: set[int] = set()
    hosts: list[dict] = []
    rows: list[dict] = []
    for name, observed, role, lab_prior in _observations(body):
        if not isinstance(observed, HostObservation):
            observed["roleLabel"] = role
            hosts.append(observed)
            continue
        prior = None
        if lab_prior is not None:
            # The lab's previous run: today's results, except where it says a check was different.
            prior = {item.code: (item.severity, set(item.fingerprints)) for item in evaluate(observed, push, policy)}
            prior.update(lab_prior)
        if uploaded_prior is not None:
            prior = prior_from_document(uploaded_prior, observed.name) or prior
        findings = apply_drift(evaluate(observed, push, policy), prior)
        findings = apply_waivers(findings, observed.name, waivers, date.today(), used)
        host_rows = key_rows(observed, push, policy)
        rows.extend(host_rows)
        report = _host_report(observed, findings, host_rows)
        report["roleLabel"] = role
        hosts.append(report)
    document = _envelope(push)
    document["hosts"] = hosts
    document["posture"] = "fail" if any(host["posture"] == "fail" for host in hosts) else "pass"
    notes = [
        f"Waiver {waiver.label} ({waiver.code}) matched nothing; remove it if the risk is gone."
        for waiver in waivers
        if waiver.index not in used
    ]
    from keywarden.evidence import render_evidence

    return {
        "report": document,
        "csv": csv_text(rows),
        "evidence": render_evidence(document),
        "notes": notes,
        "lab": body.get("target") == "lab",
    }


def run_where(body: dict) -> dict:
    wanted: list[str] = []
    for value in body.get("fingerprints") or []:
        value = str(value).strip()
        if value:
            if not FINGERPRINT.fullmatch(value):
                raise BadRequest(f"{value[:60]} is not a fingerprint. Use SHA256:..., as ssh-keygen -lf prints.")
            wanted.append(value)
    text = str(body.get("keyText") or "")
    if text.strip():
        try:
            keys, _issues = parse_public_keys(text)
        finally:
            del text
        wanted.extend(key.fingerprint for key in keys)
    if not wanted:
        raise BadRequest("Enter a fingerprint or paste a public key.")
    found: list[dict] = []
    blind: list[str] = []
    for name, observed, _role, _prior in _observations(body):
        if not isinstance(observed, HostObservation):
            blind.append(f"{name}: not checked ({observed['findings'][0]['detail'][:120]})")
            continue
        found.extend(_matches(observed, set(wanted)))
        blind.extend(f"{observed.name}: {account.user} could not be read" for account in observed.accounts if account.read_state == "unreadable")
    return {"fingerprints": list(dict.fromkeys(wanted)), "found": found, "notChecked": blind}


class Handler(BaseHTTPRequestHandler):
    server_version = "keywarden-ui"
    sys_version = ""

    def log_message(self, format, *args):  # noqa: A002 - quiet: requests can carry host names
        return

    # Every response: no caching, no framing, no referrer, scripts only with this page's nonce.
    def _headers(self, status: int, content_type: str, length: int, nonce: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        if nonce:
            self.send_header(
                "Content-Security-Policy",
                f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
                "img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
            )
        self.end_headers()

    def _send_json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode("utf-8")
        self._headers(status, "application/json; charset=utf-8", len(data))
        self.wfile.write(data)

    def _host_ok(self) -> bool:
        port = self.server.server_address[1]
        return self.headers.get("Host", "") in {f"127.0.0.1:{port}", f"localhost:{port}"}

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        port = self.server.server_address[1]
        return origin in {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}

    def _token_ok(self, supplied: str | None) -> bool:
        return supplied is not None and secrets.compare_digest(supplied, self.server.token)

    def do_GET(self):  # noqa: N802
        if not self._host_ok():
            return self._send_json(421, {"error": "wrong host"})
        url = urlsplit(self.path)
        if url.path == "/":
            token = parse_qs(url.query).get("t", [None])[0]
            if not self._token_ok(token):
                body = b"Open the link keywarden ui printed. It carries this session's token."
                self._headers(403, "text/plain; charset=utf-8", len(body))
                return self.wfile.write(body)
            nonce = secrets.token_urlsafe(16)
            page = render_page(nonce, self.server.token, __version__, LOCAL_SUPPORTED).encode("utf-8")
            self._headers(200, "text/html; charset=utf-8", len(page), nonce)
            return self.wfile.write(page)
        return self._send_json(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802
        if not self._host_ok() or not self._origin_ok():
            return self._send_json(403, {"error": "This server only answers its own page."})
        if not self._token_ok(self.headers.get("X-Keywarden-Token")):
            return self._send_json(403, {"error": "Missing or wrong session token. Reopen the link keywarden ui printed."})
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
            return self._send_json(415, {"error": "Send JSON."})
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            return self._send_json(413, {"error": "The request is larger than 2 MB."})
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._send_json(400, {"error": "The request was not valid JSON."})
        finally:
            del raw
        if not isinstance(body, dict):
            return self._send_json(400, {"error": "The request was not a JSON object."})
        try:
            if self.path == "/api/check":
                return self._send_json(200, run_check(body))
            if self.path == "/api/where":
                return self._send_json(200, run_where(body))
            if self.path == "/api/collector":
                return self._send_json(200, {"script": REMOTE_SCRIPT})
            if self.path == "/api/lab-keys":
                return self._send_json(200, {"keys": LAB_PUSH})
            return self._send_json(404, {"error": "not found"})
        except PrivateKeyError:
            return self._send_json(400, {"error": "A private key was in the input. Keywarden takes public keys only and kept nothing."})
        except (BadRequest, ValueError, OSError, RuntimeError, json.JSONDecodeError) as exc:
            return self._send_json(400, {"error": str(exc)[:400]})
        except Exception as exc:  # noqa: BLE001 - answer the page instead of dropping the connection
            return self._send_json(500, {"error": f"Keywarden hit an unexpected error ({type(exc).__name__}). Please report it on GitHub."})
        finally:
            body.clear()


class KeywardenServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int):
        super().__init__(("127.0.0.1", port), Handler)
        self.token = secrets.token_urlsafe(24)


def serve(port: int = 0, open_browser: bool = True) -> int:
    server = KeywardenServer(port)
    url = f"http://127.0.0.1:{server.server_address[1]}/?t={server.token}"
    print(f"Keywarden is running at {url}")
    print("Only this machine can reach it. Press Ctrl+C to stop; nothing is kept when it stops.")
    if open_browser:
        threading.Timer(0.3, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)
    finally:
        server.server_close()
    return 0


__all__ = ["serve", "run_check", "run_where"]
