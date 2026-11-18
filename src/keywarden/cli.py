"""Command line. Reports contain fingerprints only."""

from __future__ import annotations

import argparse
import csv
import dataclasses
import io
import json
import os
import sys
from datetime import date
from pathlib import Path

from keywarden import __version__
from keywarden.access import key_rows, reach_of
from keywarden.check import FINGERPRINT, HostObservation, Policy, PriorFindings, apply_drift, evaluate, worst
from keywarden.collect import ProtocolError, access_path, collect_local, collect_remote, now_iso, parse_protocol, read_observation
from keywarden.inventory import InventoryHost, looks_like_yaml, parse_inventory, parse_inventory_json
from keywarden.parse import PrivateKeyError, parse_public_keys
from keywarden.term import Paint, use_colour
from keywarden.waivers import Waiver, apply_waivers, load_waivers

MAX_INPUT_BYTES = 1_000_000
MAX_INVENTORY_HOSTS = 2000
MAX_JOBS = 32
_FINGERPRINT = FINGERPRINT
CSV_COLUMNS = [
    "host",
    "account",
    "uid",
    "fingerprint",
    "type",
    "bits",
    "comment",
    "inAllow",
    "reach",
    "reachVia",
    "from",
    "command",
    "allows",
    "certAuthority",
    "usage",
    "lastUsed",
    "uses",
    "lastFrom",
    "owner",
    "ownerLeft",
]


def _load_allow(path: Path | None):
    if path is None:
        return []
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("--allow file is larger than 1 MB")
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        keys, issues = parse_public_keys(text)
    finally:
        del text
    if issues:
        print(f"{len(issues)} line(s) in --allow were not public keys and were ignored", file=sys.stderr)
    return keys


def _load_prior(path: Path | None, hostname: str) -> PriorFindings | None:
    if path is None:
        return None
    return prior_from_document(json.loads(path.read_text(encoding="utf-8")), hostname)


def prior_from_document(document, hostname: str, quiet: bool = False) -> PriorFindings | None:
    host = document.get("host") if isinstance(document, dict) else None
    if host is None and isinstance(document, dict) and isinstance(document.get("hosts"), list):
        host = next((item for item in document["hosts"] if isinstance(item, dict) and item.get("name") == hostname), None)
        if host is None:
            if not quiet:
                print(f"prior report has no host named {hostname}; drift skipped", file=sys.stderr)
            return None
    if not isinstance(host, dict):
        print("prior file has no host report; drift skipped", file=sys.stderr)
        return None
    name = host.get("name")
    if name and name != hostname:
        print(f"prior report is for {name}, not {hostname}; drift skipped", file=sys.stderr)
        return None
    prior: PriorFindings = {}
    for item in host.get("findings") or []:
        if not isinstance(item, dict) or "code" not in item:
            continue
        prints = item.get("fingerprints")
        if not isinstance(prints, list):
            # Reports from 0.1.0 have no fingerprints array; read them from the detail.
            prints = _FINGERPRINT.findall(str(item.get("detail") or ""))
        severity = str(item.get("was") or item.get("severity"))
        prior[item["code"]] = (severity, {str(value) for value in prints})
    return prior


def _redact(host: HostObservation, push: list) -> list:
    """Drop key comments. They are often an email address or a laptop name."""
    for account in host.accounts:
        account.keys = [dataclasses.replace(key, comment="") for key in account.keys]
    return [dataclasses.replace(key, comment="") for key in push]


def _rows(host: HostObservation, push: list, policy: Policy, args: argparse.Namespace) -> list[dict]:
    rows = key_rows(host, push, policy)
    if getattr(args, "redact_addresses", False):
        for row in rows:
            row["lastFrom"] = None
    return rows


def _host_report(host: HostObservation, findings, rows: list[dict]) -> dict:
    report = {
        "name": host.name,
        "address": host.address,
        "role": host.role,
        "observedAt": host.observed_at,
        "privilege": host.privilege,
        "sshdRead": host.sshd_state,
        "matchBlocks": host.match_blocks,
        "authLog": host.log_source,
        "posture": worst(findings),
        "sshd": host.sshd.as_dict(),
        "findings": [item.as_dict() for item in findings],
        "keys": rows,
    }
    if host.access_path is not None:
        report["accessPath"] = host.access_path
    return report


def _envelope(push: list) -> dict:
    return {
        "product": "keywarden",
        "version": __version__,
        "keyMaterial": "omitted",
        "note": "Public key bodies are not included. Fingerprints identify keys.",
        "generatedAt": now_iso(),
        "push": [key.public() for key in push],
    }


_ORDER = {"fail": 0, "warn": 1, "accepted": 2, "pass": 3}


def _summary(findings: list[dict]) -> str:
    counts = {name: sum(1 for item in findings if item["severity"] == name) for name in ("fail", "warn", "accepted", "pass")}
    parts = [f"{counts['fail']} fail", f"{counts['warn']} warn"]
    if counts["accepted"]:
        parts.append(f"{counts['accepted']} accepted")
    parts.append(f"{counts['pass']} pass")
    return " · ".join(parts)


def _print_human(document: dict, paint: Paint | None = None, verbose: bool = False) -> None:
    paint = paint or Paint(False)
    host = document["host"]
    findings = sorted(host["findings"], key=lambda item: _ORDER.get(item["severity"], 4))
    posture = host["posture"]
    print(f"{paint('bold', 'keywarden ' + document['version'])}  {paint('bold', host['name'])}  {paint(posture, posture.upper())}  {paint('dim', _summary(findings))}")
    shown = findings if verbose else [item for item in findings if item["severity"] != "pass"]
    for item in shown:
        drift = "  " + paint("warn", item["drift"]) if item.get("drift") else ""
        print(f"  {paint.severity(item['severity'])}  {paint('dim', item['code'])}{drift}  {item['title']}")
        print(f"        {paint.fingerprints(item['detail'])}")
        if item.get("newFingerprints"):
            print(f"        new since the prior report: {paint.fingerprints(' '.join(item['newFingerprints']))}")
    hidden = len(findings) - len(shown)
    if hidden:
        print(paint("dim", f"  {hidden} passing check{'s' if hidden != 1 else ''} hidden; --verbose shows them"))
    print(paint("dim", "key material omitted"))


def _print_keys(rows: list[dict]) -> None:
    if not rows:
        print("no authorized keys were readable")
        return
    owners = any("owner" in row for row in rows)
    header = ["host", "account", "fingerprint", "reach", "usage", "last used", "from", "comment"] + (["owner"] if owners else [])
    table = [header]
    for row in rows:
        extra = [(row.get("owner") or "-") + (" (left)" if row.get("ownerLeft") else "")] if owners else []
        table.append(
            [
                row["host"],
                row["account"],
                row["fingerprint"],
                row["reach"],
                row["usage"],
                (row["lastUsed"] or "-")[:10],
                ",".join(row["options"].get("from", [])) or "any",
                row["comment"] or "-",
                *extra,
            ]
        )
    widths = [max(len(str(line[column])) for line in table) for column in range(len(header))]
    for line in table:
        print("  ".join(str(value).ljust(widths[column]) for column, value in enumerate(line)).rstrip())


def _write_evidence(path: Path, document: dict) -> None:
    from keywarden.evidence import render_evidence

    path.write_text(render_evidence(document), encoding="utf-8")


def _write_machine_outputs(args: argparse.Namespace, document: dict) -> None:
    from keywarden.outputs import to_jsonl, to_sarif

    if getattr(args, "fix_plan", None):
        _write_fix_plan(args.fix_plan, document, _fix_reasons(args), None)

    if getattr(args, "sarif", None):
        inventory = getattr(args, "inventory", None)
        args.sarif.write_text(json.dumps(to_sarif(document, inventory), indent=2) + "\n", encoding="utf-8")
    if getattr(args, "jsonl", None):
        args.jsonl.write_text(to_jsonl(document), encoding="utf-8")


def _add_owner_summary(args: argparse.Namespace, document: dict) -> None:
    if getattr(args, "owners", None) is None:
        return
    from keywarden.owners import owner_summary

    rows = [row for host in (document.get("hosts") or [document.get("host") or {}]) for row in host.get("keys", [])]
    document["owners"] = owner_summary(rows)


def _fix_reasons(args: argparse.Namespace) -> set[str]:
    from keywarden.fixplan import DEFAULT_REASONS, REASONS

    text = getattr(args, "fix_for", None)
    wanted = set(DEFAULT_REASONS) if not text else {part.strip() for part in text.split(",") if part.strip()}
    unknown = wanted - set(REASONS)
    if unknown:
        raise ValueError(f"--fix-for takes {', '.join(REASONS)}; not {', '.join(sorted(unknown))}")
    return wanted


def _write_fix_plan(path: Path, document: dict, wanted: set[str], review: dict | None) -> int:
    from keywarden.fixplan import removals, render_playbook

    items = removals(document, wanted, review)
    path.write_text(render_playbook(items, generated=now_iso(), version=__version__), encoding="utf-8")
    return sum(len(item["keys"]) for item in items)


def _notify(args: argparse.Namespace, document: dict) -> None:
    url = getattr(args, "notify", None) or os.environ.get("KEYWARDEN_WEBHOOK")
    if not url:
        return
    from keywarden.notify import send

    try:
        if send(url, document, style=args.notify_format, when=args.notify_on):
            print("summary posted to the webhook", file=sys.stderr)
    except ValueError as exc:
        print(f"webhook not sent: {exc}", file=sys.stderr)


def _print_owners(document: dict, paint: Paint) -> None:
    people = document.get("owners") or []
    if not people:
        return
    print(paint("bold", "who has access"))
    for person in people[:15]:
        flag = "  " + paint("fail", "LEFT") if person["left"] else ""
        parts = [f"{person['hosts']} host{'s' if person['hosts'] != 1 else ''}"]
        if person["rootHosts"]:
            parts.append(f"root on {person['rootHosts']}")
        accounts = len(person["accounts"])
        keys = len(person["keys"])
        parts.append(f"{accounts} account{'s' if accounts != 1 else ''}")
        parts.append(f"{keys} key{'s' if keys != 1 else ''}")
        print(f"  {person['owner']}{flag}  {paint('dim', ' · '.join(parts))}")
    if len(people) > 15:
        print(paint("dim", f"  {len(people) - 15} more in the JSON report"))


def _paint(args: argparse.Namespace) -> Paint:
    return Paint(use_colour(getattr(args, "color", "auto")))


def _write_csv(path: Path, rows: list[dict]) -> None:
    # Path.write_text has no newline argument before Python 3.10; csv already ends rows with \r\n.
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(csv_text(rows))


def csv_text(rows: list[dict]) -> str:
    handle = io.StringIO()
    writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        options = row["options"]
        flat = dict(row)
        flat["from"] = " ".join(options.get("from", []))
        flat["command"] = "yes" if options.get("command") else ""
        flat["allows"] = " ".join(options.get("allows", []))
        flat["inAllow"] = "" if row["inAllow"] is None else ("yes" if row["inAllow"] else "no")
        flat["certAuthority"] = "yes" if row["certAuthority"] else ""
        if "ownerLeft" in row:
            flat["ownerLeft"] = "yes" if row["ownerLeft"] else ""
        writer.writerow({key: _csv_safe(value) for key, value in flat.items()})
    return handle.getvalue()


def _csv_safe(value):
    """Stop a comment like =HYPERLINK(...) from running as a formula in a spreadsheet."""
    if isinstance(value, str) and value[:1] in {"=", "+", "-", "@", "\t", "\r"}:
        return "'" + value
    return "" if value is None else value


def _remember_failure(found: dict[str, dict[str, list[str]]], plain: list[str], name: str, findings: list[dict]) -> None:
    for item in findings:
        if item.get("severity") != "fail":
            continue
        fingerprints = list(dict.fromkeys(_FINGERPRINT.findall(item.get("detail") or "")))
        if not fingerprints:
            plain.append(f"{name}  {item['code']}")
            continue
        for fingerprint in fingerprints:
            bucket = found.setdefault(fingerprint, {"codes": [], "hosts": []})
            if item["code"] not in bucket["codes"]:
                bucket["codes"].append(item["code"])
            if name not in bucket["hosts"]:
                bucket["hosts"].append(name)


def _unique_failure_lines(found: dict[str, dict[str, list[str]]], plain: list[str]) -> list[str]:
    lines = [
        f"{fingerprint}  {' '.join(info['codes'])}  {' '.join(info['hosts'])}"
        for fingerprint, info in found.items()
    ]
    lines.extend(plain)
    return lines


def _policy(args: argparse.Namespace) -> Policy:
    stale = getattr(args, "stale_days", 90)
    if stale < 1:
        raise ValueError("--stale-days must be 1 or more")
    max_cert = getattr(args, "max_cert_days", 90)
    if max_cert < 1:
        raise ValueError("--max-cert-days must be 1 or more")
    book = None
    if getattr(args, "owners", None) is not None or getattr(args, "leavers", None) is not None:
        from keywarden.owners import load_book

        book = load_book(args.owners, args.leavers, fetch_github=not getattr(args, "no_github", False))
        for handle in book.unmatched_leavers():
            print(f"leaver {handle} has no keys in the owners file, so their keys cannot be swept", file=sys.stderr)
    cas = None
    if getattr(args, "allow_ca", None):
        cas = frozenset(key.fingerprint for path in args.allow_ca for key in _load_allow(path))
    return Policy(
        flag_outside_push=not getattr(args, "no_outside", False),
        flag_weak=not getattr(args, "no_weak", False),
        stale_days=stale,
        owners=book,
        allowed_cas=cas,
        max_cert_days=max_cert,
        require_jump=getattr(args, "require_jump", False),
    )


def _waivers(args: argparse.Namespace) -> list[Waiver]:
    path = getattr(args, "waivers", None)
    return load_waivers(path) if path else []


def _report_unused(waivers: list[Waiver], used: set[int]) -> None:
    for waiver in waivers:
        if waiver.index not in used:
            print(f"waiver {waiver.label} ({waiver.code}) matched nothing; remove it if the risk is gone", file=sys.stderr)


def _observe_one(args: argparse.Namespace) -> HostObservation:
    if args.local:
        return collect_local(args.account)
    if args.host:
        jump = getattr(args, "jump", None)
        observed = collect_remote(args.host, args.account, accept_new=args.accept_new, **({"jump": jump} if jump else {}))
        observed.access_path = access_path(args.host, None, jump)
        return observed
    raw = read_observation(args.observation)
    try:
        if len(raw.encode("utf-8", errors="replace")) > MAX_INPUT_BYTES:
            raise ValueError("observation is larger than 1 MB")
        address = "stdin" if args.observation == "-" else "file"
        return parse_protocol(raw, address=address)
    finally:
        del raw


def _ansible_inventory_json(path: Path) -> str:
    """Let Ansible resolve YAML files, plugins, and dynamic inventory scripts, then read its JSON."""
    import shutil
    import subprocess

    binary = shutil.which("ansible-inventory")
    if binary is None:
        raise ValueError(
            f"{path.name} is not an INI inventory. Install Ansible so Keywarden can read it with ansible-inventory, "
            f"or run 'ansible-inventory -i {path.name} --list > inventory.json' and pass --inventory inventory.json"
        )
    try:
        completed = subprocess.run(
            [binary, "-i", str(path), "--list"],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired as exc:
        raise ValueError("ansible-inventory did not finish within 3 minutes") from exc
    if completed.returncode != 0:
        tail = (completed.stderr or "").strip().splitlines()[-1:] or [f"exit {completed.returncode}"]
        raise ValueError(f"ansible-inventory could not read {path.name}: {tail[0][:200]}")
    return completed.stdout


def _targets(path: Path) -> list[InventoryHost]:
    if path.is_dir():
        text = _ansible_inventory_json(path)
        kind = "json"
    else:
        text = path.read_text(encoding="utf-8", errors="replace")
        stripped = text.lstrip()
        if path.suffix.lower() == ".json" or stripped.startswith("{"):
            kind = "json"
        elif looks_like_yaml(text, path.name) or stripped.startswith("#!"):
            # YAML, an inventory plugin config, or a dynamic inventory script.
            text = _ansible_inventory_json(path)
            kind = "json"
        else:
            kind = "ini"
    try:
        if len(text.encode("utf-8", errors="replace")) > 20 * MAX_INPUT_BYTES:
            raise ValueError("inventory is larger than 20 MB")
        if "PRIVATE KEY" in text or "-----BEGIN" in text or "PuTTY-User-Key-File" in text:
            raise PrivateKeyError("private key material was present and was not recorded")
        targets = parse_inventory_json(text) if kind == "json" else parse_inventory(text, source=path.name)
    finally:
        del text
    if not targets:
        raise ValueError("inventory has no hosts")
    if len(targets) > MAX_INVENTORY_HOSTS:
        raise ValueError(f"inventory has more than {MAX_INVENTORY_HOSTS} hosts")
    return targets


def observe_all(targets: list[InventoryHost], args, jobs: int):
    """Observe every target, several at a time, and return (target, observation or error) in inventory order."""
    from concurrent.futures import ThreadPoolExecutor

    jobs = max(1, min(int(jobs or 1), MAX_JOBS, len(targets) or 1))

    def one(target: InventoryHost):
        try:
            return target, _observe_target(target, args)
        except Exception as exc:  # noqa: BLE001 - reported per host; the run continues
            return target, exc

    if jobs == 1:
        return [one(target) for target in targets]
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        return list(pool.map(one, targets))


def _observe_target(target: InventoryHost, args: argparse.Namespace) -> HostObservation:
    observed = collect_remote(
        target.destination,
        args.account,
        target.port,
        accept_new=args.accept_new,
        identity_file=target.identity_file,
        **({"jump": target.jump} if target.jump else {}),
    )
    observed.name = target.name
    observed.address = target.destination
    observed.access_path = access_path(target.destination, target.port, target.jump)
    return observed


def _check_one(args: argparse.Namespace) -> int:
    push = _load_allow(args.allow)
    waivers = _waivers(args)
    host = _observe_one(args)
    if args.redact_comments:
        push = _redact(host, push)
    policy = _policy(args)
    findings = apply_drift(evaluate(host, push, policy), _load_prior(args.prior, host.name))
    used: set[int] = set()
    findings = apply_waivers(findings, host.name, waivers, date.today(), used)
    rows = _rows(host, push, policy, args)
    document = _envelope(push)
    document["host"] = _host_report(host, findings, rows)
    _add_owner_summary(args, document)
    encoded = json.dumps(document, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    if args.csv:
        _write_csv(args.csv, rows)
    if args.evidence:
        _write_evidence(args.evidence, document)
    _write_machine_outputs(args, document)
    _notify(args, document)
    if args.json:
        sys.stdout.write(encoded)
    else:
        _print_human(document, _paint(args), args.verbose)
        _print_owners(document, _paint(args))
        if args.keys:
            print()
            _print_keys(rows)
    _report_unused(waivers, used)
    return 1 if host_failed(document) else 0


def _unreachable(name: str, address: str, detail: str, code: str = "unreachable") -> dict:
    title = "Host could not be checked" if code == "unreachable" else "Collector output was refused"
    return {
        "name": name,
        "address": address,
        "role": "observed",
        "observedAt": now_iso(),
        "posture": "fail",
        "sshd": {},
        "findings": [
            {
                "code": code,
                "severity": "fail",
                "title": title,
                "detail": detail[:180],
            }
        ],
        "keys": [],
    }


def _check_inventory(args: argparse.Namespace) -> int:
    prior_document = json.loads(args.prior.read_text(encoding="utf-8")) if args.prior else None
    push = _load_allow(args.allow)
    waivers = _waivers(args)
    if args.redact_comments:
        push = [dataclasses.replace(key, comment="") for key in push]
    targets = _targets(args.inventory)
    policy = _policy(args)
    host_reports = []
    all_rows: list[dict] = []
    found: dict[str, dict[str, list[str]]] = {}
    plain: list[str] = []
    used: set[int] = set()
    today = date.today()
    for target, observed in observe_all(targets, args, args.jobs):
        if isinstance(observed, ProtocolError):
            host_reports.append(_unreachable(target.name, target.destination, str(observed), code="collector-output"))
            plain.append(f"{target.name}  collector-output")
            continue
        if isinstance(observed, Exception):
            host_reports.append(_unreachable(target.name, target.destination, str(observed)))
            plain.append(f"{target.name}  unreachable")
            continue
        if args.redact_comments:
            _redact(observed, [])
        prior = prior_from_document(prior_document, target.name, quiet=True) if prior_document is not None else None
        findings = apply_waivers(apply_drift(evaluate(observed, push, policy), prior), target.name, waivers, today, used)
        rows = _rows(observed, push, policy, args)
        all_rows.extend(rows)
        host_reports.append(_host_report(observed, findings, rows))
        _remember_failure(found, plain, target.name, host_reports[-1]["findings"])
    posture = "fail" if any(item["posture"] == "fail" for item in host_reports) else "pass"
    lines = _unique_failure_lines(found, plain)
    document = _envelope(push)
    document.update({"fingerprints": list(found), "posture": posture, "hosts": host_reports})
    _add_owner_summary(args, document)
    encoded = json.dumps(document, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    if args.csv:
        _write_csv(args.csv, all_rows)
    if args.evidence:
        _write_evidence(args.evidence, document)
    _write_machine_outputs(args, document)
    _notify(args, document)
    if args.json:
        sys.stdout.write(encoded)
    else:
        paint = _paint(args)
        for line in lines:
            first, _, rest = line.partition("  ")
            print(f"{paint.fingerprints(first) if first.startswith('SHA256:') else paint('bold', first)}  {paint('fail', rest)}")
        failing = sum(1 for item in host_reports if item["posture"] == "fail")
        warning = sum(1 for item in host_reports if item["posture"] == "warn")
        summary = f"{len(targets)} hosts · {failing} failing · {warning} to review · {len(targets) - failing - warning} clear"
        print(paint("dim" if lines else "pass", summary))
        _print_owners(document, paint)
        if args.keys:
            print()
            _print_keys(all_rows)
    _report_unused(waivers, used)
    return 1 if posture == "fail" else 0


def host_failed(document: dict) -> bool:
    return document["host"]["posture"] == "fail"


def _wanted_fingerprints(args: argparse.Namespace) -> list[str]:
    wanted: list[str] = []
    for value in args.fingerprint:
        if not FINGERPRINT.fullmatch(value):
            raise ValueError(f"not a fingerprint: {value} (expected SHA256:..., as ssh-keygen -lf prints)")
        wanted.append(value)
    for path in args.key or []:
        if path.stat().st_size > MAX_INPUT_BYTES:
            raise ValueError(f"{path} is larger than 1 MB")
        text = path.read_text(encoding="utf-8", errors="replace")
        try:
            keys, _issues = parse_public_keys(text)
        finally:
            del text
        if not keys:
            raise ValueError(f"{path} has no public key")
        wanted.extend(key.fingerprint for key in keys)
    if not wanted:
        raise ValueError("give a fingerprint, or --key with a public key file")
    return list(dict.fromkeys(wanted))


def _matches(host: HostObservation, wanted: set[str]) -> list[dict]:
    """Every place on this host that accepts one of the wanted keys, plus logins seen in the log."""
    hits: list[dict] = []
    listed: set[tuple[str, str]] = set()
    for account in host.accounts:
        if account.read_state != "ok":
            continue
        reach = reach_of(account)
        for key in account.keys:
            if key.fingerprint not in wanted:
                continue
            login = host.logins.get((account.user, "CA:" + key.fingerprint if key.cert_authority else key.fingerprint))
            listed.add((account.user, key.fingerprint))
            hits.append(
                {
                    "host": host.name,
                    "account": account.user,
                    "fingerprint": key.fingerprint,
                    "how": "trusted as a certificate authority" if key.cert_authority else "authorized_keys",
                    "reach": reach.level,
                    "reachVia": reach.via,
                    "from": list(key.options.source),
                    "lastUsed": _iso(login.last) if login else None,
                    "uses": login.count if login else 0,
                }
            )
    for (user, fingerprint), login in host.logins.items():
        plain = fingerprint[3:] if fingerprint.startswith("CA:") else fingerprint
        if plain in wanted and (user, plain) not in listed:
            hits.append(
                {
                    "host": host.name,
                    "account": user,
                    "fingerprint": plain,
                    "how": "logged in recently, but not in a readable authorized_keys",
                    "reach": "unknown",
                    "reachVia": "",
                    "from": [],
                    "lastUsed": _iso(login.last),
                    "uses": login.count,
                }
            )
    return hits


def _iso(epoch: int | None) -> str | None:
    from keywarden.access import _iso as to_iso

    return to_iso(epoch)


def _where(args: argparse.Namespace) -> int:
    wanted = _wanted_fingerprints(args)
    wanted_set = set(wanted)
    hits: list[dict] = []
    blind: list[str] = []
    if args.inventory:
        for target, host in observe_all(_targets(args.inventory), args, args.jobs):
            if isinstance(host, Exception):
                blind.append(f"{target.name}  not checked: {str(host)[:120]}")
                continue
            hits.extend(_matches(host, wanted_set))
            blind.extend(f"{host.name}  {account.user} could not be read" for account in host.accounts if account.read_state == "unreadable")
    else:
        host = _observe_one(args)
        hits.extend(_matches(host, wanted_set))
        blind.extend(f"{host.name}  {account.user} could not be read" for account in host.accounts if account.read_state == "unreadable")
    if args.json:
        sys.stdout.write(json.dumps({"fingerprints": wanted, "found": hits, "notChecked": blind}, indent=2) + "\n")
    else:
        for hit in hits:
            source = ",".join(hit["from"]) or "any address"
            last = hit["lastUsed"] or "no login in the logs"
            print(f"{hit['host']}  {hit['account']}  {hit['fingerprint']}  {hit['how']}  reach={hit['reach']}  from={source}  last={last}")
        if not hits:
            print("not found on any host that could be read")
        for line in blind:
            print(line, file=sys.stderr)
    return 0 if hits else 1


def _read_decisions(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if text.lstrip().startswith(("[", "{")):
        data = json.loads(text)
        return data.get("decisions", []) if isinstance(data, dict) else data
    return [{key.strip().lower(): (value or "").strip() for key, value in row.items() if key} for row in csv.DictReader(io.StringIO(text))]


def _review(args: argparse.Namespace) -> int:
    from keywarden import review

    if args.review_command == "record":
        report = json.loads(args.report.read_text(encoding="utf-8"))
        decisions = [dict(item, decision=str(item.get("decision", "")).lower()) for item in _read_decisions(args.decisions)]
        record = review.build_record(report, {"name": args.reviewer, "role": args.role}, decisions)
        args.output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        args.output.with_suffix(".html").write_text(review.render_html(record), encoding="utf-8")
        summary = record["summary"]
        print(f"{summary['approved']} approved · {summary['revoked']} revoked · {summary['undecided']} undecided · sealed {record['sha256'][:16]}")
        return 0
    if args.review_command == "sign":
        print(f"signature written to {review.sign(args.record, args.key)}")
        return 0
    print(review.verify(args.record, args.signers, args.identity))
    return 0


def _plan(args: argparse.Namespace) -> int:
    from keywarden import review

    report = json.loads(args.report.read_text(encoding="utf-8"))
    record = None
    if args.review:
        record = json.loads(args.review.read_text(encoding="utf-8"))
        review.check_record(record)
    wanted = _fix_reasons(args) if (args.fix_for or not record) else set()
    count = _write_fix_plan(args.output, report, wanted, record)
    print(f"{count} key(s) in the fix plan: {args.output}")
    return 0


def _add_source(parser: argparse.ArgumentParser, inventory_help: str) -> None:
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--local", action="store_true", help="read this machine")
    source.add_argument("--host", help="ssh to user@host in batch mode and read it")
    source.add_argument("--observation", help="collector output file, or - for stdin")
    source.add_argument("--inventory", type=Path, help=inventory_help)
    parser.add_argument("--jobs", "-j", type=int, default=8, help=f"hosts to check at once with --inventory (1-{MAX_JOBS}, default 8)")
    parser.add_argument("--account", action="append", default=[], help="extra account to read; repeatable")
    parser.add_argument("--jump", "-J", help="with --host: reach it through this jump host ([user@]host[:port]); inventories use ProxyJump in ansible_ssh_common_args")
    parser.add_argument(
        "--accept-new",
        action="store_true",
        help="trust a host key that is not in known_hosts; the default is to fail that host",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keywarden",
        description="Check SSH posture around the public keys you push. Does not store them.",
    )
    parser.add_argument("--version", action="version", version=f"keywarden {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="check one host, or every host in an Ansible inventory")
    _add_source(check, "Ansible inventory: INI, ansible-inventory --list JSON, or YAML/dynamic (needs Ansible installed)")
    check.add_argument("--allow", type=Path, help="public keys you push; fingerprinted, not copied into the report")
    check.add_argument("--prior", type=Path, help="earlier keywarden JSON report (one host or a whole inventory), for drift")
    check.add_argument("--output", type=Path, help="write the JSON report here")
    check.add_argument("--json", action="store_true", help="print the JSON report")
    check.add_argument("--csv", type=Path, help="write the access review table (one row per authorized key) here")
    check.add_argument("--keys", action="store_true", help="also print the access review table")
    check.add_argument("--evidence", type=Path, help="write an evidence report (HTML) with control mapping for an assessor")
    check.add_argument("--verbose", "-v", action="store_true", help="also print passing checks")
    check.add_argument("--sarif", type=Path, help="write findings as SARIF 2.1.0, for GitHub code scanning and similar")
    check.add_argument("--jsonl", type=Path, help="write one JSON event per finding and per key, for a SIEM")
    check.add_argument("--color", choices=["auto", "always", "never"], default="auto", help="colour the terminal output (default: auto; NO_COLOR is honoured)")
    check.add_argument("--waivers", type=Path, help="accepted risks, JSON or TOML; each needs a reason, an owner or ticket, and an end date")
    check.add_argument("--stale-days", type=int, default=90, help="a key with no login in this many days is stale (default 90)")
    check.add_argument("--no-outside", action="store_true", help="do not flag keys missing from --allow")
    check.add_argument("--no-weak", action="store_true", help="do not flag DSA or RSA under 3072 bits")
    check.add_argument(
        "--redact-comments",
        action="store_true",
        help="leave key comments (often an email or machine name) out of the output",
    )
    check.add_argument("--redact-addresses", action="store_true", help="leave the last login address out of the output")
    people = check.add_argument_group("owners and leavers")
    people.add_argument("--owners", type=Path, help="who owns each key: CSV, JSON, LDIF, or a directory of <person>.pub files")
    people.add_argument("--leavers", type=Path, help="people who have left, one name, email, or GitHub user per line; their keys fail")
    people.add_argument("--no-github", action="store_true", help="do not fetch https://github.com/<user>.keys for owners with a github column")
    certs = check.add_argument_group("certificates and access paths")
    certs.add_argument("--allow-ca", type=Path, action="append", help="approved CA public keys (user and host CAs); repeatable")
    certs.add_argument("--max-cert-days", type=int, default=90, help="warn on certificates valid for longer than this (default 90)")
    certs.add_argument("--require-jump", action="store_true", help="fail hosts that Keywarden reached directly instead of through a jump host")
    fixes = check.add_argument_group("fix plan and alerts")
    fixes.add_argument("--fix-plan", type=Path, help="write an Ansible playbook that removes flagged keys; Keywarden never runs it")
    fixes.add_argument("--fix-for", help="what the fix plan removes: leaver, outside, stale, unowned, expired (default leaver,outside)")
    fixes.add_argument("--notify", help="webhook URL for a summary (Slack, Teams workflow, Discord, or any JSON endpoint); or set KEYWARDEN_WEBHOOK")
    fixes.add_argument("--notify-on", choices=["drift", "fail", "always"], default="drift", help="when to post (default drift: something new since --prior)")
    fixes.add_argument("--notify-format", choices=["auto", "slack", "teams", "discord", "json"], default="auto", help="message shape (default: from the URL)")

    where = sub.add_parser("where", help="find every host and account that accepts a key")
    where.add_argument("fingerprint", nargs="*", default=[], help="SHA256:... fingerprint; repeatable")
    where.add_argument("--key", type=Path, action="append", help="public key file to look for; repeatable")
    where.add_argument("--json", action="store_true", help="print JSON")
    _add_source(where, "Ansible INI inventory; one SSH per host")

    review = sub.add_parser("review", help="seal, sign, and verify access review records")
    review_sub = review.add_subparsers(dest="review_command", required=True)
    record = review_sub.add_parser("record", help="turn a decisions file and a report into a sealed review record")
    record.add_argument("report", type=Path, help="keywarden JSON report the review covers")
    record.add_argument("decisions", type=Path, help="CSV or JSON: host, account, fingerprint, decision (approve/revoke), note")
    record.add_argument("--reviewer", required=True, help="reviewer's name, as it should appear on the record")
    record.add_argument("--role", default="", help="reviewer's role")
    record.add_argument("--output", type=Path, required=True, help="write the record (JSON) here; an .html copy is written beside it")
    signer = review_sub.add_parser("sign", help="sign a review record with your SSH key (ssh-keygen -Y sign)")
    signer.add_argument("record", type=Path)
    signer.add_argument("--key", type=Path, required=True, help="your SSH private key; ssh-keygen reads it, Keywarden does not")
    verifier = review_sub.add_parser("verify", help="check a record's seal, and its signature with --signers")
    verifier.add_argument("record", type=Path)
    verifier.add_argument("--signers", type=Path, help="allowed_signers file (see ssh-keygen ALLOWED SIGNERS)")
    verifier.add_argument("--identity", help="signer identity in allowed_signers (default: the reviewer's name)")

    plan = sub.add_parser("plan", help="write a fix-plan playbook from a saved report and, optionally, a review record")
    plan.add_argument("report", type=Path, help="keywarden JSON report")
    plan.add_argument("--review", type=Path, help="review record; its revoke decisions are removed")
    plan.add_argument("--fix-for", help="also remove: leaver, outside, stale, unowned, expired (default: only revoked keys when --review is given)")
    plan.add_argument("--output", type=Path, required=True, help="playbook to write")

    ui = sub.add_parser("ui", help="open the checks in a browser tab served from this machine only")
    ui.add_argument("--port", type=int, default=None, help="port on 127.0.0.1 (default 8765, or any free port if it is taken)")
    ui.add_argument("--no-browser", action="store_true", help="print the link instead of opening it")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "ui":
            from keywarden.ui import serve

            return serve(args.port, open_browser=not args.no_browser)
        if args.command == "where":
            return _where(args)
        if args.command == "review":
            return _review(args)
        if args.command == "plan":
            return _plan(args)
        if args.inventory:
            return _check_inventory(args)
        return _check_one(args)
    except BrokenPipeError:
        # Output piped into head or similar that closed early; nothing went wrong.
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        return 0
    except PrivateKeyError:
        print(
            "Refusing to continue: a private key was in the input. Keywarden accepts public keys only and did not keep a copy.",
            file=sys.stderr,
        )
        return 2
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - a bug should end in a message, not a traceback
        if os.environ.get("KEYWARDEN_DEBUG"):
            raise
        print(
            f"Keywarden hit an unexpected error ({type(exc).__name__}: {exc}). "
            "Set KEYWARDEN_DEBUG=1 to see the details, and please report it at "
            "https://github.com/generalwax2018/keywarden/issues",
            file=sys.stderr,
        )
        return 3


if __name__ == "__main__":
    sys.exit(main())
