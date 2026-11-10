"""Command line. Reports contain fingerprints only."""

from __future__ import annotations

import argparse
import csv
import dataclasses
import json
import sys
from datetime import date
from pathlib import Path

from keywarden import __version__
from keywarden.access import key_rows, reach_of
from keywarden.check import FINGERPRINT, HostObservation, Policy, PriorFindings, apply_drift, evaluate, worst
from keywarden.collect import ProtocolError, collect_local, collect_remote, now_iso, parse_protocol, read_observation
from keywarden.inventory import InventoryHost, parse_inventory
from keywarden.parse import PrivateKeyError, parse_public_keys
from keywarden.waivers import Waiver, apply_waivers, load_waivers

MAX_INPUT_BYTES = 1_000_000
MAX_INVENTORY_HOSTS = 256
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
    document = json.loads(path.read_text(encoding="utf-8"))
    host = document.get("host")
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
    return {
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


def _envelope(push: list) -> dict:
    return {
        "product": "keywarden",
        "version": __version__,
        "keyMaterial": "omitted",
        "note": "Public key bodies are not included. Fingerprints identify keys.",
        "generatedAt": now_iso(),
        "push": [key.public() for key in push],
    }


def _print_human(document: dict) -> None:
    host = document["host"]
    print(f"keywarden {document['version']}  {host['name']}  {host['posture'].upper()}")
    for item in host["findings"]:
        drift = f"  {item['drift']}" if item.get("drift") else ""
        label = "ACPT" if item["severity"] == "accepted" else item["severity"].upper()
        print(f"  {label:4}  {item['code']}{drift}  {item['title']}")
        print(f"        {item['detail']}")
        if item.get("newFingerprints"):
            print(f"        new since the prior report: {' '.join(item['newFingerprints'])}")
    print("key material omitted")


def _print_keys(rows: list[dict]) -> None:
    if not rows:
        print("no authorized keys were readable")
        return
    header = ["host", "account", "fingerprint", "reach", "usage", "last used", "from", "comment"]
    table = [header]
    for row in rows:
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
            ]
        )
    widths = [max(len(str(line[column])) for line in table) for column in range(len(header))]
    for line in table:
        print("  ".join(str(value).ljust(widths[column]) for column, value in enumerate(line)).rstrip())


def _write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
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
            writer.writerow({key: _csv_safe(value) for key, value in flat.items()})


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
    return Policy(
        flag_outside_push=not getattr(args, "no_outside", False),
        flag_weak=not getattr(args, "no_weak", False),
        stale_days=stale,
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
        return collect_remote(args.host, args.account, accept_new=args.accept_new)
    raw = read_observation(args.observation)
    try:
        if len(raw.encode("utf-8", errors="replace")) > MAX_INPUT_BYTES:
            raise ValueError("observation is larger than 1 MB")
        address = "stdin" if args.observation == "-" else "file"
        return parse_protocol(raw, address=address)
    finally:
        del raw


def _targets(path: Path) -> list[InventoryHost]:
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        if len(text.encode("utf-8", errors="replace")) > MAX_INPUT_BYTES:
            raise ValueError("inventory is larger than 1 MB")
        if "PRIVATE KEY" in text or "-----BEGIN" in text or "PuTTY-User-Key-File" in text:
            raise PrivateKeyError("private key material was present and was not recorded")
        targets = parse_inventory(text, source=path.name)
    finally:
        del text
    if not targets:
        raise ValueError("inventory has no hosts")
    if len(targets) > MAX_INVENTORY_HOSTS:
        raise ValueError(f"inventory has more than {MAX_INVENTORY_HOSTS} hosts")
    return targets


def _observe_target(target: InventoryHost, args: argparse.Namespace) -> HostObservation:
    observed = collect_remote(
        target.destination,
        args.account,
        target.port,
        accept_new=args.accept_new,
        identity_file=target.identity_file,
    )
    observed.name = target.name
    observed.address = target.destination
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
    encoded = json.dumps(document, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    if args.csv:
        _write_csv(args.csv, rows)
    if args.json:
        sys.stdout.write(encoded)
    else:
        _print_human(document)
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
    if args.prior:
        raise ValueError("--prior applies to one host; leave it off with --inventory")
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
    for target in targets:
        try:
            observed = _observe_target(target, args)
        except ProtocolError as exc:
            host_reports.append(_unreachable(target.name, target.destination, str(exc), code="collector-output"))
            plain.append(f"{target.name}  collector-output")
            continue
        except (OSError, RuntimeError, ValueError) as exc:
            host_reports.append(_unreachable(target.name, target.destination, str(exc)))
            plain.append(f"{target.name}  unreachable")
            continue
        if args.redact_comments:
            _redact(observed, [])
        findings = apply_waivers(evaluate(observed, push, policy), target.name, waivers, today, used)
        rows = _rows(observed, push, policy, args)
        all_rows.extend(rows)
        host_reports.append(_host_report(observed, findings, rows))
        _remember_failure(found, plain, target.name, host_reports[-1]["findings"])
    posture = "fail" if any(item["posture"] == "fail" for item in host_reports) else "pass"
    lines = _unique_failure_lines(found, plain)
    document = _envelope(push)
    document.update({"fingerprints": list(found), "posture": posture, "hosts": host_reports})
    encoded = json.dumps(document, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    if args.csv:
        _write_csv(args.csv, all_rows)
    if args.json:
        sys.stdout.write(encoded)
    else:
        if lines:
            print("\n".join(lines))
        else:
            print(f"{len(targets)} hosts  ok")
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
        for target in _targets(args.inventory):
            try:
                host = _observe_target(target, args)
            except (OSError, RuntimeError, ValueError) as exc:
                blind.append(f"{target.name}  not checked: {str(exc)[:120]}")
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


def _add_source(parser: argparse.ArgumentParser, inventory_help: str) -> None:
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--local", action="store_true", help="read this machine")
    source.add_argument("--host", help="ssh to user@host in batch mode and read it")
    source.add_argument("--observation", help="collector output file, or - for stdin")
    source.add_argument("--inventory", type=Path, help=inventory_help)
    parser.add_argument("--account", action="append", default=[], help="extra account to read; repeatable")
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
    _add_source(check, "Ansible INI inventory; failures only, one SSH per host")
    check.add_argument("--allow", type=Path, help="public keys you push; fingerprinted, not copied into the report")
    check.add_argument("--prior", type=Path, help="earlier keywarden JSON report, for drift")
    check.add_argument("--output", type=Path, help="write the JSON report here")
    check.add_argument("--json", action="store_true", help="print the JSON report")
    check.add_argument("--csv", type=Path, help="write the access review table (one row per authorized key) here")
    check.add_argument("--keys", action="store_true", help="also print the access review table")
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

    where = sub.add_parser("where", help="find every host and account that accepts a key")
    where.add_argument("fingerprint", nargs="*", default=[], help="SHA256:... fingerprint; repeatable")
    where.add_argument("--key", type=Path, action="append", help="public key file to look for; repeatable")
    where.add_argument("--json", action="store_true", help="print JSON")
    _add_source(where, "Ansible INI inventory; one SSH per host")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "where":
            return _where(args)
        if args.inventory:
            return _check_inventory(args)
        return _check_one(args)
    except PrivateKeyError:
        print(
            "Refusing to continue: a private key was in the input. Keywarden accepts public keys only and did not keep a copy.",
            file=sys.stderr,
        )
        return 2
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
