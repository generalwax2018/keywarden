"""Command line. Reports contain fingerprints only."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from keywarden import __version__
from keywarden.check import Policy, apply_drift, evaluate, worst
from keywarden.collect import collect_local, collect_remote, now_iso, parse_protocol, read_observation
from keywarden.inventory import parse_inventory
from keywarden.parse import PrivateKeyError, parse_public_keys

MAX_INPUT_BYTES = 1_000_000
MAX_INVENTORY_HOSTS = 256
_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]+")


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


def _load_prior(path: Path | None, hostname: str):
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
    findings = host.get("findings") or []
    return {item["code"]: item["severity"] for item in findings if isinstance(item, dict) and "code" in item}


def _report(host, push, findings) -> dict:
    return {
        "product": "keywarden",
        "version": __version__,
        "keyMaterial": "omitted",
        "note": "Public key bodies are not included. Fingerprints identify keys.",
        "generatedAt": now_iso(),
        "push": [key.public() for key in push],
        "host": {
            "name": host.name,
            "address": host.address,
            "role": host.role,
            "observedAt": host.observed_at,
            "posture": worst(findings),
            "sshd": host.sshd.as_dict(),
            "findings": [item.as_dict() for item in findings],
        },
    }


def _print_human(document: dict) -> None:
    host = document["host"]
    print(f"keywarden {document['version']}  {host['name']}  {host['posture'].upper()}")
    for item in host["findings"]:
        drift = f"  {item['drift']}" if item.get("drift") else ""
        print(f"  {item['severity'].upper():4}  {item['code']}{drift}  {item['title']}")
        print(f"        {item['detail']}")
    print("key material omitted")


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
    return Policy(flag_outside_push=not args.no_outside, flag_weak=not args.no_weak)


def _check_one(args: argparse.Namespace) -> int:
    push = _load_allow(args.allow)
    if args.local:
        host = collect_local(args.account)
    elif args.host:
        host = collect_remote(args.host, args.account, accept_new=args.accept_new)
    else:
        raw = read_observation(args.observation)
        try:
            if len(raw.encode("utf-8", errors="replace")) > MAX_INPUT_BYTES:
                raise ValueError("observation is larger than 1 MB")
            address = "stdin" if args.observation == "-" else "file"
            host = parse_protocol(raw, address=address)
        finally:
            del raw
    policy = _policy(args)
    findings = apply_drift(evaluate(host, push, policy), _load_prior(args.prior, host.name))
    document = _report(host, push, findings)
    encoded = json.dumps(document, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    if args.json or not args.output:
        sys.stdout.write(encoded if args.json else "")
    if not args.json:
        _print_human(document)
    return 1 if host_failed(document) else 0


def _unreachable(name: str, address: str, detail: str) -> dict:
    return {
        "name": name,
        "address": address,
        "role": "observed",
        "observedAt": now_iso(),
        "posture": "fail",
        "sshd": {},
        "findings": [
            {
                "code": "unreachable",
                "severity": "fail",
                "title": "Host could not be checked",
                "detail": detail[:180],
            }
        ],
    }


def _check_inventory(args: argparse.Namespace) -> int:
    if args.prior:
        raise ValueError("--prior applies to one host; leave it off with --inventory")
    push = _load_allow(args.allow)
    text = args.inventory.read_text(encoding="utf-8", errors="replace")
    try:
        if len(text.encode("utf-8", errors="replace")) > MAX_INPUT_BYTES:
            raise ValueError("inventory is larger than 1 MB")
        if "PRIVATE KEY" in text or "-----BEGIN" in text or "PuTTY-User-Key-File" in text:
            raise PrivateKeyError("private key material was present and was not recorded")
        targets = parse_inventory(text)
    finally:
        del text
    if not targets:
        raise ValueError("inventory has no hosts")
    if len(targets) > MAX_INVENTORY_HOSTS:
        raise ValueError(f"inventory has more than {MAX_INVENTORY_HOSTS} hosts")
    policy = _policy(args)
    host_reports = []
    found: dict[str, dict[str, list[str]]] = {}
    plain: list[str] = []
    for target in targets:
        try:
            observed = collect_remote(target.destination, args.account, target.port, accept_new=args.accept_new)
        except (OSError, RuntimeError, ValueError) as exc:
            report = _unreachable(target.name, target.destination, str(exc))
            host_reports.append(report)
            plain.append(f"{target.name}  unreachable")
            continue
        observed.name = target.name
        observed.address = target.destination
        findings = evaluate(observed, push, policy)
        host_reports.append(_report(observed, push, findings)["host"])
        _remember_failure(found, plain, target.name, host_reports[-1]["findings"])
    posture = "fail" if any(item["posture"] == "fail" for item in host_reports) else "pass"
    rows = _unique_failure_lines(found, plain)
    document = {
        "product": "keywarden",
        "version": __version__,
        "keyMaterial": "omitted",
        "note": "Public key bodies are not included. Fingerprints identify keys.",
        "generatedAt": now_iso(),
        "push": [key.public() for key in push],
        "fingerprints": list(found),
        "posture": posture,
        "hosts": host_reports,
    }
    encoded = json.dumps(document, indent=2) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    if args.json:
        sys.stdout.write(encoded)
    elif rows:
        print("\n".join(rows))
    else:
        print(f"{len(targets)} hosts  ok")
    return 1 if posture == "fail" else 0


def host_failed(document: dict) -> bool:
    return document["host"]["posture"] == "fail"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keywarden",
        description="Check SSH posture around the public keys you push. Does not store them.",
    )
    parser.add_argument("--version", action="version", version=f"keywarden {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="check one host, or every host in an Ansible inventory")
    source = check.add_mutually_exclusive_group(required=True)
    source.add_argument("--local", action="store_true", help="read this machine")
    source.add_argument("--host", help="ssh to user@host in batch mode and read it")
    source.add_argument("--observation", help="collector output file, or - for stdin")
    source.add_argument("--inventory", type=Path, help="Ansible INI inventory; failures only, one SSH per host")
    check.add_argument("--allow", type=Path, help="public keys you push; fingerprinted, not copied into the report")
    check.add_argument("--account", action="append", default=[], help="extra account to read; repeatable")
    check.add_argument("--prior", type=Path, help="earlier keywarden JSON report, for drift")
    check.add_argument("--output", type=Path, help="write the JSON report here")
    check.add_argument("--json", action="store_true", help="print the JSON report")
    check.add_argument("--no-outside", action="store_true", help="do not flag keys missing from --allow")
    check.add_argument("--no-weak", action="store_true", help="do not flag DSA or RSA under 3072 bits")
    check.add_argument(
        "--accept-new",
        action="store_true",
        help="trust a host key that is not in known_hosts; the default is to fail that host",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "check":
        parser.error("unknown command")
    try:
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
