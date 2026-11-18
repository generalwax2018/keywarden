"""0.5.0: owners and leavers, review records, fix plans, webhooks, certificates, jump hosts."""

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from keywarden import ui_lab  # noqa: E402
from keywarden.access import key_rows, parse_log_time  # noqa: E402
from keywarden.check import Policy, evaluate  # noqa: E402
from keywarden.cli import main  # noqa: E402
from keywarden.collect import ProtocolError, access_path, collect_remote, parse_protocol  # noqa: E402
from keywarden.fixplan import REMOVER, removals, render_playbook  # noqa: E402
from keywarden.inventory import jump_from_args, parse_inventory  # noqa: E402
from keywarden.notify import check_url, guess_format, payload, send, should_send  # noqa: E402
from keywarden.owners import book_from_texts, fetch_github_keys, load_book, load_owners, owner_summary  # noqa: E402
from keywarden.parse import parse_public_keys  # noqa: E402
from keywarden.review import build_record, check_record, render_html  # noqa: E402
from keywarden.ui import run_check, run_fixplan, run_review  # noqa: E402

KEYS = ui_lab.LAB_KEYS
FP = {name: parse_public_keys(line)[0][0].fingerprint for name, line in KEYS.items()}
HAS_SSH_KEYGEN = shutil.which("ssh-keygen") is not None


def observation(extra: str = "") -> str:
    now = int(time.time())
    text = ui_lab._host(
        "web-01",
        now,
        {},
        [
            ui_lab._account("root", 0, ["root"], [], [], "web-01"),
            ui_lab._account("ops", 1000, ["ops"], ui_lab._NO_SUDO, [KEYS["ops"], KEYS["alice"], KEYS["contractor"]], "web-01"),
        ],
        [("ops", "ops", 1, "10.0.0.9", 3)],
    )
    if not extra:
        return text
    cut = text.rstrip().rfind("\nEND")
    return text[: cut + 1] + extra + text[cut + 1 :]


def owners_csv() -> str:
    return (
        "owner,email,fingerprint,status\n"
        f"Dana Ortiz,dana@example.com,{FP['ops']},\n"
        f"Alice Chen,alice@example.com,{FP['alice']},\n"
    )


def codes(findings):
    return {item.code: item for item in findings}


class OwnerTests(unittest.TestCase):
    def test_csv_json_ldif_and_directory_give_the_same_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            (folder / "o.csv").write_text(f"owner,key\nDana,{KEYS['ops']}\n", encoding="utf-8")
            (folder / "o.json").write_text(json.dumps({"owners": [{"name": "Dana", "keys": [KEYS["ops"]]}]}), encoding="utf-8")
            (folder / "o.ldif").write_text(f"dn: uid=Dana,ou=people\nuid: Dana\nmail: d@example.com\nsshPublicKey: {KEYS['ops']}\n", encoding="utf-8")
            people = folder / "keys"
            people.mkdir()
            (people / "Dana.pub").write_text(KEYS["ops"] + "\n", encoding="utf-8")
            for path in (folder / "o.csv", folder / "o.json", folder / "o.ldif", people):
                owners = load_owners(path, fetch_github=False)
                self.assertEqual([(o.name, o.fingerprints) for o in owners], [("Dana", {FP["ops"]})], path.name)

    def test_private_key_in_owners_is_refused(self):
        from keywarden.parse import PrivateKeyError

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "o.csv"
            path.write_text("owner,key\nx,-----BEGIN OPENSSH PRIVATE KEY-----\n", encoding="utf-8")
            with self.assertRaises(PrivateKeyError):
                load_owners(path)

    def test_github_keys_are_fingerprinted(self):
        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        seen = []

        def opener(request, timeout):
            seen.append(request.full_url)
            return Response((KEYS["deploy"] + "\n").encode())

        self.assertEqual(fetch_github_keys("sam-lee", opener), {FP["deploy"]})
        self.assertEqual(seen, ["https://github.com/sam-lee.keys"])
        with self.assertRaises(ValueError):
            fetch_github_keys("../etc", opener)

    def test_leaver_and_unowned_findings(self):
        host = parse_protocol(observation())
        book = book_from_texts(owners_csv(), "alice@example.com\n")
        found = codes(evaluate(host, [], Policy(owners=book)))
        self.assertEqual(found["leaver-key"].severity, "fail")
        self.assertIn("Alice Chen", found["leaver-key"].detail)
        self.assertEqual(found["key-owner"].severity, "warn")
        self.assertIn(FP["contractor"], found["key-owner"].detail)
        rows = key_rows(host, [], Policy(owners=book))
        alice = next(row for row in rows if row["fingerprint"] == FP["alice"])
        self.assertEqual((alice["owner"], alice["ownerLeft"]), ("Alice Chen", True))
        summary = owner_summary(rows)
        self.assertEqual(summary[0]["owner"], "Alice Chen")
        self.assertTrue(summary[0]["left"])

    def test_status_column_marks_leavers_and_unmatched_leavers_are_reported(self):
        book = book_from_texts(owners_csv().replace(f"{FP['ops']},\n", f"{FP['ops']},terminated\n"), "nobody@example.com")
        self.assertTrue(book.has_left(book.owner_of(FP["ops"])))
        self.assertEqual(book.unmatched_leavers(), ["nobody@example.com"])

    def test_no_owners_means_no_owner_checks(self):
        host = parse_protocol(observation())
        found = codes(evaluate(host, [], Policy()))
        self.assertNotIn("key-owner", found)
        self.assertNotIn("leaver-key", found)
        self.assertNotIn("owner", key_rows(host, [], Policy())[0])

    def test_leavers_need_owners(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "l.txt"
            path.write_text("alice\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_book(None, path)


class CliOwnerTests(unittest.TestCase):
    def test_check_with_owners_writes_owner_summary_csv_and_fix_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            (folder / "obs.txt").write_text(observation(), encoding="utf-8")
            (folder / "owners.csv").write_text(owners_csv(), encoding="utf-8")
            (folder / "leavers.txt").write_text("# gone\nAlice Chen\n", encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                code = main(["check", "--observation", str(folder / "obs.txt"), "--owners", str(folder / "owners.csv"),
                             "--leavers", str(folder / "leavers.txt"), "--output", str(folder / "r.json"),
                             "--csv", str(folder / "r.csv"), "--fix-plan", str(folder / "fix.yml"), "--color", "never"])
            self.assertEqual(code, 1)
            self.assertIn("who has access", out.getvalue())
            self.assertIn("Alice Chen  LEFT", out.getvalue())
            report = json.loads((folder / "r.json").read_text(encoding="utf-8"))
            self.assertEqual(report["owners"][0]["owner"], "Alice Chen")
            self.assertIn("owner", (folder / "r.csv").read_text(encoding="utf-8").splitlines()[0])
            plan = (folder / "fix.yml").read_text(encoding="utf-8")
            self.assertIn(FP["alice"], plan)
            self.assertNotIn(FP["ops"] + ":", plan)
            self.assertNotIn(KEYS["alice"].split()[1], plan)


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.report = run_check({"target": "lab", "allowText": "\n".join(ui_lab.LAB_PUSH),
                                 "ownersText": ui_lab.LAB_OWNERS, "leaversText": ui_lab.LAB_LEAVERS})["report"]
        self.rows = [row for host in self.report["hosts"] for row in host["keys"]]

    def decisions(self):
        return [{"host": r["host"], "account": r["account"], "fingerprint": r["fingerprint"],
                 "decision": "revoke" if r.get("ownerLeft") else "approve", "note": "x\ny"} for r in self.rows]

    def test_record_is_sealed_and_detects_edits(self):
        record = build_record(self.report, {"name": "Dana Ortiz", "role": "Security lead"}, self.decisions())
        check_record(record)
        self.assertEqual(record["summary"]["undecided"], 0)
        self.assertEqual(record["summary"]["revoked"], sum(1 for r in self.rows if r.get("ownerLeft")))
        self.assertEqual(record["decisions"][0]["note"], "x y")
        self.assertIn("Dana Ortiz", render_html(record))
        record["decisions"][0]["decision"] = "approve" if record["decisions"][0]["decision"] == "revoke" else "revoke"
        with self.assertRaises(ValueError):
            check_record(record)

    def test_decisions_must_match_the_report(self):
        with self.assertRaises(ValueError):
            build_record(self.report, {"name": "x"}, [{"host": "nope", "account": "a", "fingerprint": FP["ops"], "decision": "approve"}])
        with self.assertRaises(ValueError):
            build_record(self.report, {"name": ""}, [])
        bad = self.decisions()[:1]
        bad[0]["decision"] = "maybe"
        with self.assertRaises(ValueError):
            build_record(self.report, {"name": "x"}, bad)

    def test_gui_endpoints(self):
        data = run_review({"report": self.report, "reviewer": {"name": "Dana"}, "decisions": self.decisions()})
        check_record(data["record"])
        plan = run_fixplan({"report": self.report, "decisions": self.decisions()})
        self.assertGreater(plan["count"], 0)
        self.assertIn("keywarden_remover", plan["playbook"])

    @unittest.skipUnless(HAS_SSH_KEYGEN and os.name == "posix", "ssh-keygen -Y needed")
    def test_sign_and_verify(self):
        from keywarden import review

        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            record = build_record(self.report, {"name": "Dana"}, self.decisions())
            path = folder / "review.json"
            path.write_text(json.dumps(record), encoding="utf-8")
            key = folder / "id"
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
            with redirect_stderr(io.StringIO()):
                review.sign(path, key)
            signers = folder / "allowed"
            signers.write_text(f'Dana namespaces="keywarden-review" {key.with_suffix(".pub").read_text().strip()}\n', encoding="utf-8")
            self.assertIn("verified", review.verify(path, signers, None))
            with self.assertRaises(ValueError):
                review.verify(path, signers, "Somebody Else")


class FixPlanTests(unittest.TestCase):
    def test_names_are_checked_before_they_go_in_a_playbook(self):
        doc = {"hosts": [{"name": "web", "keys": [{"host": "web;rm", "account": "ops", "fingerprint": FP["ops"], "ownerLeft": True}]}]}
        with self.assertRaises(ValueError):
            removals(doc, {"leaver"})
        self.assertEqual(render_playbook([], generated="t", version="v").count("nothing to remove"), 1)

    @unittest.skipUnless(HAS_SSH_KEYGEN and os.name == "posix" and shutil.which("sh"), "sh and ssh-keygen needed")
    def test_remover_script_dry_runs_then_removes_by_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / ".ssh").mkdir()
            keyfile = home / ".ssh" / "authorized_keys"
            original = f"# team keys\n{KEYS['ops']}\nrestrict,from=\"10.0.0.1\" {KEYS['alice']}\n\n"
            keyfile.write_text(original, encoding="utf-8")
            script = REMOVER.replace('file="$home/.ssh/authorized_keys"', f'file="{keyfile}"')
            run = lambda apply: subprocess.run(  # noqa: E731
                ["sh", "-c", script, "keywarden-remove", "root", FP["alice"]],
                capture_output=True, text=True, env={**os.environ, "KEYWARDEN_APPLY": apply}, check=True,
            )
            self.assertIn("would-remove=1", run("0").stdout)
            self.assertEqual(keyfile.read_text(encoding="utf-8"), original)
            self.assertIn("removed=1", run("1").stdout)
            left = keyfile.read_text(encoding="utf-8")
            self.assertIn(KEYS["ops"], left)
            self.assertIn("# team keys", left)
            self.assertNotIn(KEYS["alice"].split()[1], left)
            self.assertEqual(len(list((home / ".ssh").glob("authorized_keys.keywarden-*"))), 1)


class NotifyTests(unittest.TestCase):
    DOC = {"version": "x", "hosts": [{"name": "web-01", "posture": "fail", "findings": [
        {"code": "outside-push", "severity": "fail", "title": "A key is not in the push", "drift": "new-keys", "newFingerprints": [FP["alice"]]},
        {"code": "permit-root", "severity": "pass", "title": "ok"},
    ]}]}

    def test_urls_and_formats(self):
        with self.assertRaises(ValueError):
            check_url("http://hooks.example.com/x")
        check_url("http://127.0.0.1:9000/x")
        self.assertEqual(guess_format("https://hooks.slack.com/services/x"), "slack")
        self.assertEqual(guess_format("https://discord.com/api/webhooks/1/x"), "discord")
        self.assertEqual(guess_format("https://prod-1.westus.logic.azure.com/workflows/x"), "teams")
        self.assertIn(FP["alice"], payload(self.DOC, "slack", "drift")["text"])
        self.assertEqual(payload(self.DOC, "teams", "drift")["attachments"][0]["content"]["type"], "AdaptiveCard")

    def test_sends_only_when_asked(self):
        quiet = {"hosts": [{"name": "a", "findings": [{"code": "x", "severity": "fail", "title": "t"}]}]}
        self.assertFalse(should_send(quiet, "drift"))
        self.assertTrue(should_send(quiet, "fail"))
        sent = []

        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def opener(request, timeout):
            sent.append(json.loads(request.data))
            return Response()

        self.assertTrue(send("https://hooks.slack.com/services/x", self.DOC, opener=opener))
        self.assertFalse(send("https://hooks.slack.com/services/x", quiet, opener=opener))
        self.assertEqual(len(sent), 1)
        self.assertNotIn("AAAA", json.dumps(sent))


class CertificateAndPathTests(unittest.TestCase):
    def test_protocol_4_reads_trusted_cas_and_refuses_unprefixed_lines(self):
        host = parse_protocol(observation(f"TRUSTEDCA ok\nK {KEYS['ci']}\nENDTRUSTEDCA\nHOSTCERT none\nENDHOSTCERT\n").replace("KEYWARDEN 3", "KEYWARDEN 4")
                              .replace("trustedusercakeys none", "trustedusercakeys /etc/ssh/ca.pub"))
        self.assertEqual([key.fingerprint for key in host.trusted_cas], [FP["ci"]])
        found = codes(evaluate(host, [], Policy(allowed_cas=frozenset({FP["ci"]}))))
        self.assertEqual(found["trusted-user-ca"].severity, "pass")
        found = codes(evaluate(host, [], Policy(allowed_cas=frozenset({FP["ops"]}))))
        self.assertEqual(found["trusted-user-ca"].severity, "fail")
        with self.assertRaises(ProtocolError):
            parse_protocol(observation(f"TRUSTEDCA ok\n{KEYS['ci']}\nENDTRUSTEDCA\n"))

    @unittest.skipUnless(HAS_SSH_KEYGEN, "ssh-keygen needed")
    def test_long_lived_user_cert_and_expiring_host_cert(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            for name in ("ca", "user", "hostkey"):
                subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(folder / name)], check=True)
            subprocess.run(["ssh-keygen", "-q", "-s", str(folder / "ca"), "-I", "u", "-n", "ops", "-V", "-1d:+400d", str(folder / "user.pub")], check=True)
            subprocess.run(["ssh-keygen", "-q", "-s", str(folder / "ca"), "-I", "h", "-h", "-n", "web-01", "-V", "-1d:+3d", str(folder / "hostkey.pub")], check=True)
            user_cert = (folder / "user-cert.pub").read_text(encoding="utf-8").strip()
            host_cert = (folder / "hostkey-cert.pub").read_text(encoding="utf-8").strip()
            ca_fp = parse_public_keys((folder / "ca.pub").read_text(encoding="utf-8"))[0][0].fingerprint
        text = observation(f"HOSTCERT ok\nK {host_cert}\nENDHOSTCERT\n").replace("KEYWARDEN 3", "KEYWARDEN 4")
        text = text.replace(f"K {KEYS['contractor']}", f"K {user_cert}")
        text = text.replace("trustedusercakeys none", "trustedusercakeys none\nhostcertificate /etc/ssh/h-cert.pub")
        host = parse_protocol(text)
        found = codes(evaluate(host, [], Policy(allowed_cas=frozenset({ca_fp}))))
        self.assertEqual(found["ssh-certificate"].severity, "warn")
        self.assertIn("valid for 401 days", found["ssh-certificate"].detail)
        self.assertEqual(found["host-certificate"].severity, "warn")
        self.assertIn("expires in", found["host-certificate"].detail)
        found = codes(evaluate(host, [], Policy(allowed_cas=frozenset({FP["ops"]}))))
        self.assertEqual(found["ssh-certificate"].severity, "fail")
        self.assertEqual(found["host-certificate"].severity, "fail")

    def test_jump_hosts_from_inventory_args(self):
        self.assertEqual(jump_from_args("-J ops@bastion:2222"), "ops@bastion:2222")
        self.assertEqual(jump_from_args("-o ProxyJump=a,b"), "a,b")
        self.assertEqual(jump_from_args('-o ProxyCommand="ssh -W %h:%p -q ops@bastion"'), "ops@bastion")
        self.assertIsNone(jump_from_args("-o ProxyCommand=nc -X 5 proxy %h %p"))
        self.assertIsNone(jump_from_args("-J ;rm"))
        hosts = parse_inventory('web ansible_user=ops ansible_ssh_common_args="-o ProxyCommand=\\"ssh -W %h:%p -q ops@bastion\\""\ndb\n')
        self.assertEqual([h.jump for h in hosts], ["ops@bastion", None])

    def test_jump_is_passed_to_ssh_and_reported(self):
        with patch("keywarden.collect.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, observation().encode(), b"")
            collect_remote("ops@web-01", jump="ops@bastion")
            command = run.call_args.args[0]
        self.assertEqual(command[command.index("-J") + 1], "ops@bastion")
        with self.assertRaises(ValueError):
            collect_remote("ops@web-01", jump="-oProxyCommand=x")
        self.assertEqual(access_path("ops@web-01", None, "b"), {"via": "b", "source": "inventory"})
        with patch("keywarden.collect.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, "hostname web\nproxyjump ops@bastion\n", "")
            self.assertEqual(access_path("ops@web-01"), {"via": "ops@bastion", "source": "ssh config"})
            run.return_value = subprocess.CompletedProcess([], 0, "hostname web\nproxycommand none\n", "")
            self.assertEqual(access_path("ops@web-01")["source"], "direct")
        host = parse_protocol(observation())
        host.access_path = {"via": None, "source": "direct"}
        self.assertEqual(codes(evaluate(host, [], Policy(require_jump=True)))["jump-host"].severity, "fail")
        self.assertNotIn("jump-host", codes(evaluate(host, [], Policy())))


class FleetPriorTests(unittest.TestCase):
    def test_inventory_runs_take_a_fleet_prior(self):
        from keywarden.cli import prior_from_document

        doc = {"hosts": [{"name": "web-01", "findings": [{"code": "outside-push", "severity": "pass"}]}]}
        self.assertEqual(prior_from_document(doc, "web-01"), {"outside-push": ("pass", set())})
        with redirect_stderr(io.StringIO()):
            self.assertIsNone(prior_from_document(doc, "db-01"))


class MacLogTimeTests(unittest.TestCase):
    def test_unified_log_timestamp(self):
        self.assertEqual(parse_log_time("2026-11-17 10:00:00.123456-0800  host sshd-session[1]: x", None, "+0000"), 1794938400)


if __name__ == "__main__":
    unittest.main()
