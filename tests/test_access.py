import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import date, datetime, timezone
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from keywarden.access import (  # noqa: E402
    Reach,
    classify_sudo,
    key_rows,
    parse_log_time,
    parse_login_lines,
    reach_of,
)
from keywarden.check import Account, Finding, Policy, evaluate  # noqa: E402
from keywarden.cli import main  # noqa: E402
from keywarden.collect import REMOTE_SCRIPT, ProtocolError, _aggregate_logins, parse_protocol  # noqa: E402
from keywarden.parse import parse_options, parse_public_keys, summarize_options  # noqa: E402
from keywarden.waivers import apply_waivers, load_waivers  # noqa: E402

OPS = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGiUj+g3GBj1La4DirE3b9XJ6gMvxVIYk69JX0EnCEBI ops@latch"
DEPLOY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHoZ4DW0qqL47zxp9vN442Zu2f6a5fPe62aKE6GDtKUn deploy@ci"
OPS_FP = parse_public_keys(OPS)[0][0].fingerprint
DEPLOY_FP = parse_public_keys(DEPLOY)[0][0].fingerprint
NOW = int(datetime(2026, 11, 10, 18, 0, tzinfo=timezone.utc).timestamp())
DAY = 86400


def observation(*, ops_line=OPS, deploy_line=DEPLOY, sudo_ops=None, groups_deploy="deploy", logins=(), first=None, source="journal"):
    sudo_ops = sudo_ops or ["User ops may run the following commands on web:", "    (ALL : ALL) NOPASSWD: ALL"]
    lines = [
        "KEYWARDEN 3",
        "HOST web-01",
        f"NOW {NOW} +0000",
        "PRIV root",
        "SSHDRUN ok",
        "SSHD",
        "permitrootlogin no",
        "passwordauthentication no",
        "loglevel INFO",
        "allowtcpforwarding yes",
        "allowagentforwarding yes",
        "permituserenvironment no",
        "ENDSSHD",
        "MATCH no",
        "SSHDROOT",
        "ENDSSHDROOT",
        f"AUTHLOG {source}",
        "LOGINS",
    ]
    if first is not None:
        lines.append(f"AUTHFIRST {first}")
    lines.extend("L " + row for row in logins)
    lines += [
        "ENDLOGINS",
        "ACCOUNT root",
        "UID 0",
        "LOCKED yes",
        "DIR 700",
        "FILE absent",
        "STATE absent",
        "KEYS",
        "ENDKEYS",
        "ACCOUNT ops",
        "UID 1000",
        "GROUPS ops",
        "SUDOSTATE ok",
        "SUDO",
        *("S " + line for line in sudo_ops),
        "ENDSUDO",
        "DIR 700",
        "FILE 600",
        "STATE ok",
        "KEYS",
        "K " + ops_line,
        "ENDKEYS",
        "ACCOUNT deploy",
        "UID 1001",
        f"GROUPS {groups_deploy}",
        "SUDOSTATE ok",
        "SUDO",
        "S User deploy is not allowed to run sudo on web.",
        "ENDSUDO",
        "DIR 700",
        "FILE 600",
        "STATE ok",
        "KEYS",
        "K " + deploy_line,
        "ENDKEYS",
        "PASSWD ok",
        "END",
    ]
    return "\n".join(lines) + "\n"


def accepted(user, fp, when, source="10.0.0.5", count=1):
    stamp = f"{when}.000000"
    return f"{count} {stamp} web-01 sshd[1]: Accepted publickey for {user} from {source} port 50000 ssh2: ED25519 {fp}"


def codes(findings):
    return {item.code: item.severity for item in findings}


class OptionTests(unittest.TestCase):
    def test_quoted_values_with_commas_and_restrict(self):
        options = summarize_options(parse_options('from="10.0.0.0/8,!10.9.9.9",command="echo a,b",restrict,port-forwarding'))
        self.assertEqual(options.source, ("10.0.0.0/8", "!10.9.9.9"))
        self.assertTrue(options.forced_command)
        self.assertTrue(options.restricted)
        self.assertEqual(options.allows, frozenset({"port"}))

    def test_command_text_is_never_reported(self):
        keys, _ = parse_public_keys('command="/usr/bin/backup --token=s3cret" ' + DEPLOY)
        self.assertNotIn("s3cret", json.dumps(keys[0].options.public()))
        self.assertTrue(keys[0].options.public()["command"])

    def test_expiry_time(self):
        options = summarize_options(parse_options('expiry-time="20200101Z"'))
        self.assertEqual(options.expires, int(datetime(2020, 1, 1, tzinfo=timezone.utc).timestamp()))
        self.assertTrue(summarize_options(parse_options('expiry-time="soon"')).expiry_unreadable)


class SudoTests(unittest.TestCase):
    def test_classification(self):
        header = "User u may run the following commands on h:"
        self.assertEqual(classify_sudo([header, "    (ALL) NOPASSWD: ALL"]).level, "root-nopasswd")
        self.assertEqual(classify_sudo([header, "    (ALL : ALL) ALL"]).level, "root-password")
        self.assertEqual(classify_sudo([header, "    (root) NOPASSWD: /usr/bin/vim /etc/hosts"]).level, "root-nopasswd")
        self.assertEqual(classify_sudo([header, "    (root) NOPASSWD: /usr/bin/uptime"]).level, "limited")
        self.assertEqual(classify_sudo([header, "    (postgres) NOPASSWD: ALL"]).level, "limited")
        self.assertEqual(classify_sudo(["User u is not allowed to run sudo on h."]).level, "none")
        self.assertIsNone(classify_sudo(["sudo: a password is required"]))

    def test_root_equivalent_group_without_sudo(self):
        account = Account("deploy", "700", "600", [], "ok", 1001, groups=["deploy", "docker"], sudo_state="ok",
                          sudo_lines=["User deploy is not allowed to run sudo on web."])
        self.assertEqual(reach_of(account), Reach("root-nopasswd", "member of docker, which is root-equivalent"))

    def test_findings_rank_a_root_reaching_key(self):
        host = parse_protocol(observation(groups_deploy="deploy docker"))
        found = codes(evaluate(host, [], Policy()))
        self.assertEqual(found["key-to-root"], "warn")
        self.assertEqual(found["key-source"], "warn")
        restricted = parse_protocol(observation(ops_line='from="10.0.0.0/8" ' + OPS))
        self.assertEqual(codes(evaluate(restricted, [], Policy()))["key-source"], "pass")


class LogTests(unittest.TestCase):
    def test_timestamp_formats(self):
        self.assertEqual(parse_log_time("1731234567.5 host sshd[1]: x", NOW, "+0000"), 1731234567)
        self.assertEqual(
            parse_log_time("2026-11-01T10:00:00.123456-07:00 host sshd[1]: x", NOW, "+0000"),
            int(datetime(2026, 11, 1, 17, 0, tzinfo=timezone.utc).timestamp()),
        )
        self.assertEqual(
            parse_log_time("Nov  9 10:00:00 host sshd[1]: x", NOW, "+0000"),
            int(datetime(2026, 11, 9, 10, 0, tzinfo=timezone.utc).timestamp()),
        )
        # December seen in November is last year: syslog has no year.
        self.assertEqual(
            parse_log_time("Dec 31 23:00:00 host sshd[1]: x", NOW, "+0000"),
            int(datetime(2025, 12, 31, 23, 0, tzinfo=timezone.utc).timestamp()),
        )
        self.assertEqual(parse_log_time("Jun 1 09:00:00", NOW, "+0000"), int(datetime(2026, 6, 1, 9, tzinfo=timezone.utc).timestamp()))

    def test_certificate_logins_count_for_the_ca_line(self):
        line = (f"1 {NOW - DAY}.0 h sshd[1]: Accepted publickey for ops from 10.0.0.5 port 1 ssh2: "
                f"ED25519-CERT SHA256:abc ID ops (serial 1) CA ED25519 {OPS_FP}")
        logins = parse_login_lines([line], NOW, "+0000")
        self.assertIn(("ops", "CA:" + OPS_FP), logins)

    def test_stale_fresh_and_short_logs(self):
        fresh = accepted("ops", OPS_FP, NOW - 3 * DAY)
        old = accepted("deploy", DEPLOY_FP, NOW - 200 * DAY)
        host = parse_protocol(observation(logins=[fresh, old], first=f"{NOW - 365 * DAY}.0"))
        findings = evaluate(host, [], Policy())
        stale = next(item for item in findings if item.code == "stale-key")
        self.assertEqual(stale.severity, "fail")
        self.assertIn(DEPLOY_FP, stale.detail)
        self.assertNotIn(OPS_FP, stale.detail)
        rows = {row["account"]: row for row in key_rows(host, [], Policy())}
        self.assertEqual(rows["ops"]["usage"], "fresh")
        self.assertEqual(rows["ops"]["lastFrom"], "10.0.0.5")
        self.assertEqual(rows["deploy"]["usage"], "stale")

        short = parse_protocol(observation(logins=[fresh], first=f"{NOW - 10 * DAY}.0"))
        self.assertEqual(codes(evaluate(short, [], Policy()))["stale-key"], "warn")
        self.assertEqual(codes(evaluate(short, [], Policy(stale_days=5)))["stale-key"], "fail")

    def test_unreadable_logs_skip_stale_key(self):
        host = parse_protocol(observation(source="unreadable"))
        found = codes(evaluate(host, [], Policy()))
        self.assertEqual(found["auth-log"], "warn")
        self.assertNotIn("stale-key", found)

    def test_quiet_log_level_fails(self):
        host = parse_protocol(observation().replace("loglevel INFO", "loglevel QUIET"))
        self.assertEqual(codes(evaluate(host, [], Policy()))["log-level"], "fail")

    def test_log_rows_without_a_prefix_are_refused(self):
        bad = observation(logins=[accepted("ops", OPS_FP, NOW)]).replace("ENDLOGINS", "Accepted publickey for x\nENDLOGINS")
        with self.assertRaises(ProtocolError):
            parse_protocol(bad)

    @unittest.skipUnless(shutil.which("sh") and shutil.which("awk"), "sh and awk needed")
    def test_remote_awk_and_local_python_agree(self):
        start = REMOTE_SCRIPT.index("LOGAWK='") + len("LOGAWK='")
        program = REMOTE_SCRIPT[start: REMOTE_SCRIPT.index("'\n", start)]
        sample = "\n".join(
            [
                "Jun  1 09:00:00 h sshd[1]: Server listening on 0.0.0.0 port 22.",
                f"Jun  1 09:15:00 h sshd[2]: Accepted publickey for ops from 10.0.0.5 port 1 ssh2: ED25519 {OPS_FP}",
                f"Jun  2 09:15:00 h sshd[3]: Accepted publickey for ops from 10.0.0.6 port 1 ssh2: ED25519 {OPS_FP}",
                f"Jun  3 09:15:00 h sshd[4]: Accepted publickey for deploy from 10.0.0.7 port 1 ssh2: ED25519 {DEPLOY_FP}",
            ]
        ) + "\n"
        completed = subprocess.run(["awk", program], input=sample, capture_output=True, text=True, check=True)
        awk_rows = sorted(line[2:] for line in completed.stdout.splitlines() if line.startswith("L "))
        first_awk = next(line[10:] for line in completed.stdout.splitlines() if line.startswith("AUTHFIRST "))
        first_py, py_rows = _aggregate_logins(sample.splitlines())
        self.assertEqual(awk_rows, sorted(py_rows))
        self.assertEqual(first_awk, first_py)


class WaiverTests(unittest.TestCase):
    def _file(self, folder: Path, entries) -> Path:
        path = folder / "waivers.json"
        path.write_text(json.dumps({"waivers": entries}), encoding="utf-8")
        return path

    def test_expiry_and_owner_are_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                load_waivers(self._file(Path(tmp), [{"code": "permit-root", "reason": "x", "owner": "me"}]))
            with self.assertRaises(ValueError):
                load_waivers(self._file(Path(tmp), [{"code": "permit-root", "reason": "x", "expires": "2027-01-01"}]))

    def test_accept_partial_and_expired(self):
        with tempfile.TemporaryDirectory() as tmp:
            waivers = load_waivers(
                self._file(
                    Path(tmp),
                    [
                        {"code": "permit-root", "host": "web-*", "reason": "migration", "ticket": "SEC-1", "expires": "2027-01-01"},
                        {"code": "stale-key", "fingerprint": OPS_FP, "reason": "break glass", "owner": "secops", "expires": "2027-01-01"},
                        {"code": "auth-methods", "reason": "old", "ticket": "SEC-3", "expires": "2026-01-01"},
                    ],
                )
            )
        findings = [
            Finding("permit-root", "fail", "t", "PermitRootLogin is yes."),
            Finding("stale-key", "fail", "t", f"ops · {OPS_FP}; deploy · {DEPLOY_FP}"),
            Finding("auth-methods", "fail", "t", "AuthenticationMethods is any."),
        ]
        used: set[int] = set()
        result = {item.code: item for item in apply_waivers(findings, "web-01", waivers, date(2026, 11, 10), used)}
        self.assertEqual(result["permit-root"].severity, "accepted")
        self.assertEqual(result["permit-root"].as_dict()["was"], "fail")
        self.assertEqual(result["stale-key"].severity, "fail")
        self.assertIn("the rest are not", result["stale-key"].detail)
        self.assertEqual(result["auth-methods"].severity, "fail")
        self.assertIn("expired 2026-01-01", result["auth-methods"].detail)
        self.assertEqual(used, {0, 1, 2})
        other = apply_waivers([Finding("permit-root", "fail", "t", "x")], "db-01", waivers, date(2026, 11, 10), set())
        self.assertEqual(other[0].severity, "fail")

    def test_waived_host_passes_in_the_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            obs = folder / "obs.txt"
            obs.write_text(observation(groups_deploy="deploy"), encoding="utf-8")
            waivers = self._file(
                folder,
                [{"code": "key-to-root", "reason": "ops is the admin", "owner": "secops", "expires": "2099-01-01"},
                 {"code": "key-source", "reason": "ops is the admin", "owner": "secops", "expires": "2099-01-01"},
                 {"code": "permit-root", "host": "nowhere", "reason": "x", "owner": "y", "expires": "2099-01-01"}],
            )
            report = folder / "r.json"
            stderr = StringIO()
            with redirect_stdout(StringIO()), redirect_stderr(stderr):
                main(["check", "--observation", str(obs), "--waivers", str(waivers), "--output", str(report)])
            body = json.loads(report.read_text(encoding="utf-8"))
            severities = {item["code"]: item["severity"] for item in body["host"]["findings"]}
            self.assertEqual(severities["key-to-root"], "accepted")
            self.assertIn("matched nothing", stderr.getvalue())


class AccessReviewCliTests(unittest.TestCase):
    def test_csv_table_and_formula_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            obs = folder / "obs.txt"
            hostile = OPS.rsplit(" ", 1)[0] + " =HYPERLINK(\"http://x\")"
            obs.write_text(observation(ops_line=hostile, logins=[accepted("ops", OPS_FP, NOW - DAY)], first=f"{NOW - 400 * DAY}.0"), encoding="utf-8")
            table = folder / "review.csv"
            with redirect_stdout(StringIO()):
                main(["check", "--observation", str(obs), "--csv", str(table), "--redact-addresses"])
            text = table.read_text(encoding="utf-8")
            self.assertIn("'=HYPERLINK", text)
            self.assertNotIn("10.0.0.5", text)
            self.assertNotIn(OPS.split()[1], text)
            self.assertIn("root-nopasswd", text)
            self.assertIn("stale", text)

    def test_where_finds_keys_and_logins_and_exits_like_grep(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            obs = folder / "obs.txt"
            removed = "SHA256:" + "A" * 43
            obs.write_text(observation(logins=[accepted("deploy", removed, NOW - DAY)], first=f"{NOW - 30 * DAY}.0"), encoding="utf-8")
            out = StringIO()
            with redirect_stdout(out):
                code = main(["where", OPS_FP, "--observation", str(obs), "--json"])
            self.assertEqual(code, 0)
            found = json.loads(out.getvalue())["found"]
            self.assertEqual([(hit["account"], hit["reach"]) for hit in found], [("ops", "root-nopasswd")])

            out = StringIO()
            with redirect_stdout(out):
                code = main(["where", removed, "--observation", str(obs), "--json"])
            self.assertEqual(code, 0)
            self.assertIn("not in a readable authorized_keys", out.getvalue())

            with redirect_stdout(StringIO()):
                self.assertEqual(main(["where", "SHA256:" + "B" * 43, "--observation", str(obs)]), 1)
            with redirect_stderr(StringIO()):
                self.assertEqual(main(["where", "not-a-fingerprint", "--observation", str(obs)]), 2)


if __name__ == "__main__":
    unittest.main()
