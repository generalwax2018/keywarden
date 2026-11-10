import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from keywarden.check import Account, HostObservation, Policy, SshdFacts, evaluate, worst  # noqa: E402
from keywarden.cli import main  # noqa: E402
from keywarden.collect import inspect_account, parse_protocol  # noqa: E402
from keywarden.parse import PrivateKeyError, parse_public_keys  # noqa: E402

OPS = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGiUj+g3GBj1La4DirE3b9XJ6gMvxVIYk69JX0EnCEBI ops@latch"
ROOT_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJtKKj9UmCH8MVh3X1kXxTZFn5Ao6oCiJxst6OwEG1T+ root@app-web-03"
LEGACY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDRouExOk2eo1194WTx6G9L/8XqnM49I5JXWGf3lwLRPRRoxADdDzuh43QV16yM3c5jTrxrmR0T9UIjtCl58/wszMKOxaDvFFDRVxCNrb3u1suEF5FXwRzxpGtB8nYz2hxvEKmT/Ds/optfoy43bE8Q64gzYgpLTHowKGbrZhZ1FbuYdzmd9p82y0cSjzt9hkrv+XQxrPj5J+COXw6XdQnVKpe/lU78VyVAP0GIIVh9lQjah3zqpdurRtX+WkR/xscp/nXjj6ap4cVRuDMOiCbVGSBoDzhELuDZlvgXZ6hWnDUAf81+twGW7AQ7Wl3i+PtBsfs8LzwvWkbJ8w2lQLtF legacy-jump"

TIGHT = """KEYWARDEN 1
HOST bastion-01
SSHD
permitrootlogin no
passwordauthentication no
kbdinteractiveauthentication no
pubkeyauthentication yes
permitemptypasswords no
ENDSSHD
ACCOUNT ops
DIR 700
FILE 600
STATE ok
KEYS
{ops}
ENDKEYS
ACCOUNT root
DIR absent
FILE absent
STATE absent
KEYS
ENDKEYS
END
"""


def _codes(findings):
    return {item.code: item.severity for item in findings}


class ParseTests(unittest.TestCase):
    def test_fingerprint_matches_openssh(self):
        keys, issues = parse_public_keys(OPS)
        self.assertEqual(issues, [])
        self.assertEqual(len(keys), 1)
        completed = subprocess.run(
            ["ssh-keygen", "-lf", "-"],
            input=OPS + "\n",
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            self.skipTest("ssh-keygen unavailable")
        self.assertIn(keys[0].fingerprint, completed.stdout)

    def test_options_prefix_and_weak_rsa(self):
        line = 'restrict,command="/bin/true" ' + LEGACY
        keys, issues = parse_public_keys(line, user="jump")
        self.assertEqual(issues, [])
        self.assertEqual(keys[0].kind, "rsa")
        self.assertIsNotNone(keys[0].bits)
        self.assertLess(keys[0].bits, 3072)
        self.assertEqual(keys[0].comment, "legacy-jump")

    def test_private_key_is_refused(self):
        with self.assertRaises(PrivateKeyError):
            parse_public_keys("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")


class CheckTests(unittest.TestCase):
    def test_clean_host_passes(self):
        host = parse_protocol(TIGHT.format(ops=OPS))
        push, _ = parse_public_keys(OPS)
        findings = evaluate(host, push, Policy())
        self.assertEqual(worst(findings), "pass")
        self.assertEqual(_codes(findings)["root-authorized-key"], "pass")
        self.assertEqual(_codes(findings)["permit-root"], "pass")

    def test_root_key_and_prohibit_password_fail(self):
        text = TIGHT.format(ops=OPS).replace("permitrootlogin no", "permitrootlogin prohibit-password")
        text = text.replace("STATE absent\nKEYS\nENDKEYS", "STATE ok\nKEYS\n" + ROOT_KEY + "\nENDKEYS")
        host = parse_protocol(text)
        push, _ = parse_public_keys(OPS)
        findings = evaluate(host, push, Policy())
        codes = _codes(findings)
        self.assertEqual(codes["permit-root"], "fail")
        self.assertEqual(codes["root-authorized-key"], "fail")
        blob = ROOT_KEY.split()[1]
        encoded = json.dumps([item.as_dict() for item in findings])
        root_fp = parse_public_keys(ROOT_KEY)[0][0].fingerprint
        self.assertNotIn(blob, encoded)
        self.assertIn(root_fp, encoded)

    def test_without_password_is_still_root_login(self):
        host = parse_protocol(TIGHT.format(ops=OPS).replace("permitrootlogin no", "permitrootlogin without-password"))
        findings = evaluate(host, [], Policy())
        self.assertEqual(_codes(findings)["permit-root"], "fail")

    def test_unreadable_root_is_not_a_pass(self):
        host = HostObservation(
            name="box",
            address="local",
            role="local",
            observed_at="now",
            sshd=SshdFacts("no", "no", "no", "yes", "no"),
            accounts=[
                Account("root", "unknown", "unknown", [], "unreadable"),
                Account("ops", "700", "600", parse_public_keys(OPS, "ops")[0], "ok"),
            ],
        )
        findings = evaluate(host, parse_public_keys(OPS)[0], Policy())
        self.assertEqual(_codes(findings)["root-authorized-key"], "warn")
        self.assertNotEqual(worst(findings), "fail")

    def test_loose_permissions_and_stray_key(self):
        text = TIGHT.format(ops=OPS + "\n" + LEGACY).replace("FILE 600", "FILE 644")
        host = parse_protocol(text)
        findings = evaluate(host, parse_public_keys(OPS)[0], Policy())
        codes = _codes(findings)
        self.assertEqual(codes["permissions"], "fail")
        self.assertEqual(codes["weak-algorithm"], "fail")
        self.assertEqual(codes["outside-push"], "fail")


class LocalReadTests(unittest.TestCase):
    def test_missing_file_is_absent_and_unreadable_home_is_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "ops"
            ssh_dir = home / ".ssh"
            ssh_dir.mkdir(parents=True)
            (ssh_dir / "authorized_keys").write_text(OPS + "\n", encoding="utf-8")
            ssh_dir.chmod(0o700)
            (ssh_dir / "authorized_keys").chmod(0o600)
            account = inspect_account("ops", home)
            self.assertEqual(account.read_state, "ok")
            self.assertEqual(len(account.keys), 1)
            self.assertNotIn("AAAAC3NzaC1lZDI1NTE5AAAAIGiUj", json.dumps(account.keys[0].public()))

            locked = Path(tmp) / "rootish"
            locked.mkdir()
            locked.chmod(0o000)
            try:
                if os.geteuid() == 0:
                    hidden = inspect_account("root", locked)
                    self.assertIn(hidden.read_state, {"unreadable", "absent"})
                else:
                    hidden = inspect_account("root", locked)
                    self.assertEqual(hidden.read_state, "unreadable")
            finally:
                locked.chmod(0o700)

    def test_permission_denied_is_not_an_empty_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "root"
            home.mkdir()
            real = Path.lstat

            def denied(self):
                if self == home or home in self.parents:
                    raise PermissionError("denied")
                return real(self)

            with patch.object(Path, "lstat", denied):
                hidden = inspect_account("root", home)
            self.assertEqual(hidden.read_state, "unreadable")
            self.assertEqual(hidden.keys, [])


class CliTests(unittest.TestCase):
    def test_cli_report_omits_key_and_fails_closed_on_private_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            observation = folder / "obs.txt"
            observation.write_text(TIGHT.format(ops=OPS), encoding="utf-8")
            allow = folder / "team.pub"
            allow.write_text(OPS + "\n", encoding="utf-8")
            report = folder / "report.json"
            code = main(["check", "--observation", str(observation), "--allow", str(allow), "--output", str(report), "--json"])
            self.assertEqual(code, 0)
            body = report.read_text(encoding="utf-8")
            self.assertNotIn(OPS.split()[1], body)
            self.assertEqual(json.loads(body)["keyMaterial"], "omitted")
            self.assertEqual(json.loads(body)["host"]["posture"], "pass")

            private = folder / "nope.pub"
            private.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n", encoding="utf-8")
            leaked = folder / "should-not-exist.json"
            code = main(["check", "--observation", str(observation), "--allow", str(private), "--output", str(leaked)])
            self.assertEqual(code, 2)
            self.assertFalse(leaked.exists())


if __name__ == "__main__":
    unittest.main()
