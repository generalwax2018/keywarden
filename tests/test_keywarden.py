import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
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


class InventoryTests(unittest.TestCase):
    def test_inventory_keeps_connection_fields_and_drops_secrets(self):
        from keywarden.inventory import parse_inventory

        hosts = parse_inventory(
            "\n".join(
                [
                    "[web]",
                    "app-[01:02] ansible_user=deploy ansible_ssh_pass=nope",
                    "[web:vars]",
                    "ansible_port=2222",
                    "[jump]",
                    "bastion ansible_host=10.0.0.9 ansible_user=ops",
                    "[db:children]",
                    "web",
                ]
            )
        )
        self.assertEqual([item.name for item in hosts], ["app-01", "app-02", "bastion"])
        self.assertEqual(hosts[0].destination, "deploy@app-01")
        self.assertEqual(hosts[0].port, 2222)
        self.assertEqual(hosts[2].destination, "ops@10.0.0.9")
        self.assertNotIn("nope", repr(hosts))

    def test_inventory_prints_failures_only(self):
        from keywarden.collect import parse_protocol
        from keywarden.parse import parse_public_keys

        good = TIGHT.format(ops=OPS)
        bad = TIGHT.format(ops=ROOT_KEY).replace("HOST bastion-01", "HOST app-web-03").replace(
            "permitrootlogin no", "permitrootlogin yes"
        )
        fingerprint = parse_public_keys(ROOT_KEY)[0][0].fingerprint

        def fake(destination, extra_users=None, port=None):
            if "app-web-0" in destination:
                name = "app-web-04" if "04" in destination else "app-web-03"
                return parse_protocol(bad.replace("HOST app-web-03", f"HOST {name}"), address=destination)
            if "down" in destination:
                raise RuntimeError("ssh timed out before a check could finish")
            return parse_protocol(good, address=destination)

        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            inventory = folder / "hosts.ini"
            inventory.write_text(
                "\n".join(
                    [
                        "bastion-01 ansible_user=deploy",
                        "app-web-03 ansible_user=deploy",
                        "app-web-04 ansible_user=deploy",
                        "down-01 ansible_user=deploy",
                    ]
                ),
                encoding="utf-8",
            )
            allow = folder / "team.pub"
            allow.write_text(OPS + "\n", encoding="utf-8")
            report = folder / "report.json"
            stdout = StringIO()
            with patch("keywarden.cli.collect_remote", fake):
                with redirect_stdout(stdout):
                    code = main(
                        ["check", "--inventory", str(inventory), "--allow", str(allow), "--output", str(report)]
                    )
            self.assertEqual(code, 1)
            written = report.read_text(encoding="utf-8")
            printed = stdout.getvalue()
            self.assertNotIn(OPS.split()[1], written)
            self.assertNotIn(ROOT_KEY.split()[1], written)
            self.assertIn(fingerprint, written)
            self.assertEqual(json.loads(written)["posture"], "fail")
            self.assertEqual(len(json.loads(written)["hosts"]), 4)
            self.assertEqual(json.loads(written)["fingerprints"], [fingerprint])
            self.assertEqual(printed.count(fingerprint), 1)
            self.assertIn(f"{fingerprint}  outside-push  app-web-03 app-web-04", printed)
            self.assertIn("app-web-03  permit-root", printed)
            self.assertIn("down-01  unreachable", printed)
            self.assertNotIn("bastion-01", printed)
            self.assertNotIn("PASS", printed)

    def test_one_fingerprint_on_two_accounts_is_listed_once(self):
        from keywarden.check import Account, HostObservation, Policy, SshdFacts, evaluate
        from keywarden.parse import parse_public_keys

        keys, _ = parse_public_keys(ROOT_KEY)
        allow, _ = parse_public_keys(OPS)
        host = HostObservation(
            "web",
            "x",
            "observed",
            "t",
            SshdFacts("no", "no", "no", "yes", "no"),
            [
                Account("ops", "700", "600", keys, "ok"),
                Account("deploy", "700", "600", keys, "ok"),
            ],
        )
        findings = evaluate(host, allow, Policy())
        outside = next(item for item in findings if item.code == "outside-push")
        self.assertEqual(outside.detail.count(keys[0].fingerprint), 1)
        self.assertIn("ops, deploy", outside.detail)
        self.assertIn("A key is not in the push", outside.title)


class RootAccountTests(unittest.TestCase):
    def _with_passwd(self, body: str) -> str:
        return TIGHT.format(ops=OPS).replace("ENDSSHD\n", "ENDSSHD\n" + body, 1)

    def test_observation_without_passwd_does_not_invent_a_result(self):
        host = parse_protocol(TIGHT.format(ops=OPS))
        self.assertNotIn("root-account", _codes(evaluate(host, [], Policy())))

    def test_second_uid_zero_fails_even_without_a_key(self):
        text = self._with_passwd(
            "\n".join(
                [
                    "PASSWD ok",
                    "ACCOUNT toor",
                    "UID 0",
                    "LOCKED yes",
                    "DIR absent",
                    "FILE absent",
                    "STATE absent",
                    "KEYS",
                    "ENDKEYS",
                    "",
                ]
            )
        )
        host = parse_protocol(text)
        self.assertEqual(host.passwd_state, "ok")
        self.assertEqual(_codes(evaluate(host, [], Policy()))["root-account"], "fail")

    def test_only_root_passes_and_an_empty_password_fails(self):
        clean = self._with_passwd("PASSWD ok\nACCOUNT root\nUID 0\nLOCKED yes\n")
        # The fixture already has an ACCOUNT root block; a second one is the same user.
        host = parse_protocol(clean)
        root = next(account for account in host.accounts if account.user == "root" and account.uid == 0)
        self.assertEqual(root.uid, 0)
        self.assertEqual(_codes(evaluate(host, [], Policy()))["root-account"], "pass")

        empty = self._with_passwd("PASSWD ok\n")
        parsed = parse_protocol(empty)
        for account in parsed.accounts:
            if account.user == "root":
                account.password_locked = False
                account.uid = 0
        self.assertEqual(_codes(evaluate(parsed, [], Policy()))["root-account"], "fail")


class CertificateTests(unittest.TestCase):
    def _signed(self, folder: Path, validity: str, host: bool = False, name: str = "user") -> tuple[str, str]:
        ca = folder / f"{name}-ca"
        user = folder / name
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-f", str(ca), "-N", ""], check=True)
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-f", str(user), "-N", ""], check=True)
        command = ["ssh-keygen", "-q", "-s", str(ca), "-I", name, "-n", "ops", "-V", validity]
        if host:
            command.append("-h")
        command.append(str(user) + ".pub")
        subprocess.run(command, check=True)
        cert = (folder / f"{name}-cert.pub").read_text(encoding="utf-8").strip()
        ca_pub = ca.with_suffix(".pub").read_text(encoding="utf-8").strip()
        for private in (ca, user):
            private.unlink(missing_ok=True)
        return cert, ca_pub

    def test_certificate_matches_ca_and_is_not_stored(self):
        with tempfile.TemporaryDirectory() as tmp:
            cert, ca_pub = self._signed(Path(tmp), "+1d")
            keys, issues = parse_public_keys(cert, user="ops")
            ca_keys, _ = parse_public_keys(ca_pub)
            self.assertEqual(issues, [])
            self.assertIsNotNone(keys[0].cert)
            self.assertEqual(keys[0].cert.cert_type, "user")
            self.assertEqual(keys[0].cert.ca_fingerprint, ca_keys[0].fingerprint)
            self.assertFalse(keys[0].cert_authority)
            blob = cert.split()[1]
            self.assertNotIn(blob, json.dumps(keys[0].public()))
            host = parse_protocol(TIGHT.format(ops=cert))
            findings = evaluate(host, keys, Policy())
            self.assertEqual(_codes(findings)["ssh-certificate"], "pass")

    def test_expired_host_and_authority_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            expired, _ca = self._signed(folder, "-5d:-1d", name="expired")
            host = parse_protocol(TIGHT.format(ops=expired))
            self.assertEqual(_codes(evaluate(host, [], Policy()))["ssh-certificate"], "fail")
            host_cert, _ca = self._signed(folder, "+1d", host=True, name="hostcert")
            observed = parse_protocol(TIGHT.format(ops=host_cert))
            self.assertEqual(_codes(evaluate(observed, [], Policy()))["ssh-certificate"], "fail")
            plain, _ = parse_public_keys(OPS)
            marked = "cert-authority " + OPS
            flagged, _ = parse_public_keys(marked)
            self.assertTrue(flagged[0].cert_authority)
            account_host = parse_protocol(TIGHT.format(ops=marked))
            self.assertEqual(_codes(evaluate(account_host, plain, Policy()))["cert-authority"], "fail")

    def test_daemon_trust_is_not_a_pass_when_present(self):
        text = TIGHT.format(ops=OPS).replace(
            "permitemptypasswords no",
            "\n".join(
                [
                    "permitemptypasswords no",
                    "trustedusercakeys /etc/ssh/ca.pub",
                    "revokedkeys none",
                    "pubkeyacceptedalgorithms ssh-ed25519,rsa-sha2-256,ssh-rsa",
                    "authorizedkeyscommand /usr/local/bin/keys",
                    "hostbasedauthentication yes",
                    "authenticationmethods publickey,password",
                ]
            ),
        )
        findings = evaluate(parse_protocol(text), parse_public_keys(OPS)[0], Policy())
        codes = _codes(findings)
        self.assertEqual(codes["trusted-user-ca"], "fail")
        self.assertEqual(codes["revoked-keys"], "warn")
        self.assertEqual(codes["accepted-algorithms"], "fail")
        self.assertEqual(codes["authorized-keys-command"], "fail")
        self.assertEqual(codes["hostbased-auth"], "fail")
        self.assertEqual(codes["auth-methods"], "fail")


if __name__ == "__main__":
    unittest.main()
