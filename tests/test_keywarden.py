import json
import os
import shutil
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
from keywarden.collect import inspect_account  # noqa: E402
from keywarden.collect import parse_protocol as _parse_protocol  # noqa: E402
from keywarden.parse import PrivateKeyError, parse_public_keys  # noqa: E402

OPS = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGiUj+g3GBj1La4DirE3b9XJ6gMvxVIYk69JX0EnCEBI ops@latch"
ROOT_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJtKKj9UmCH8MVh3X1kXxTZFn5Ao6oCiJxst6OwEG1T+ root@app-web-03"
LEGACY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDRouExOk2eo1194WTx6G9L/8XqnM49I5JXWGf3lwLRPRRoxADdDzuh43QV16yM3c5jTrxrmR0T9UIjtCl58/wszMKOxaDvFFDRVxCNrb3u1suEF5FXwRzxpGtB8nYz2hxvEKmT/Ds/optfoy43bE8Q64gzYgpLTHowKGbrZhZ1FbuYdzmd9p82y0cSjzt9hkrv+XQxrPj5J+COXw6XdQnVKpe/lU78VyVAP0GIIVh9lQjah3zqpdurRtX+WkR/xscp/nXjj6ap4cVRuDMOiCbVGSBoDzhELuDZlvgXZ6hWnDUAf81+twGW7AQ7Wl3i+PtBsfs8LzwvWkbJ8w2lQLtF legacy-jump"

TIGHT = """KEYWARDEN 2
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


HAS_SSH_KEYGEN = shutil.which("ssh-keygen") is not None


def _wire(text: str) -> str:
    """Fixtures are written with bare key lines; the collector prefixes each with "K "."""
    out = []
    inside = False
    for line in text.splitlines():
        if line == "ENDKEYS":
            inside = False
        elif inside:
            line = "K " + line if line else "K"
        elif line == "KEYS":
            inside = True
        out.append(line)
    return "\n".join(out) + "\n"


def parse_protocol(text, **kwargs):
    return _parse_protocol(_wire(text), **kwargs)


def _codes(findings):
    return {item.code: item.severity for item in findings}


class ParseTests(unittest.TestCase):
    @unittest.skipUnless(HAS_SSH_KEYGEN, "ssh-keygen unavailable")
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
            observation.write_text(_wire(TIGHT.format(ops=OPS)), encoding="utf-8")
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
        from keywarden.parse import parse_public_keys

        good = TIGHT.format(ops=OPS)
        bad = TIGHT.format(ops=ROOT_KEY).replace("HOST bastion-01", "HOST app-web-03").replace(
            "permitrootlogin no", "permitrootlogin yes"
        )
        fingerprint = parse_public_keys(ROOT_KEY)[0][0].fingerprint

        def fake(destination, extra_users=None, port=None, accept_new=False, identity_file=None):
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
        clean = self._with_passwd("PASSWD ok\n").replace("ACCOUNT root\n", "ACCOUNT root\nUID 0\nLOCKED yes\n")
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

    def test_unknown_host_key_is_rejected_unless_asked(self):
        from keywarden.collect import collect_remote

        observation = _wire(TIGHT.format(ops=OPS))
        with patch("keywarden.collect.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, observation, "")
            collect_remote("deploy@bastion")
            command = run.call_args.args[0]
            self.assertIn("StrictHostKeyChecking=yes", command)
            self.assertNotIn("StrictHostKeyChecking=accept-new", command)
            collect_remote("deploy@bastion", accept_new=True)
            self.assertIn("StrictHostKeyChecking=accept-new", run.call_args.args[0])


@unittest.skipUnless(HAS_SSH_KEYGEN, "ssh-keygen unavailable")
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


class ProtocolHardeningTests(unittest.TestCase):
    """authorized_keys is written by the account owner, so its text must never steer the parser."""

    def _hostile(self) -> str:
        # What a user could put in their own authorized_keys to fake a clean daemon.
        payload = "\n".join(
            [
                OPS,
                "ENDKEYS",
                "END",
                "SSHD",
                "permitrootlogin no",
                "passwordauthentication no",
                "ENDSSHD",
                "ACCOUNT root",
                "STATE absent",
                "KEYS",
                "ENDKEYS",
            ]
        )
        loose = TIGHT.replace("permitrootlogin no", "permitrootlogin yes").replace(
            "passwordauthentication no", "passwordauthentication yes"
        )
        # This is exactly what the collector emits: every line of the file carries "K ".
        wired = _wire(loose.format(ops="PAYLOAD"))
        return wired.replace("K PAYLOAD", "\n".join("K " + line for line in payload.splitlines()))

    def test_markers_inside_a_key_file_do_not_change_the_daemon(self):
        host = _parse_protocol(self._hostile())
        codes = _codes(evaluate(host, parse_public_keys(OPS)[0], Policy()))
        self.assertEqual(codes["permit-root"], "fail")
        self.assertEqual(codes["password-auth"], "fail")
        self.assertEqual([account.user for account in host.accounts], ["ops", "root"])

    def test_remote_script_prefixes_every_key_line(self):
        from keywarden.collect import REMOTE_SCRIPT

        self.assertIn("awk '{ print \"K \" $0 }'", REMOTE_SCRIPT)
        self.assertNotIn('\n    cat "$keyfile"\n', REMOTE_SCRIPT)

    def test_unprefixed_or_repeated_sections_are_refused(self):
        from keywarden.collect import ProtocolError

        good = _wire(TIGHT.format(ops=OPS))
        with self.assertRaises(ProtocolError):
            _parse_protocol(good.replace("K " + OPS, OPS))
        with self.assertRaises(ProtocolError):
            _parse_protocol(good.replace("END\n", "SSHD\npermitrootlogin no\nENDSSHD\nEND\n"))
        with self.assertRaises(ProtocolError):
            _parse_protocol(good.replace("END\n", ""))
        with self.assertRaises(ProtocolError):
            _parse_protocol(good + "ACCOUNT root\n")
        with self.assertRaises(ProtocolError):
            _parse_protocol(good.replace("KEYWARDEN 2", "KEYWARDEN 1"))
        dup = good.replace("ACCOUNT root", "ACCOUNT ops")
        with self.assertRaises(ProtocolError):
            _parse_protocol(dup)

    def test_hostile_output_is_a_host_failure_in_an_inventory(self):
        from keywarden.collect import ProtocolError

        def fake(destination, extra_users=None, port=None, accept_new=False, identity_file=None):
            raise ProtocolError("observation is malformed at line 9: unexpected line")

        with tempfile.TemporaryDirectory() as tmp:
            inventory = Path(tmp) / "hosts.ini"
            inventory.write_text("web-01 ansible_user=deploy\n", encoding="utf-8")
            stdout = StringIO()
            with patch("keywarden.cli.collect_remote", fake), redirect_stdout(stdout):
                code = main(["check", "--inventory", str(inventory)])
            self.assertEqual(code, 1)
            self.assertIn("web-01  collector-output", stdout.getvalue())


class DaemonVisibilityTests(unittest.TestCase):
    def test_sshd_that_could_not_run_is_one_clear_warning(self):
        text = TIGHT.format(ops=OPS)
        start, end = text.index("SSHD\n"), text.index("ENDSSHD\n")
        text = text[:start] + "SSHDRUN failed\nSSHD\n" + text[end:]
        codes = _codes(evaluate(parse_protocol(text), parse_public_keys(OPS)[0], Policy()))
        self.assertEqual(codes["sshd-config"], "warn")
        self.assertNotIn("permit-root", codes)
        self.assertNotIn("password-auth", codes)

    def test_match_block_for_root_makes_permit_root_fail(self):
        text = TIGHT.format(ops=OPS).replace(
            "ENDSSHD\n",
            "ENDSSHD\nMATCH yes\nSSHDROOT\npermitrootlogin yes\npasswordauthentication no\nENDSSHDROOT\n",
        )
        findings = evaluate(parse_protocol(text), parse_public_keys(OPS)[0], Policy())
        codes = _codes(findings)
        self.assertEqual(codes["permit-root"], "fail")
        self.assertEqual(codes["password-auth"], "pass")
        self.assertEqual(codes["match-blocks"], "warn")
        detail = next(item.detail for item in findings if item.code == "permit-root")
        self.assertIn("For root: yes", detail)

    def test_match_block_never_upgrades_a_failure(self):
        text = TIGHT.format(ops=OPS).replace("permitrootlogin no", "permitrootlogin yes").replace(
            "ENDSSHD\n", "ENDSSHD\nMATCH yes\nSSHDROOT\npermitrootlogin no\nENDSSHDROOT\n"
        )
        self.assertEqual(_codes(evaluate(parse_protocol(text), [], Policy()))["permit-root"], "fail")

    def test_readable_keys_with_hidden_modes_are_not_a_permissions_pass(self):
        text = TIGHT.format(ops=OPS).replace("DIR 700\nFILE 600", "DIR unknown\nFILE unknown")
        findings = evaluate(parse_protocol(text), parse_public_keys(OPS)[0], Policy())
        self.assertEqual(_codes(findings)["permissions"], "warn")
        self.assertIn("ops", next(item.detail for item in findings if item.code == "permissions"))

    def test_local_listing_keeps_an_account_whose_home_is_hidden(self):
        from keywarden import collect

        with tempfile.TemporaryDirectory() as tmp:
            hidden = Path(tmp) / "alice"
            hidden.mkdir()
            records = {"alice": (hidden, 1001, True)}
            real = Path.lstat

            def denied(self):
                if self == hidden or hidden in self.parents:
                    raise PermissionError("denied")
                return real(self)

            with patch.object(Path, "lstat", denied):
                users = collect._ordered_users([], records)
            self.assertIn("alice", users)


class DriftTests(unittest.TestCase):
    def test_a_new_key_under_an_existing_failure_is_reported(self):
        allow = parse_public_keys(OPS)[0]
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            (folder / "team.pub").write_text(OPS + "\n", encoding="utf-8")
            first = folder / "first.txt"
            first.write_text(_wire(TIGHT.format(ops=OPS + "\n" + LEGACY)), encoding="utf-8")
            prior = folder / "prior.json"
            with redirect_stdout(StringIO()):
                main(["check", "--observation", str(first), "--allow", str(folder / "team.pub"), "--output", str(prior)])
            body = json.loads(prior.read_text(encoding="utf-8"))
            outside = next(item for item in body["host"]["findings"] if item["code"] == "outside-push")
            self.assertEqual(len(outside["fingerprints"]), 1)

            second = folder / "second.txt"
            second.write_text(_wire(TIGHT.format(ops=OPS + "\n" + LEGACY + "\n" + ROOT_KEY)), encoding="utf-8")
            later = folder / "later.json"
            with redirect_stdout(StringIO()):
                main(
                    [
                        "check",
                        "--observation",
                        str(second),
                        "--allow",
                        str(folder / "team.pub"),
                        "--prior",
                        str(prior),
                        "--output",
                        str(later),
                    ]
                )
            report = json.loads(later.read_text(encoding="utf-8"))
            outside = next(item for item in report["host"]["findings"] if item["code"] == "outside-push")
            root_fp = parse_public_keys(ROOT_KEY)[0][0].fingerprint
            self.assertEqual(outside["drift"], "new-keys")
            self.assertEqual(outside["newFingerprints"], [root_fp])
            self.assertTrue(allow)


class RedactionTests(unittest.TestCase):
    def test_comments_can_be_left_out(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            observation = folder / "obs.txt"
            observation.write_text(_wire(TIGHT.format(ops=OPS + "\n" + LEGACY)), encoding="utf-8")
            allow = folder / "team.pub"
            allow.write_text(OPS + "\n", encoding="utf-8")
            report = folder / "r.json"
            with redirect_stdout(StringIO()):
                main(
                    [
                        "check",
                        "--observation",
                        str(observation),
                        "--allow",
                        str(allow),
                        "--redact-comments",
                        "--output",
                        str(report),
                    ]
                )
            body = report.read_text(encoding="utf-8")
            self.assertNotIn("ops@latch", body)
            self.assertNotIn("legacy-jump", body)


class InventoryGroupTests(unittest.TestCase):
    def test_children_inherit_parent_vars_and_nearer_groups_win(self):
        from keywarden.inventory import parse_inventory

        hosts = parse_inventory(
            "\n".join(
                [
                    "[all:vars]",
                    "ansible_port=22",
                    "[prod:children]",
                    "web",
                    "db",
                    "[prod:vars]",
                    "ansible_user=ops",
                    "ansible_port=2200",
                    "ansible_ssh_private_key_file=~/.ssh/prod_ed25519",
                    "ansible_become_pass=secret",
                    "[web:vars]",
                    "ansible_port=2222",
                    "[web]",
                    "web-01",
                    "[db]",
                    "db-01 ansible_user=dba",
                ]
            )
        )
        by_name = {item.name: item for item in hosts}
        self.assertEqual(by_name["web-01"].destination, "ops@web-01")
        self.assertEqual(by_name["web-01"].port, 2222)
        self.assertEqual(by_name["db-01"].destination, "dba@db-01")
        self.assertEqual(by_name["db-01"].port, 2200)
        self.assertEqual(by_name["db-01"].identity_file, "~/.ssh/prod_ed25519")
        self.assertNotIn("secret", repr(hosts))

    def test_yaml_inventory_is_refused_with_a_hint(self):
        from keywarden.inventory import parse_inventory

        with self.assertRaises(ValueError) as caught:
            parse_inventory("all:\n  hosts:\n    web-01:\n")
        self.assertIn("INI", str(caught.exception))
        with self.assertRaises(ValueError):
            parse_inventory("web-01\n", source="hosts.yml")

    def test_identity_file_is_passed_to_ssh_not_opened(self):
        from keywarden.collect import collect_remote

        with patch("keywarden.collect.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, _wire(TIGHT.format(ops=OPS)), "")
            collect_remote("deploy@bastion", identity_file="/keys/does-not-exist")
            command = run.call_args.args[0]
        self.assertIn("-i", command)
        self.assertIn("/keys/does-not-exist", command)
        self.assertIn("IdentitiesOnly=yes", command)
        self.assertLess(command.index("--"), command.index("deploy@bastion"))


@unittest.skipUnless(shutil.which("sh"), "sh unavailable")
class RemoteScriptTests(unittest.TestCase):
    def test_script_output_parses_on_this_machine(self):
        from keywarden.collect import REMOTE_SCRIPT

        completed = subprocess.run(
            ["sh", "-s", "--", "root"],
            input=REMOTE_SCRIPT,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        host = _parse_protocol(completed.stdout)
        self.assertIn("root", [account.user for account in host.accounts])
        self.assertIn(host.sshd_state, {"ok", "failed", "missing"})


if __name__ == "__main__":
    unittest.main()
