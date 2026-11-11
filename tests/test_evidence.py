import hashlib
import json
import os
import re
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from keywarden import ui_lab  # noqa: E402
from keywarden.cli import main  # noqa: E402
from keywarden.controls import FRAMEWORKS, MAPPING, NAMES, controls_for, markdown_table  # noqa: E402
from keywarden.evidence import control_matrix, render_evidence  # noqa: E402
from keywarden.term import Paint, use_colour  # noqa: E402

KEYS = ui_lab.LAB_KEYS


def lab_observation(comment_override=None) -> str:
    now = int(time.time())
    deploy = KEYS["deploy"] if comment_override is None else KEYS["deploy"].rsplit(" ", 1)[0] + " " + comment_override
    return ui_lab._host(
        "app-web-03",
        now,
        {"permitrootlogin": "prohibit-password"},
        [
            ui_lab._account("root", 0, ["root"], [], [KEYS["root"]], "app-web-03"),
            ui_lab._account("ops", 1000, ["ops", "sudo"], ui_lab._ADMIN_SUDO, [KEYS["ops"]], "app-web-03"),
            ui_lab._account("deploy", 1001, ["deploy"], ui_lab._NO_SUDO, [deploy, KEYS["alice"]], "app-web-03"),
        ],
        [("ops", "ops", 1, "10.0.0.9", 41), ("deploy", "deploy", 0, "10.0.6.15", 212)],
    )


class ControlMappingTests(unittest.TestCase):
    def test_every_check_maps_to_known_controls(self):
        emitted = set()
        for path in (ROOT / "src" / "keywarden").glob("*.py"):
            emitted |= set(re.findall(r'Finding\(\s*"([a-z0-9-]+)"', path.read_text(encoding="utf-8")))
        emitted -= {"collector-output", "unreachable"}
        self.assertEqual(sorted(emitted - set(MAPPING)), [])
        for keys in MAPPING.values():
            for key in keys:
                self.assertIn(key, NAMES)
                self.assertIn(key.split(":", 1)[0], FRAMEWORKS)

    def test_no_mfa_claims(self):
        self.assertFalse(any("MFA" in name for name in NAMES.values()))

    def test_docs_table_matches_the_code(self):
        docs = (ROOT / "docs" / "compliance.md").read_text(encoding="utf-8")
        self.assertIn(markdown_table(), docs)

    def test_controls_appear_in_findings(self):
        self.assertTrue(any(c["framework"] == "pci" and c["id"] == "8.2.6" for c in controls_for("stale-key")))


class EvidenceTests(unittest.TestCase):
    def run_check(self, observation_text, *extra):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            (folder / "obs.txt").write_text(observation_text, encoding="utf-8")
            (folder / "team.pub").write_text("\n".join(ui_lab.LAB_PUSH) + "\n", encoding="utf-8")
            with redirect_stdout(StringIO()):
                code = main(["check", "--observation", str(folder / "obs.txt"), "--allow", str(folder / "team.pub"),
                             "--evidence", str(folder / "e.html"), "--output", str(folder / "r.json"), *extra])
            return code, (folder / "e.html").read_text(encoding="utf-8"), json.loads((folder / "r.json").read_text(encoding="utf-8"))

    def test_report_has_scope_controls_and_a_matching_hash(self):
        code, page, report = self.run_check(lab_observation())
        self.assertEqual(code, 1)
        for title in FRAMEWORKS.values():
            self.assertIn(title, page)
        for line in KEYS.values():
            self.assertNotIn(line.split()[1], page)
        embedded = re.search(r"<script type='application/json' id='keywarden-report'>(.*?)</script>", page, re.S).group(1)
        document = json.loads(embedded.replace("<\\/", "</"))
        digest = hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertIn(digest, page)
        self.assertEqual(document["host"]["name"], report["host"]["name"])

    def test_hostile_comment_is_escaped(self):
        _code, page, _report = self.run_check(lab_observation('<img src=x onerror=alert(1)>'))
        self.assertNotIn("<img src=x", page.split("<script type='application/json'")[0])
        self.assertIn("&lt;img src=x", page)

    def test_matrix_marks_failures_and_unassessed(self):
        document = {"host": {"name": "h", "findings": [{"code": "stale-key", "severity": "fail"}, {"code": "log-level", "severity": "pass"}]}}
        matrix = control_matrix(document)
        rows = {row["id"]: row for row in matrix["pci"]}
        self.assertEqual(rows["8.2.6"]["status"], "fail")
        self.assertEqual(rows["10.2.1"]["status"], "pass")
        self.assertEqual(rows["2.2.7"]["status"], "none")
        self.assertIn("evidence report", render_evidence(document).lower())


class TerminalTests(unittest.TestCase):
    def test_colour_rules(self):
        self.assertFalse(use_colour("auto", StringIO()))
        self.assertFalse(use_colour("never"))
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            class Tty(StringIO):
                def isatty(self):
                    return True
            self.assertFalse(use_colour("auto", Tty()))
        self.assertEqual(Paint(False)("fail", "x"), "x")
        self.assertIn("\033[", Paint(True)("fail", "x"))

    def test_passes_hidden_unless_verbose_and_summary_printed(self):
        with tempfile.TemporaryDirectory() as tmp:
            obs = Path(tmp) / "obs.txt"
            obs.write_text(lab_observation(), encoding="utf-8")
            quiet, loud = StringIO(), StringIO()
            with redirect_stdout(quiet):
                main(["check", "--observation", str(obs), "--color", "never"])
            with redirect_stdout(loud):
                main(["check", "--observation", str(obs), "--color", "never", "--verbose"])
        self.assertNotIn("PASS", quiet.getvalue())
        self.assertIn("passing checks hidden", quiet.getvalue())
        self.assertRegex(quiet.getvalue().splitlines()[0], r"\d+ fail · \d+ warn · \d+ pass")
        self.assertIn("PASS", loud.getvalue())
        self.assertNotIn("\033[", quiet.getvalue())


if __name__ == "__main__":
    unittest.main()
