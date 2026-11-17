import json
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from keywarden import ui_lab  # noqa: E402
from keywarden.check import Policy, evaluate  # noqa: E402
from keywarden.cli import main  # noqa: E402
from keywarden.collect import parse_protocol  # noqa: E402
from keywarden.inventory import parse_inventory_json  # noqa: E402
from keywarden.outputs import to_jsonl, to_sarif  # noqa: E402
from keywarden.ui import run_check  # noqa: E402

KEYS = ui_lab.LAB_KEYS
INVENTORY = {
    "_meta": {
        "hostvars": {
            "web-01": {"ansible_host": "10.0.0.11", "ansible_user": "deploy", "ansible_port": 2222, "ansible_password": "hunter2"},
            "web-02": {"ansible_host": "10.0.0.12", "ansible_user": "deploy", "ansible_ssh_private_key_file": "~/.ssh/prod"},
            "db-01": {"ansible_user": "dba"},
        }
    },
    "all": {"children": ["ungrouped", "web", "db"]},
    "web": {"hosts": ["web-01", "web-02"]},
    "db": {"hosts": ["db-01"]},
}


def observation(name: str, days_of_logs: int = 210) -> str:
    now = int(time.time())
    text = ui_lab._host(
        name, now, {},
        [ui_lab._account("root", 0, ["root"], [], [], name),
         ui_lab._account("ops", 1000, ["ops"], ui_lab._NO_SUDO, [KEYS["ops"], KEYS["contractor"]], name)],
        [("ops", "ops", 1, "10.0.0.9", 3)],
    )
    return text.replace(f"AUTHFIRST {now - 210 * 86400}.000000", f"AUTHFIRST {now - days_of_logs * 86400}.000000")


class InventoryJsonTests(unittest.TestCase):
    def test_hosts_vars_and_order(self):
        hosts = parse_inventory_json(json.dumps(INVENTORY))
        self.assertEqual([h.name for h in hosts], ["web-01", "web-02", "db-01"])
        self.assertEqual(hosts[0].destination, "deploy@10.0.0.11")
        self.assertEqual(hosts[0].port, 2222)
        self.assertEqual(hosts[1].identity_file, "~/.ssh/prod")
        self.assertEqual(hosts[2].destination, "dba@db-01")
        self.assertNotIn("hunter2", repr(hosts))

    def test_yaml_goes_through_ansible_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hosts.yml"
            path.write_text("all:\n  hosts:\n    web-01:\n", encoding="utf-8")
            completed = subprocess.CompletedProcess([], 0, json.dumps(INVENTORY), "")
            with patch("shutil.which", return_value="/usr/bin/ansible-inventory"), patch("subprocess.run", return_value=completed) as run, \
                    patch("keywarden.cli.collect_remote", side_effect=RuntimeError("down")), redirect_stdout(StringIO()):
                code = main(["check", "--inventory", str(path), "--color", "never"])
            self.assertEqual(run.call_args.args[0][1:], ["-i", str(path), "--list"])
            self.assertEqual(code, 1)

    def test_yaml_without_ansible_explains(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hosts.yml"
            path.write_text("all:\n  hosts:\n    web-01:\n", encoding="utf-8")
            err = StringIO()
            with patch("shutil.which", return_value=None), redirect_stdout(StringIO()), patch("sys.stderr", err):
                code = main(["check", "--inventory", str(path)])
        self.assertEqual(code, 2)
        self.assertIn("ansible-inventory", err.getvalue())


class ParallelTests(unittest.TestCase):
    def test_hosts_run_at_once_and_report_in_inventory_order(self):
        active, peak, lock = [0], [0], threading.Lock()

        def fake(destination, extra_users=None, port=None, accept_new=False, identity_file=None):
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            time.sleep(0.2)
            with lock:
                active[0] -= 1
            if destination.endswith("10.0.0.12"):
                raise RuntimeError("connection refused")
            return parse_protocol(observation(destination.split("@")[-1]), address=destination)

        with tempfile.TemporaryDirectory() as tmp:
            inv = Path(tmp) / "inventory.json"
            inv.write_text(json.dumps(INVENTORY), encoding="utf-8")
            report = Path(tmp) / "r.json"
            with patch("keywarden.cli.collect_remote", fake), redirect_stdout(StringIO()):
                main(["check", "--inventory", str(inv), "--jobs", "3", "--output", str(report)])
            names = [h["name"] for h in json.loads(report.read_text(encoding="utf-8"))["hosts"]]
        self.assertEqual(names, ["web-01", "web-02", "db-01"])
        self.assertGreaterEqual(peak[0], 2)


class MachineOutputTests(unittest.TestCase):
    def document(self):
        host = parse_protocol(observation("web-01"))
        findings = evaluate(host, [k for k in []], Policy())
        from keywarden.access import key_rows
        from keywarden.cli import _envelope, _host_report

        document = _envelope([])
        document["hosts"] = [_host_report(host, findings, key_rows(host, [], Policy()))]
        return document

    def test_sarif_points_at_the_host_line_and_has_no_key_bodies(self):
        with tempfile.TemporaryDirectory() as tmp:
            inv = Path(tmp) / "hosts.ini"
            inv.write_text("[web]\nweb-00\nweb-01 ansible_user=ops\n", encoding="utf-8")
            sarif = to_sarif(self.document(), inv)
        run = sarif["runs"][0]
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertTrue(run["results"])
        self.assertTrue(all(r["locations"][0]["physicalLocation"]["region"]["startLine"] == 3 for r in run["results"]))
        self.assertEqual({r["level"] for r in run["results"]} - {"error", "warning", "note"}, set())
        text = json.dumps(sarif)
        for line in KEYS.values():
            self.assertNotIn(line.split()[1], text)

    def test_jsonl_one_event_per_finding_and_key(self):
        document = self.document()
        lines = to_jsonl(document).splitlines()
        events = [json.loads(line) for line in lines]
        host = document["hosts"][0]
        self.assertEqual(sum(e["type"] == "finding" for e in events), len(host["findings"]))
        self.assertEqual(sum(e["type"] == "key" for e in events), len(host["keys"]))
        self.assertTrue(any(e.get("controls") for e in events if e["type"] == "finding"))


class RetentionTests(unittest.TestCase):
    def test_short_logs_warn(self):
        short = evaluate(parse_protocol(observation("h", days_of_logs=20)), [], Policy())
        long = evaluate(parse_protocol(observation("h", days_of_logs=200)), [], Policy())
        self.assertEqual({f.code: f.severity for f in short}["auth-log"], "warn")
        self.assertEqual({f.code: f.severity for f in long}["auth-log"], "pass")


class GuiPreviousRunTests(unittest.TestCase):
    def test_previous_summary_marks_new_keys(self):
        text = observation("web-01")
        before = {"web-01": {"outside-push": ["fail", []]}}
        result = run_check({"target": "paste", "observation": text, "allowText": KEYS["ops"], "previous": before})
        outside = next(f for f in result["report"]["hosts"][0]["findings"] if f["code"] == "outside-push")
        self.assertEqual(outside["drift"], "new-keys")
        ignored = run_check({"target": "paste", "observation": text, "allowText": KEYS["ops"], "previous": {"web-01": "junk"}})
        self.assertNotIn("drift", next(f for f in ignored["report"]["hosts"][0]["findings"] if f["code"] == "outside-push"))


if __name__ == "__main__":
    unittest.main()
