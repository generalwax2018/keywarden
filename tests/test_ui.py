import http.client
import json
import sys
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from keywarden.ui import KeywardenServer  # noqa: E402
from keywarden.ui_lab import LAB_KEYS, LAB_PUSH  # noqa: E402


class UiServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = KeywardenServer(0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def request(self, method, path, body=None, headers=None, host=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        sent = {"Host": host or f"127.0.0.1:{self.port}"}
        sent.update(headers or {})
        data = json.dumps(body).encode() if body is not None else None
        if data is not None:
            sent.setdefault("Content-Type", "application/json")
        connection.request(method, path, body=data, headers=sent)
        response = connection.getresponse()
        payload = response.read()
        connection.close()
        return response.status, dict(response.getheaders()), payload

    def api(self, path, body, **headers):
        merged = {"X-Keywarden-Token": self.server.token}
        merged.update(headers)
        return self.request("POST", path, body, merged)

    def test_page_needs_the_token_and_a_local_host_header(self):
        self.assertEqual(self.request("GET", "/")[0], 403)
        self.assertEqual(self.request("GET", f"/?t={self.server.token}", host=f"rebind.example:{self.port}")[0], 421)
        status, headers, page = self.request("GET", f"/?t={self.server.token}")
        self.assertEqual(status, 200)
        self.assertIn("script-src 'nonce-", headers["Content-Security-Policy"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertNotIn(b"https://", page.split(b"<script")[0].split(b"</style>")[0])

    def test_api_refuses_missing_token_and_other_origins(self):
        self.assertEqual(self.request("POST", "/api/check", {"target": "lab"})[0], 403)
        status, _, _ = self.api("/api/check", {"target": "lab"}, Origin="http://evil.example")
        self.assertEqual(status, 403)
        status, _, _ = self.request("POST", "/api/check", {"target": "lab"}, {"X-Keywarden-Token": "wrong"})
        self.assertEqual(status, 403)

    def test_lab_run_returns_fingerprints_not_key_bodies(self):
        status, _, payload = self.api("/api/check", {"target": "lab", "allowText": "\n".join(LAB_PUSH)})
        self.assertEqual(status, 200)
        text = payload.decode()
        for line in LAB_KEYS.values():
            self.assertNotIn(line.split()[1], text)
        data = json.loads(text)
        hosts = {host["name"]: host for host in data["report"]["hosts"]}
        self.assertEqual(len(hosts), 6)
        self.assertEqual(hosts["bastion"]["posture"], "pass")
        drift = {item["code"]: item.get("drift") for item in hosts["app-web-03"]["findings"]}
        self.assertEqual(drift["permit-root"], "regressed")
        self.assertIsNone(drift["password-auth"])
        # A second run can use the fingerprints the page kept instead of the key text.
        prints = data["report"]["push"]
        status, _, payload = self.api("/api/check", {"target": "lab", "allowFingerprints": prints})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["report"]["push"], prints)

    def test_private_key_is_refused(self):
        status, _, payload = self.api("/api/check", {"target": "lab", "allowText": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc"})
        self.assertEqual(status, 400)
        self.assertIn("private key", json.loads(payload)["error"])

    def test_where_in_the_lab(self):
        status, _, payload = self.api("/api/where", {"target": "lab", "keyText": LAB_KEYS["alice"]})
        self.assertEqual(status, 200)
        found = json.loads(payload)["found"]
        self.assertEqual([(hit["host"], hit["account"]) for hit in found], [("ci-runner", "deploy")])


if __name__ == "__main__":
    unittest.main()
