import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from keywarden import collect  # noqa: E402
from keywarden.cli import main  # noqa: E402
from keywarden.ui_page import render_page  # noqa: E402


class WindowsTests(unittest.TestCase):
    def test_local_check_explains_itself_off_posix(self):
        with patch.object(collect, "LOCAL_SUPPORTED", False):
            with self.assertRaises(ValueError) as caught:
                collect.collect_local()
            self.assertIn("--host", str(caught.exception))
            err = StringIO()
            with redirect_stderr(err), redirect_stdout(StringIO()):
                code = main(["check", "--local"])
        self.assertEqual(code, 2)
        self.assertIn("Linux", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())

    def test_ui_disables_this_machine_off_posix(self):
        self.assertIn("const LOCAL_OK = false;", render_page("n", "t", "0", False))
        self.assertIn("const LOCAL_OK = true;", render_page("n", "t", "0", True))

    def test_script_is_sent_as_bytes_so_newlines_survive_windows(self):
        with patch("keywarden.collect.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 255, b"", b"ssh: connect to host x port 22: refused\r\n")
            with self.assertRaises(RuntimeError) as caught:
                collect.collect_remote("deploy@x")
        sent = run.call_args.kwargs["input"]
        self.assertIsInstance(sent, bytes)
        self.assertNotIn(b"\r\n", sent)
        self.assertNotIn("text", run.call_args.kwargs)
        self.assertIn("refused", str(caught.exception))

    def test_unexpected_errors_end_in_a_message(self):
        err = StringIO()
        with patch("keywarden.cli._check_one", side_effect=KeyError("boom")), redirect_stderr(err):
            code = main(["check", "--local"])
        self.assertEqual(code, 3)
        self.assertIn("unexpected error", err.getvalue())


if __name__ == "__main__":
    unittest.main()
