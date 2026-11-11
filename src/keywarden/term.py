"""Terminal colour. Off when output is not a terminal, when NO_COLOR is set, or when asked."""

from __future__ import annotations

import os
import sys

_CODES = {
    "fail": "31;1",
    "warn": "33;1",
    "pass": "32",
    "accepted": "34;1",
    "dim": "2",
    "bold": "1",
    "fp": "36",
}


def _enable_windows_vt() -> bool:
    """Windows 10 and later understand ANSI once virtual terminal processing is switched on."""
    try:
        import ctypes

        kernel = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def use_colour(choice: str = "auto", stream=None) -> bool:
    stream = stream or sys.stdout
    if choice == "always":
        if os.name == "nt":
            _enable_windows_vt()
        return True
    if choice == "never" or os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    if not hasattr(stream, "isatty") or not stream.isatty():
        return False
    if os.name == "nt":
        return _enable_windows_vt()
    return True


class Paint:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, style: str, text: str) -> str:
        if not self.enabled or style not in _CODES:
            return text
        return f"\033[{_CODES[style]}m{text}\033[0m"

    def severity(self, severity: str) -> str:
        label = {"fail": "FAIL", "warn": "WARN", "pass": "PASS", "accepted": "ACPT"}.get(severity, severity.upper())
        return self(severity, f"{label:4}")

    def fingerprints(self, text: str) -> str:
        if not self.enabled:
            return text
        from keywarden.check import FINGERPRINT

        return FINGERPRINT.sub(lambda match: self("fp", match.group(0)), text)
