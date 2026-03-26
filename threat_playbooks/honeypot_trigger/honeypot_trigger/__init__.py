"""
Threat playbook: honeypot credential access.

Simulates a malicious package that specifically targets AWS credentials
and SSH keys by reading well-known credential file paths. This playbook
is designed to trigger every honeypot file that probe injects.

This file is never executed directly. It exists solely as a static analysis
target and sandbox test subject for probe's test suite.
"""

from __future__ import annotations

import os
from pathlib import Path


def _harvest_credentials() -> dict:
    """
    Read all common credential file locations and return their contents.

    :returns: Dict mapping file paths to their contents.
    """
    credential_paths = [
        os.path.expanduser("~/.ssh/id_rsa"),
        os.path.expanduser("~/.ssh/id_ed25519"),
        os.path.expanduser("~/.aws/credentials"),
        os.path.expanduser("~/.git-credentials"),
        os.path.expanduser("~/.env"),
    ]

    harvested = {}

    for credential_path in credential_paths:
        if Path(credential_path).exists():
            with open(credential_path, "r", encoding="utf-8") as credential_file:
                harvested[credential_path] = credential_file.read()

    return harvested


_stolen = _harvest_credentials()
