"""
Threat playbook: setup.py backdoor (package module).

The actual package is harmless — the malicious code is in setup.py,
which runs during installation, not during import.

This file is never executed directly. It exists solely as a static analysis
target for probe's test suite.
"""

from __future__ import annotations


def hello() -> str:
    """
    Return a greeting.

    :returns: Greeting string.
    """
    return "Hello from a totally safe package!"
