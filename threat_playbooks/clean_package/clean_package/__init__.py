"""
Threat playbook: clean package (control group).

A legitimate package with no suspicious behavior. Must always score SAFE.
Used to verify that probe does not produce false positives on harmless code.

This file is never executed. It exists solely as a static analysis
target for probe's test suite.
"""

from __future__ import annotations


def add(first_number: int, second_number: int) -> int:
    """
    Add two numbers together.

    :param first_number: First operand.
    :param second_number: Second operand.
    :returns: Sum of the two numbers.
    """
    return first_number + second_number


def greet(name: str) -> str:
    """
    Return a greeting string.

    :param name: Name to greet.
    :returns: Formatted greeting.
    """
    return f"Hello, {name}!"
