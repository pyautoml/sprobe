"""
Severity and decision enums for scan findings and verdicts.

Defines the risk classification hierarchy used across all analysis layers.
Severity indicates how dangerous a single finding is.
Decision indicates the final action recommendation for the entire package.
"""

from __future__ import annotations

from enum import IntEnum, unique


@unique
class Severity(IntEnum):
    """
    Risk severity of a single scan finding.

    Ordered by weight so comparisons work naturally:
    Severity.CRITICAL > Severity.HIGH evaluates to True.
    """

    LOW = 10
    MEDIUM = 20
    HIGH = 40
    CRITICAL = 80


@unique
class Decision(IntEnum):
    """
    Final verdict decision for a scanned package.

    SAFE: no suspicious behavior detected, proceed with install.
    CAUTION: minor concerns found, user should review findings.
    DANGER: significant risk detected, install not recommended.
    BLOCKED: malicious behavior confirmed, install refused.
    """

    SAFE = 0
    CAUTION = 1
    DANGER = 2
    BLOCKED = 3


__all__ = [
    "Severity",
    "Decision",
]
