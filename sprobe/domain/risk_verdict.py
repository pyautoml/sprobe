"""
Risk verdict data types.

RiskScore wraps the numeric 0-100 score with an automatic label.
RiskVerdict is the final output of the entire analysis pipeline,
containing the score, decision, all findings, and a human-readable summary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from sprobe.domain.scan_finding import ScanFinding
from sprobe.domain.severity import Decision

# Score thresholds that map numeric score to decision
# Tuned conservatively: anything above 60 is blocked outright
_SAFE_UPPER_BOUND: int = 15
_CAUTION_UPPER_BOUND: int = 35
_DANGER_UPPER_BOUND: int = 60


@dataclass(frozen=True, slots=True)
class RiskScore:
    """
    Numeric risk score with automatic label derivation.

    :param value: Score from 0 (safe) to 100 (confirmed malicious).
    """

    value: int

    def __post_init__(self) -> None:
        """Clamp value to valid range 0-100."""
        if self.value < 0 or self.value > 100:
            object.__setattr__(self, "value", max(0, min(100, self.value)))

    @property
    def decision(self) -> Decision:
        """
        Derive decision from numeric score.

        :returns: Decision based on score thresholds.
        """
        if self.value <= _SAFE_UPPER_BOUND:
            return Decision.SAFE
        if self.value <= _CAUTION_UPPER_BOUND:
            return Decision.CAUTION
        if self.value <= _DANGER_UPPER_BOUND:
            return Decision.DANGER
        return Decision.BLOCKED


@dataclass(frozen=True, slots=True)
class RiskVerdict:
    """
    Final analysis result for a scanned package.

    :param package_name: Name of the analyzed package.
    :param package_version: Version string of the analyzed package.
    :param score: Computed risk score.
    :param findings: All findings collected across analysis layers.
    :param summary: Human-readable one-line summary of the verdict.
    """

    package_name: str
    package_version: str
    score: RiskScore
    findings: List[ScanFinding] = field(default_factory=list)
    summary: str = ""

    @property
    def decision(self) -> Decision:
        """
        Shortcut to the score's decision.

        :returns: Final decision for this package.
        """
        return self.score.decision


__all__ = [
    "RiskScore",
    "RiskVerdict",
]
