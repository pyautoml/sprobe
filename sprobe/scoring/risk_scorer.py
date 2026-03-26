"""
Risk scoring engine.

Aggregates scan findings into a single RiskScore and RiskVerdict.
The scoring algorithm accounts for:
  - Individual finding severity (weighted via Severity IntEnum values)
  - Number of distinct categories hit (breadth of suspicious behavior)
  - Critical findings acting as circuit breakers (instant high score)
  - Diminishing returns from multiple findings in the same category

Scoring formula:
  base_score = sum of severity values across all findings
  category_breadth_multiplier = 1.0 + (0.15 * unique_categories_count)
  raw_score = base_score * category_breadth_multiplier
  final_score = clamp(raw_score, 0, 100)

A single CRITICAL finding (value=80) alone pushes the score past DANGER.
Two HIGH findings (40+40=80) do the same. This is intentional — one
suspicious behavior might be a coincidence, but a combination is a pattern.
"""

from __future__ import annotations

from typing import List, Set

from sprobe.domain.risk_verdict import RiskScore, RiskVerdict
from sprobe.domain.scan_finding import ScanFinding
from sprobe.domain.severity import Decision, Severity

# Multiplier per unique category — rewards breadth detection
# A package that reads SSH keys AND makes POST requests is worse
# than one that just reads SSH keys twice
_CATEGORY_BREADTH_FACTOR: float = 0.15

# Cap for category multiplier to prevent runaway scores
_MAX_CATEGORY_MULTIPLIER: float = 2.0

# Diminishing returns: second+ findings in same category contribute less
_SAME_CATEGORY_DIMINISH: float = 0.3

# Maximum additional findings per category that contribute to the score
# Beyond this, more findings in the same category add nothing
_MAX_FINDINGS_PER_CATEGORY: int = 3


def compute_verdict(
    package_name: str,
    package_version: str,
    findings: List[ScanFinding],
) -> RiskVerdict:
    """
    Compute a risk verdict from a list of scan findings.

    :param package_name: Name of the scanned package.
    :param package_version: Version of the scanned package.
    :param findings: All findings from all analysis layers.
    :returns: Final risk verdict with score and decision.
    """
    if not findings:
        return RiskVerdict(
            package_name=package_name,
            package_version=package_version,
            score=RiskScore(value=0),
            findings=findings,
            summary="No suspicious behavior detected",
        )

    has_critical = any(f.severity == Severity.CRITICAL for f in findings)
    raw_score = _calculate_raw_score(findings)

    # Without CRITICAL findings, cap the score at DANGER threshold
    # Only CRITICAL findings (credential theft, honeypot access, obfuscated exec)
    # should push a package into BLOCKED territory
    _DANGER_SCORE_CAP: int = 60
    if not has_critical:
        raw_score = min(raw_score, _DANGER_SCORE_CAP)

    clamped_score = max(0, min(100, round(raw_score)))
    risk_score = RiskScore(value=clamped_score)
    summary = _generate_summary(findings, risk_score)

    return RiskVerdict(
        package_name=package_name,
        package_version=package_version,
        score=risk_score,
        findings=findings,
        summary=summary,
    )


def _calculate_raw_score(findings: List[ScanFinding]) -> float:
    """
    Calculate raw numeric score from findings.

    Uses severity-weighted scoring with category breadth multiplier
    and diminishing returns for same-category findings.

    :param findings: Non-empty list of findings.
    :returns: Raw score before clamping.
    """
    unique_categories: Set[str] = set()
    category_seen_count: dict[str, int] = {}
    base_score: float = 0.0

    # Sort by severity descending — highest severity findings contribute fully
    sorted_findings = sorted(findings, key=lambda finding: finding.severity.value, reverse=True)

    for finding in sorted_findings:
        unique_categories.add(finding.category)
        seen_count = category_seen_count.get(finding.category, 0)

        # First finding in a category contributes full severity value
        # Subsequent findings contribute diminished value, capped at max per category
        if seen_count == 0:
            base_score += finding.severity.value
        elif seen_count < _MAX_FINDINGS_PER_CATEGORY:
            base_score += finding.severity.value * _SAME_CATEGORY_DIMINISH
        # Beyond max: no additional score contribution

        category_seen_count[finding.category] = seen_count + 1

    # Category breadth multiplier
    category_multiplier = min(
        1.0 + (_CATEGORY_BREADTH_FACTOR * len(unique_categories)),
        _MAX_CATEGORY_MULTIPLIER,
    )

    return base_score * category_multiplier


def _generate_summary(findings: List[ScanFinding], score: RiskScore) -> str:
    """
    Generate a human-readable one-line summary.

    :param findings: All findings.
    :param score: Computed risk score.
    :returns: Summary string.
    """
    decision = score.decision
    finding_count = len(findings)
    critical_count = sum(1 for finding in findings if finding.severity == Severity.CRITICAL)

    if decision == Decision.BLOCKED:
        return (
            f"BLOCKED: {finding_count} suspicious behaviors detected "
            f"({critical_count} critical)."
        )

    if decision == Decision.DANGER:
        return (
            f"DANGER: {finding_count} suspicious behaviors detected "
            f"({critical_count} critical)."
        )

    if decision == Decision.CAUTION:
        return f"CAUTION: {finding_count} minor concerns found."

    return "No suspicious behavior detected"


__all__ = [
    "compute_verdict",
]
