"""Tests for risk scoring engine."""

from sprobe.domain.scan_finding import ScanFinding
from sprobe.domain.severity import Decision, Severity
from sprobe.scoring.risk_scorer import compute_verdict


def _make_finding(
    severity: Severity = Severity.HIGH,
    category: str = "test",
    pattern_id: str = "test_pattern",
) -> ScanFinding:
    """
    Create a minimal ScanFinding for testing.

    :param severity: Finding severity.
    :param category: Finding category.
    :param pattern_id: Pattern ID.
    :returns: ScanFinding instance.
    """
    return ScanFinding(
        pattern_id=pattern_id,
        category=category,
        severity=severity,
        description="Test finding",
        evidence="test evidence",
    )


def test_no_findings_is_safe() -> None:
    """Zero findings must produce a SAFE verdict with score 0."""
    verdict = compute_verdict("test", "1.0", [])
    assert verdict.decision == Decision.SAFE
    assert verdict.score.value == 0


def test_single_critical_is_blocked() -> None:
    """A single CRITICAL finding must push score past BLOCKED threshold."""
    findings = [_make_finding(severity=Severity.CRITICAL)]
    verdict = compute_verdict("test", "1.0", findings)
    assert verdict.decision == Decision.BLOCKED


def test_two_high_findings_different_categories() -> None:
    """Two HIGH findings without CRITICAL cap at DANGER (60)."""
    findings = [
        _make_finding(severity=Severity.HIGH, category="network"),
        _make_finding(severity=Severity.HIGH, category="file_access"),
    ]
    verdict = compute_verdict("test", "1.0", findings)
    assert verdict.score.value == 60  # Capped at DANGER without CRITICAL findings
    assert verdict.decision == Decision.DANGER


def test_same_category_diminishing_returns() -> None:
    """Multiple findings in the same category have diminishing impact."""
    single = compute_verdict(
        "test",
        "1.0",
        [
            _make_finding(severity=Severity.MEDIUM, category="network"),
        ],
    )
    double = compute_verdict(
        "test",
        "1.0",
        [
            _make_finding(severity=Severity.MEDIUM, category="network", pattern_id="p1"),
            _make_finding(severity=Severity.MEDIUM, category="network", pattern_id="p2"),
        ],
    )
    # Second finding should add less than the first
    assert double.score.value < single.score.value * 2


def test_verdict_summary_not_empty() -> None:
    """Every verdict must have a non-empty summary string."""
    verdict_safe = compute_verdict("test", "1.0", [])
    assert verdict_safe.summary

    verdict_blocked = compute_verdict(
        "test",
        "1.0",
        [
            _make_finding(severity=Severity.CRITICAL),
        ],
    )
    assert verdict_blocked.summary


def test_verdict_contains_package_info() -> None:
    """Verdict must carry the package name and version."""
    verdict = compute_verdict("my-package", "2.5.0", [])
    assert verdict.package_name == "my-package"
    assert verdict.package_version == "2.5.0"
