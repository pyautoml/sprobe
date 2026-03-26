"""Tests for severity and decision enums."""

from sprobe.domain.severity import Decision, Severity


def test_severity_ordering() -> None:
    """Severity values must be ordered for comparison."""
    assert Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL


def test_severity_weights_are_distinct() -> None:
    """Each severity level has a unique numeric weight."""
    values = [severity.value for severity in Severity]
    assert len(values) == len(set(values))


def test_decision_ordering() -> None:
    """Decision values must be ordered for exit code logic."""
    assert Decision.SAFE < Decision.CAUTION < Decision.DANGER < Decision.BLOCKED


def test_critical_is_heavier_than_low() -> None:
    """CRITICAL (80) should weigh 8x more than LOW (10) in scoring."""
    assert Severity.CRITICAL.value == 8 * Severity.LOW.value
