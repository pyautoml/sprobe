"""Tests for RiskScore and RiskVerdict."""

from sprobe.domain.risk_verdict import RiskScore, RiskVerdict
from sprobe.domain.severity import Decision


def test_score_zero_is_safe() -> None:
    """Score 0 must map to SAFE."""
    score = RiskScore(value=0)
    assert score.decision == Decision.SAFE


def test_score_15_is_safe_boundary() -> None:
    """Score 15 is the upper boundary of SAFE."""
    score = RiskScore(value=15)
    assert score.decision == Decision.SAFE


def test_score_16_is_caution() -> None:
    """Score 16 crosses into CAUTION."""
    score = RiskScore(value=16)
    assert score.decision == Decision.CAUTION


def test_score_35_is_caution_boundary() -> None:
    """Score 35 is the upper boundary of CAUTION."""
    score = RiskScore(value=35)
    assert score.decision == Decision.CAUTION


def test_score_36_is_danger() -> None:
    """Score 36 crosses into DANGER."""
    score = RiskScore(value=36)
    assert score.decision == Decision.DANGER


def test_score_60_is_danger_boundary() -> None:
    """Score 60 is the upper boundary of DANGER."""
    score = RiskScore(value=60)
    assert score.decision == Decision.DANGER


def test_score_61_is_blocked() -> None:
    """Score 61 crosses into BLOCKED."""
    score = RiskScore(value=61)
    assert score.decision == Decision.BLOCKED


def test_score_100_is_blocked() -> None:
    """Maximum score is BLOCKED."""
    score = RiskScore(value=100)
    assert score.decision == Decision.BLOCKED


def test_score_clamped_above_100() -> None:
    """Scores above 100 are clamped to 100."""
    score = RiskScore(value=150)
    assert score.value == 100


def test_score_clamped_below_0() -> None:
    """Scores below 0 are clamped to 0."""
    score = RiskScore(value=-5)
    assert score.value == 0


def test_verdict_decision_shortcut() -> None:
    """Verdict.decision delegates to score.decision."""
    verdict = RiskVerdict(
        package_name="test",
        package_version="1.0",
        score=RiskScore(value=80),
    )
    assert verdict.decision == Decision.BLOCKED


def test_verdict_safe_with_no_findings() -> None:
    """Empty findings list produces SAFE verdict."""
    verdict = RiskVerdict(
        package_name="test",
        package_version="1.0",
        score=RiskScore(value=0),
        findings=[],
    )
    assert verdict.decision == Decision.SAFE
    assert len(verdict.findings) == 0
