"""Tests for typosquatting detector."""

from sprobe.metadata.typosquat_detector import detect_typosquatting


def test_single_char_typo_detected() -> None:
    """Single character difference from popular package must be caught."""
    result = detect_typosquatting("requets")
    assert result is not None
    similar_name, distance = result
    assert similar_name == "requests"
    assert distance == 1


def test_two_char_typo_detected() -> None:
    """Two character differences must be caught within threshold."""
    result = detect_typosquatting("reqeusts")
    assert result is not None
    _, distance = result
    assert distance == 2


def test_exact_match_not_flagged() -> None:
    """Exact popular package name must not be flagged."""
    result = detect_typosquatting("requests")
    assert result is None


def test_unique_name_not_flagged() -> None:
    """Unrelated package name must not be flagged."""
    result = detect_typosquatting("my-completely-unique-library")
    assert result is None


def test_short_names_skipped() -> None:
    """Names shorter than 4 characters are skipped (too many false positives)."""
    result = detect_typosquatting("pip")
    assert result is None


def test_numpy_typo() -> None:
    """Common numpy typosquat must be caught."""
    result = detect_typosquatting("numppy")
    assert result is not None
    assert result[0] == "numpy"


def test_underscore_dash_normalization() -> None:
    """Underscores and dashes are normalized before comparison."""
    result = detect_typosquatting("python_dotenv")
    assert result is None  # exact match after normalization
