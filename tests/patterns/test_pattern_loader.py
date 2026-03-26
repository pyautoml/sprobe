"""Tests for pattern loader."""

import tempfile
from pathlib import Path

from sprobe.patterns.pattern_loader import load_all_patterns


def test_builtin_patterns_load() -> None:
    """Built-in patterns directory must produce at least 10 patterns."""
    patterns = load_all_patterns()
    assert len(patterns) >= 10


def test_all_patterns_have_required_fields() -> None:
    """Every loaded pattern must have id, category, severity, and rules."""
    patterns = load_all_patterns()
    for pattern in patterns:
        assert pattern.pattern_id, f"Pattern missing id: {pattern}"
        assert pattern.category, f"Pattern {pattern.pattern_id} missing category"
        assert pattern.severity is not None, f"Pattern {pattern.pattern_id} missing severity"
        assert isinstance(pattern.rules, list), f"Pattern {pattern.pattern_id} rules not a list"


def test_all_categories_present() -> None:
    """Built-in patterns must cover all expected categories."""
    patterns = load_all_patterns()
    categories = {pattern.category for pattern in patterns}
    expected_categories = {
        "file_access",
        "network",
        "obfuscation",
        "code_execution",
        "install_hooks",
    }
    assert expected_categories.issubset(categories)


def test_extra_dirs_loaded() -> None:
    """Patterns from extra directories are loaded alongside built-in ones."""
    with tempfile.TemporaryDirectory() as temp_dir:
        custom_pattern = Path(temp_dir) / "custom.toml"
        custom_pattern.write_text(
            'id = "test_custom"\n'
            'category = "custom"\n'
            'severity = "low"\n'
            'description = "Test pattern"\n'
            "\n"
            "[detection]\n"
            'type = "regex"\n'
            'target = "source"\n'
            "\n"
            "[[detection.rules]]\n"
            "pattern = 'test_match'\n",
            encoding="utf-8",
        )

        patterns = load_all_patterns(extra_dirs=[Path(temp_dir)])
        pattern_ids = {pattern.pattern_id for pattern in patterns}
        assert "test_custom" in pattern_ids


def test_invalid_toml_skipped() -> None:
    """Invalid TOML files are skipped without crashing."""
    with tempfile.TemporaryDirectory() as temp_dir:
        bad_file = Path(temp_dir) / "bad.toml"
        bad_file.write_text("this is not valid toml [[[", encoding="utf-8")

        patterns = load_all_patterns(extra_dirs=[Path(temp_dir)])
        # Should still load built-in patterns without error
        assert len(patterns) >= 10
