"""Tests for regex scanner."""

import tempfile
from pathlib import Path

from sprobe.patterns.pattern_loader import load_all_patterns
from sprobe.static_analysis.regex_scanner import scan_source_with_regex


def _create_temp_package(file_content: str, filename: str = "__init__.py") -> Path:
    """
    Create a temporary package directory with a single Python file.

    :param file_content: Content to write.
    :param filename: Name of the Python file.
    :returns: Path to the temp directory.
    """
    temp_dir = tempfile.mkdtemp()
    pkg_dir = Path(temp_dir) / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / filename).write_text(file_content, encoding="utf-8")
    return Path(temp_dir)


def test_detects_ssh_key_access() -> None:
    """Regex scanner must detect .ssh/id_rsa access."""
    source = _create_temp_package('path = "~/.ssh/id_rsa"\n')
    patterns = load_all_patterns()
    findings = scan_source_with_regex(source, patterns, "evil-package")
    pattern_ids = {finding.pattern_id for finding in findings}
    assert "ssh_key_read" in pattern_ids


def test_detects_subprocess_spawn() -> None:
    """Regex scanner must detect subprocess.run calls."""
    source = _create_temp_package('import subprocess\nsubprocess.run(["ls"])\n')
    patterns = load_all_patterns()
    findings = scan_source_with_regex(source, patterns, "evil-package")
    pattern_ids = {finding.pattern_id for finding in findings}
    assert "subprocess_spawn" in pattern_ids


def test_skips_expected_for_package() -> None:
    """Patterns with expected_for should not flag known-legitimate packages."""
    source = _create_temp_package('path = "~/.ssh/id_rsa"\n')
    patterns = load_all_patterns()
    findings = scan_source_with_regex(source, patterns, "paramiko")
    ssh_findings = [finding for finding in findings if finding.pattern_id == "ssh_key_read"]
    assert len(ssh_findings) == 0


def test_clean_code_no_findings() -> None:
    """Clean Python code should produce zero findings."""
    source = _create_temp_package("def add(a, b):\n    return a + b\n")
    patterns = load_all_patterns()
    findings = scan_source_with_regex(source, patterns, "clean-lib")
    assert len(findings) == 0


def test_setup_py_scope_respected() -> None:
    """setup_py_exec pattern must only fire on setup.py, not other files."""
    source = _create_temp_package("import subprocess\n", filename="helper.py")
    patterns = load_all_patterns()
    findings = scan_source_with_regex(source, patterns, "some-package")
    setup_findings = [finding for finding in findings if finding.pattern_id == "setup_py_exec"]
    assert len(setup_findings) == 0


def test_setup_py_scope_fires_on_setup_py() -> None:
    """setup_py_exec must fire when subprocess is in setup.py."""
    source = _create_temp_package("import subprocess\n", filename="setup.py")
    patterns = load_all_patterns()
    findings = scan_source_with_regex(source, patterns, "some-package")
    setup_findings = [finding for finding in findings if finding.pattern_id == "setup_py_exec"]
    assert len(setup_findings) == 1
