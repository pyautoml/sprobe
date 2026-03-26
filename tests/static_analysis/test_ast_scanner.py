"""Tests for AST scanner."""

import tempfile
from pathlib import Path

from sprobe.patterns.pattern_loader import load_all_patterns
from sprobe.static_analysis.ast_scanner import scan_source_with_ast


def _create_temp_package(file_content: str) -> Path:
    """
    Create a temporary package directory with a single Python file.

    :param file_content: Content to write.
    :returns: Path to the temp directory.
    """
    temp_dir = tempfile.mkdtemp()
    pkg_dir = Path(temp_dir) / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "__init__.py").write_text(file_content, encoding="utf-8")
    return Path(temp_dir)


def test_detects_exec_with_dynamic_args() -> None:
    """AST scanner must detect exec() called with a variable argument."""
    source = _create_temp_package('payload = "print(1)"\nexec(payload)\n')
    patterns = load_all_patterns()
    findings = scan_source_with_ast(source, patterns, "evil-package")
    pattern_ids = {finding.pattern_id for finding in findings}
    assert "eval_dynamic_code" in pattern_ids


def test_allows_exec_with_literal() -> None:
    """exec() with a string literal is not flagged (no dynamic input)."""
    source = _create_temp_package('exec("print(1)")\n')
    patterns = load_all_patterns()
    findings = scan_source_with_ast(source, patterns, "safe-package")
    dynamic_findings = [
        finding for finding in findings if finding.pattern_id == "eval_dynamic_code"
    ]
    assert len(dynamic_findings) == 0


def test_detects_base64_exec_chain() -> None:
    """AST scanner must detect base64.b64decode combined with exec."""
    code = "import base64\n" "data = base64.b64decode('dGVzdA==')\n" "exec(data)\n"
    source = _create_temp_package(code)
    patterns = load_all_patterns()
    findings = scan_source_with_ast(source, patterns, "evil-package")
    assert len(findings) > 0


def test_clean_code_no_findings() -> None:
    """Clean Python code should produce zero AST findings."""
    source = _create_temp_package('def greet(name):\n    return f"Hello {name}"\n')
    patterns = load_all_patterns()
    findings = scan_source_with_ast(source, patterns, "clean-lib")
    assert len(findings) == 0


def test_syntax_error_file_skipped() -> None:
    """Files with syntax errors must be skipped without crashing."""
    source = _create_temp_package("def broken(\n")
    patterns = load_all_patterns()
    findings = scan_source_with_ast(source, patterns, "broken-lib")
    # Should not crash, just return empty
    assert isinstance(findings, list)
