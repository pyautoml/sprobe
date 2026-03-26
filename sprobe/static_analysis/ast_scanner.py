"""
AST-based source code scanner.

Walks the Python Abstract Syntax Tree of each file to detect
structural patterns that regex cannot reliably catch:
  - eval/exec/compile with dynamic (non-literal) arguments
  - base64.b64decode chained with exec/eval
  - marshal.loads combined with exec
  - __import__ calls with dynamic arguments

Uses Python's built-in ast module — zero external dependencies.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import List, Set

from sprobe.domain.scan_finding import ScanFinding
from sprobe.domain.severity import Severity
from sprobe.patterns.pattern_definition import PatternDefinition

logger = logging.getLogger("sprobe")

_SCANNABLE_SUFFIXES: frozenset[str] = frozenset({".py", ".pyx"})
_MAX_FILE_SIZE_BYTES: int = 1_048_576

_TEST_DIRECTORY_NAMES: frozenset[str] = frozenset(
    {"tests", "test", "testing", "test_utils", "testutils"}
)

# Functions that execute dynamic code — always suspicious with non-literal args
_DYNAMIC_EXEC_FUNCTIONS: frozenset[str] = frozenset({"eval", "exec", "compile"})

# Functions that decode/deserialize — suspicious when combined with exec
_DECODE_FUNCTIONS: frozenset[str] = frozenset(
    {
        "b64decode",
        "b32decode",
        "b16decode",
        "loads",  # marshal.loads, pickle.loads
        "decompress",  # zlib.decompress
    }
)


def scan_source_with_ast(
    source_path: Path,
    patterns: List[PatternDefinition],
    package_name: str,
) -> List[ScanFinding]:
    """
    Scan all Python files under source_path using AST analysis.

    :param source_path: Root directory of unpacked package source.
    :param patterns: Only patterns with detection_type='ast' are used.
    :param package_name: Used to check expected_for and skip false positives.
    :returns: All AST-based findings.
    """
    ast_patterns = [
        pattern
        for pattern in patterns
        if pattern.detection_type == "ast" and pattern.detection_target == "source"
    ]

    if not ast_patterns:
        return []

    findings: List[ScanFinding] = []

    for file_path in sorted(source_path.rglob("*")):
        if not file_path.is_file():
            continue
        if file_path.suffix.lower() not in _SCANNABLE_SUFFIXES:
            continue
        if file_path.stat().st_size > _MAX_FILE_SIZE_BYTES:
            continue

        file_findings = _analyze_file_ast(file_path, source_path, ast_patterns, package_name)
        findings.extend(file_findings)

    return findings


def _analyze_file_ast(
    file_path: Path,
    source_root: Path,
    patterns: List[PatternDefinition],
    package_name: str,
) -> List[ScanFinding]:
    """
    Parse one file into AST and check for suspicious structures.

    :param file_path: Python file to analyze.
    :param source_root: Package root for relative path display.
    :param patterns: AST patterns to check.
    :param package_name: For expected_for filtering.
    :returns: Findings from this file.
    """
    source_code = _read_source_safe(file_path)
    if source_code is None:
        return []

    try:
        tree = ast.parse(source_code, filename=str(file_path))
    except SyntaxError:
        logger.debug("Syntax error parsing %s, skipping AST analysis", file_path)
        return []

    relative_path = str(file_path.relative_to(source_root))
    source_lines = source_code.splitlines()
    detected_issues = _walk_tree_for_suspicious_calls(tree)

    is_test_file = any(part in _TEST_DIRECTORY_NAMES for part in file_path.parts)

    return _convert_issues_to_findings(
        detected_issues,
        patterns,
        package_name,
        relative_path,
        source_lines,
        is_test_file,
    )


def _read_source_safe(file_path: Path) -> str | None:
    """
    Read a source file, returning None on failure.

    :param file_path: Path to the Python file.
    :returns: File contents, or None if unreadable.
    """
    try:
        return file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as read_error:
        logger.warning("Cannot read %s: %s", file_path, read_error)
        return None


def _demote_severity(severity: Severity) -> Severity:
    """
    Drop severity by one level (e.g. HIGH -> MEDIUM).

    :param severity: Original severity.
    :returns: One level lower, minimum LOW.
    """
    severity_levels = sorted(Severity, key=lambda s: s.value)
    current_index = severity_levels.index(severity)
    prev_index = max(current_index - 1, 0)
    return severity_levels[prev_index]


def _convert_issues_to_findings(
    issues: List[dict],
    patterns: List[PatternDefinition],
    package_name: str,
    relative_path: str,
    source_lines: List[str],
    is_test_file: bool = False,
) -> List[ScanFinding]:
    """
    Convert raw AST issues into ScanFinding objects matched against patterns.

    :param issues: Issue dicts from AST walk.
    :param patterns: AST patterns to match against.
    :param package_name: For expected_for filtering.
    :param relative_path: Relative file path for display.
    :param source_lines: Source code lines for evidence extraction.
    :param is_test_file: Whether this file is inside a test directory.
    :returns: Matched findings.
    """
    findings: List[ScanFinding] = []

    for issue in issues:
        matched_pattern = _match_issue_to_pattern(issue, patterns, package_name)
        if matched_pattern is None:
            continue

        line_number = issue.get("line", 0)
        evidence_line = ""
        if 0 < line_number <= len(source_lines):
            evidence_line = source_lines[line_number - 1].strip()

        severity = _demote_severity(matched_pattern.severity) if is_test_file else matched_pattern.severity

        findings.append(
            ScanFinding(
                pattern_id=matched_pattern.pattern_id,
                category=matched_pattern.category,
                severity=severity,
                description=matched_pattern.description,
                evidence=evidence_line,
                source_file=relative_path,
                line_number=line_number,
                layer="static",
            )
        )

    return findings


def _walk_tree_for_suspicious_calls(tree: ast.Module) -> List[dict]:
    """
    Walk AST and detect suspicious call patterns.

    Detects:
      - eval/exec/compile with non-literal arguments
      - Decode functions (b64decode, loads) whose result flows into exec/eval
      - __import__ with dynamic arguments

    :param tree: Parsed AST module.
    :returns: List of issue dicts with keys: type, function, line, detail.
    """
    issues: List[dict] = []
    all_call_names: Set[str] = set()

    # First pass: collect all function names called in the module
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_name = _extract_call_name(node)
            if call_name:
                all_call_names.add(call_name)

    # Second pass: detect suspicious patterns
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        call_name = _extract_call_name(node)
        if not call_name:
            continue

        # Dynamic exec/eval/compile
        if call_name in _DYNAMIC_EXEC_FUNCTIONS and _has_dynamic_args(node):
            issues.append(
                {
                    "type": "dynamic_exec",
                    "function": call_name,
                    "line": node.lineno,
                    "detail": f"{call_name}() called with dynamic argument",
                }
            )

        # Decode + exec chain: b64decode exists AND exec/eval exists in same file
        if call_name in _DECODE_FUNCTIONS:
            exec_present = _DYNAMIC_EXEC_FUNCTIONS.intersection(all_call_names)
            if exec_present:
                issues.append(
                    {
                        "type": "decode_exec_chain",
                        "function": call_name,
                        "line": node.lineno,
                        "detail": f"{call_name}() in same file as {', '.join(exec_present)}",
                    }
                )

        # Dynamic __import__
        if call_name == "__import__" and _has_dynamic_args(node):
            issues.append(
                {
                    "type": "dynamic_import",
                    "function": call_name,
                    "line": node.lineno,
                    "detail": "__import__() with dynamic argument",
                }
            )

    return issues


def _extract_call_name(node: ast.Call) -> str:
    """
    Extract the function name from a Call node.

    Handles: func(), module.func(), module.sub.func().

    :param node: AST Call node.
    :returns: Dotted function name, or empty string if unresolvable.
    """
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        parts = []
        current = node.func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return ""


def _has_dynamic_args(node: ast.Call) -> bool:
    """
    Check if a Call node has non-literal arguments.

    A literal argument is a string, number, or constant.
    Anything else (variable, function call, attribute access) is dynamic.

    :param node: AST Call node.
    :returns: True if any argument is non-literal.
    """
    if not node.args:
        return False

    for argument in node.args:
        if not isinstance(argument, (ast.Constant, ast.JoinedStr)):
            return True

    return False


def _match_issue_to_pattern(
    issue: dict,
    patterns: List[PatternDefinition],
    package_name: str,
) -> PatternDefinition | None:
    """
    Find the best matching pattern for a detected issue.

    :param issue: Issue dict from AST walk.
    :param patterns: Available AST patterns.
    :param package_name: For expected_for filtering.
    :returns: Best matching pattern, or None.
    """
    issue_type = issue["type"]
    issue_function = issue["function"]

    for pattern in patterns:
        if pattern.is_expected_for_package(package_name):
            continue

        for rule in pattern.rules:
            function_names = rule.get("function_names", [])
            call_chains = rule.get("call_chains", [])
            require_dynamic = rule.get("require_dynamic_args", False)

            if issue_type == "dynamic_exec" and require_dynamic:
                if issue_function in function_names:
                    return pattern

            if issue_type == "decode_exec_chain":
                if issue_function in call_chains or any(
                    issue_function.endswith(chain) for chain in call_chains
                ):
                    return pattern

            if issue_type == "dynamic_import" and issue_function in function_names:
                return pattern

    return None


__all__ = [
    "scan_source_with_ast",
]
