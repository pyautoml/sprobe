"""
Regex-based source code scanner.

Scans all Python files in an unpacked package directory against
regex-type pattern rules. Each rule contains a regex pattern that
is matched line-by-line against source code.

This is the fastest detection method — no parsing overhead,
works on any text file. Used for file_access, network, code_execution,
and install_hooks pattern categories.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import List, Set

logger = logging.getLogger("sprobe")

from sprobe.domain.scan_finding import ScanFinding
from sprobe.domain.severity import Severity
from sprobe.patterns.pattern_definition import PatternDefinition

_SCANNABLE_SUFFIXES: frozenset[str] = frozenset({".py", ".pyx", ".pyi"})

# Files that deserve extra scrutiny — malware hides here
_HIGH_PRIORITY_FILES: frozenset[str] = frozenset(
    {
        "setup.py",
        "setup.cfg",
        "__init__.py",
        "conftest.py",
    }
)

# Maximum file size to scan — skip generated or vendored blobs
# 1 MB should cover any reasonable Python source file
_MAX_FILE_SIZE_BYTES: int = 1_048_576

# Directories containing test code — findings here are less suspicious
_TEST_DIRECTORY_NAMES: frozenset[str] = frozenset(
    {"tests", "test", "testing", "test_utils", "testutils"}
)


def scan_source_with_regex(
    source_path: Path,
    patterns: List[PatternDefinition],
    package_name: str,
) -> List[ScanFinding]:
    """
    Scan all Python files under source_path against regex patterns.

    :param source_path: Root directory of unpacked package source.
    :param patterns: Only patterns with detection_type='regex' are used.
    :param package_name: Used to check expected_for and skip false positives.
    :returns: All regex-based findings.
    """
    regex_patterns = [
        pattern
        for pattern in patterns
        if pattern.detection_type == "regex" and pattern.detection_target == "source"
    ]

    if not regex_patterns:
        return []

    python_files = _collect_python_files(source_path)
    findings: List[ScanFinding] = []

    for file_path in python_files:
        file_findings = _scan_single_file(file_path, source_path, regex_patterns, package_name)
        findings.extend(file_findings)

    return findings


def _collect_python_files(source_path: Path) -> List[Path]:
    """
    Collect all scannable Python files, high-priority files first.

    :param source_path: Root directory to scan.
    :returns: Sorted list of Python files to scan.
    """
    high_priority: List[Path] = []
    normal_priority: List[Path] = []

    for file_path in sorted(source_path.rglob("*")):
        if not file_path.is_file():
            continue

        if file_path.suffix.lower() not in _SCANNABLE_SUFFIXES:
            continue

        if file_path.stat().st_size > _MAX_FILE_SIZE_BYTES:
            logger.debug("Skipping oversized file: %s", file_path)
            continue

        if file_path.name in _HIGH_PRIORITY_FILES:
            high_priority.append(file_path)
        else:
            normal_priority.append(file_path)

    return high_priority + normal_priority


def _scan_single_file(
    file_path: Path,
    source_root: Path,
    patterns: List[PatternDefinition],
    package_name: str,
) -> List[ScanFinding]:
    """
    Scan one file against all regex patterns.

    :param file_path: Absolute path to the Python file.
    :param source_root: Package source root, for relative path display.
    :param patterns: Regex patterns to match.
    :param package_name: For expected_for filtering.
    :returns: Findings from this file.
    """
    try:
        source_content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as read_error:
        logger.warning("Cannot read %s: %s", file_path, read_error)
        return []

    source_lines = source_content.splitlines()
    relative_path = str(file_path.relative_to(source_root))
    is_high_priority = file_path.name in _HIGH_PRIORITY_FILES
    is_test_file = _is_test_path(file_path)
    findings: List[ScanFinding] = []
    matched_pattern_ids: Set[str] = set()

    applicable_patterns = _filter_applicable_patterns(patterns, package_name, file_path.name)

    for pattern in applicable_patterns:
        match = _find_first_rule_match(pattern, source_lines)
        if match is None:
            continue

        if pattern.pattern_id in matched_pattern_ids:
            continue

        matched_pattern_ids.add(pattern.pattern_id)
        line_index, line_content = match

        severity = _adjust_severity_for_context(
            pattern.severity, is_high_priority, is_test_file, file_path.name
        )

        findings.append(
            ScanFinding(
                pattern_id=pattern.pattern_id,
                category=pattern.category,
                severity=severity,
                description=pattern.description,
                evidence=line_content.strip(),
                source_file=relative_path,
                line_number=line_index,
                layer="static",
            )
        )

    return findings


def _filter_applicable_patterns(
    patterns: List[PatternDefinition],
    package_name: str,
    filename: str,
) -> List[PatternDefinition]:
    """
    Filter patterns to only those applicable to a given file and package.

    :param patterns: All regex patterns.
    :param package_name: Package name for expected_for check.
    :param filename: Current filename for file_scope check.
    :returns: Applicable patterns.
    """
    return [
        pattern
        for pattern in patterns
        if not pattern.is_expected_for_package(package_name)
        and (not pattern.file_scope or filename in pattern.file_scope)
    ]


def _find_first_rule_match(
    pattern: PatternDefinition,
    source_lines: List[str],
) -> tuple[int, str] | None:
    """
    Find the first line matching any rule in the pattern.

    :param pattern: Pattern with regex rules.
    :param source_lines: Source code lines to scan.
    :returns: Tuple of (line_number, line_content), or None if no match.
    """
    for rule in pattern.rules:
        regex_string = rule.get("pattern", "")
        if not regex_string:
            continue

        try:
            compiled_regex = re.compile(regex_string, re.IGNORECASE)
        except re.error as regex_error:
            logger.warning("Invalid regex in pattern %s: %s", pattern.pattern_id, regex_error)
            continue

        for line_index, line_content in enumerate(source_lines, start=1):
            if compiled_regex.search(line_content):
                return (line_index, line_content)

    return None


def _is_test_path(file_path: Path) -> bool:
    """
    Check if a file lives inside a test directory.

    :param file_path: Absolute path to the file.
    :returns: True if any parent directory is a test directory.
    """
    return any(part in _TEST_DIRECTORY_NAMES for part in file_path.parts)


def _adjust_severity_for_context(
    base_severity: Severity,
    is_high_priority_file: bool,
    is_test_file: bool,
    filename: str,
) -> Severity:
    """
    Adjust severity based on file location.

    setup.py running subprocess is worse than a utility module doing it.
    Test files are less suspicious than production code.

    :param base_severity: Pattern's base severity.
    :param is_high_priority_file: Whether this file is setup.py, __init__.py, etc.
    :param is_test_file: Whether this file is inside a test directory.
    :param filename: Name of the file for context-specific adjustments.
    :returns: Adjusted severity.
    """
    # Test files get severity dropped one level
    if is_test_file:
        severity_levels = sorted(Severity, key=lambda s: s.value)
        current_index = severity_levels.index(base_severity)
        prev_index = max(current_index - 1, 0)
        return severity_levels[prev_index]

    if not is_high_priority_file:
        return base_severity

    # setup.py with suspicious code is always escalated — classic attack vector
    if filename == "setup.py" and base_severity.value < Severity.CRITICAL.value:
        return Severity(min(base_severity.value * 2, Severity.CRITICAL.value))

    return base_severity


__all__ = [
    "scan_source_with_regex",
]
