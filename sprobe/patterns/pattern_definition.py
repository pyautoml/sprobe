"""
Pattern definition data type.

A pattern is a single detection rule loaded from a YAML file.
Patterns are grouped by category (file_access, network, obfuscation, etc.)
and can be either built-in or user-contributed.

Detection types:
  - regex: match raw source code against regex patterns
  - ast: match Python AST node structures (function calls, imports)
  - syscall: match strace output during sandbox execution
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional

from sprobe.domain.severity import Severity

_DETECTION_TYPE = Literal["regex", "ast", "syscall"]
_DETECTION_TARGET = Literal["source", "runtime"]


@dataclass(frozen=True, slots=True)
class PatternDefinition:
    """
    Single detection rule loaded from YAML.

    :param pattern_id: Unique identifier for this pattern.
    :param category: Group this pattern belongs to (file_access, network, etc).
    :param severity: Risk severity when this pattern matches.
    :param description: Human-readable explanation of what this detects.
    :param detection_type: How to detect: regex, ast, or syscall.
    :param detection_target: Where to detect: source (static) or runtime (sandbox).
    :param rules: List of match rules, structure depends on detection_type.
    :param file_scope: If set, only scan files matching these filenames.
    :param expected_for: Package names where this behavior is legitimate.
    :param tags: Optional labels for filtering and grouping.
    """

    pattern_id: str
    category: str
    severity: Severity
    description: str
    detection_type: _DETECTION_TYPE
    detection_target: _DETECTION_TARGET
    rules: List[Dict[str, Any]]
    file_scope: List[str] = field(default_factory=list)
    expected_for: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def is_expected_for_package(self, package_name: str) -> bool:
        """
        Check if this pattern is expected behavior for a given package.

        Prevents false positives: paramiko reading .ssh is normal.

        :param package_name: Name of the package being analyzed.
        :returns: True if this behavior is expected for the package.
        """
        return package_name.lower() in [name.lower() for name in self.expected_for]


def severity_from_string(severity_string: str) -> Severity:
    """
    Convert a YAML severity string to Severity enum.

    :param severity_string: One of: low, medium, high, critical.
    :returns: Corresponding Severity enum value.
    :raises ValueError: If the string does not match any severity level.
    """
    severity_map: Dict[str, Severity] = {
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }
    normalized = severity_string.strip().lower()
    if normalized not in severity_map:
        raise ValueError(
            f"Unknown severity '{severity_string}'. "
            f"Valid values: {', '.join(severity_map.keys())}"
        )
    return severity_map[normalized]


__all__ = [
    "PatternDefinition",
    "severity_from_string",
]
