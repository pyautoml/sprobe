"""
Scan finding data type.

Represents a single suspicious behavior detected during any analysis layer.
Each finding links back to the pattern that matched via pattern_id,
allowing traceability from verdict back to detection rule.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from sprobe.domain.severity import Severity


@dataclass(frozen=True, slots=True)
class ScanFinding:
    """
    Single suspicious behavior detected during package analysis.

    :param pattern_id: Identifier of the pattern that matched.
    :param category: Pattern group this belongs to (file_access, network, etc).
    :param severity: Risk severity of this finding.
    :param description: Human-readable explanation of what was found.
    :param evidence: The actual code snippet, syscall, or data that triggered the match.
    :param source_file: File within the package where the finding was detected.
    :param line_number: Line number within the source file, if applicable.
    :param layer: Which analysis layer produced this finding (static, metadata, sandbox).
    """

    pattern_id: str
    category: str
    severity: Severity
    description: str
    evidence: str
    source_file: Optional[str] = None
    line_number: Optional[int] = None
    layer: str = "static"


__all__ = [
    "ScanFinding",
]
