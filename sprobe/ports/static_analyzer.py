"""
Static analyzer port.

Defines the contract that any static analysis adapter must satisfy.
The orchestrator depends on this Protocol, never on a concrete implementation.
Swap ASTAnalyzer for SemgrepAnalyzer by changing one line in the composition root.
"""

from __future__ import annotations

from typing import List, Protocol

from sprobe.domain.package_info import PackageInfo
from sprobe.domain.scan_finding import ScanFinding
from sprobe.patterns.pattern_definition import PatternDefinition


class StaticAnalyzer(Protocol):
    """Interface for static analysis of unpacked package source code."""

    async def analyze(
        self,
        package: PackageInfo,
        patterns: List[PatternDefinition],
    ) -> List[ScanFinding]:
        """
        Scan unpacked package source against the given patterns.

        :param package: Package metadata with source_path pointing to unpacked source.
        :param patterns: Detection patterns to match against.
        :returns: All findings discovered during analysis.
        """


__all__ = [
    "StaticAnalyzer",
]
