"""
AST analyzer adapter.

Combines regex and AST scanning into a single StaticAnalyzer implementation.
This is the default adapter — zero external dependencies, uses only Python
built-in ast module and re module.

Satisfies the StaticAnalyzer protocol defined in sprobe.ports.static_analyzer.
"""

from __future__ import annotations

import logging
from typing import List

logger = logging.getLogger("sprobe")

from sprobe.domain.package_info import PackageInfo
from sprobe.domain.scan_finding import ScanFinding
from sprobe.patterns.pattern_definition import PatternDefinition
from sprobe.static_analysis.ast_scanner import scan_source_with_ast
from sprobe.static_analysis.regex_scanner import scan_source_with_regex


class ASTStaticAnalyzer:
    """
    Default static analyzer combining regex and AST scanning.

    Runs both detection modes against the unpacked package source
    and merges all findings. Regex runs first (faster), then AST
    for structural patterns that regex cannot catch.
    """

    async def analyze(
        self,
        package: PackageInfo,
        patterns: List[PatternDefinition],
    ) -> List[ScanFinding]:
        """
        Run regex and AST analysis on unpacked package source.

        :param package: Package with source_path pointing to unpacked source.
        :param patterns: All loaded patterns (filtered internally by detection_type).
        :returns: Combined findings from both scanners, deduplicated by pattern_id per file.
        """
        if not package.source_path.is_dir():
            logger.error("Source path does not exist: %s", package.source_path)
            return []

        logger.info("Static analysis starting for %s==%s", package.name, package.version)

        regex_findings = scan_source_with_regex(
            source_path=package.source_path,
            patterns=patterns,
            package_name=package.name,
        )

        ast_findings = scan_source_with_ast(
            source_path=package.source_path,
            patterns=patterns,
            package_name=package.name,
        )

        all_findings = _deduplicate_findings(regex_findings + ast_findings)

        logger.info(
            "Static analysis complete: %d findings (%d regex, %d AST)",
            len(all_findings),
            len(regex_findings),
            len(ast_findings),
        )

        return all_findings


def _deduplicate_findings(findings: List[ScanFinding]) -> List[ScanFinding]:
    """
    Remove duplicate findings for the same pattern in the same file.

    Keeps the finding with the highest severity when duplicates exist.

    :param findings: Raw findings from all scanners.
    :returns: Deduplicated findings.
    """
    seen: dict[tuple[str, str | None], ScanFinding] = {}

    for finding in findings:
        dedup_key = (finding.pattern_id, finding.source_file)
        existing = seen.get(dedup_key)

        if existing is None or finding.severity.value > existing.severity.value:
            seen[dedup_key] = finding

    return list(seen.values())


__all__ = [
    "ASTStaticAnalyzer",
]
