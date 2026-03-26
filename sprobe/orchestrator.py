"""
Scan orchestrator.

Coordinates the analysis pipeline: loads patterns, runs static analysis,
computes the verdict, and renders the report. Each layer is pluggable
via dependency injection — swap analyzers by changing the composition root.

Currently supports:
  - Package fetching from PyPI with SHA256 verification
  - Static analysis (regex + AST)
  - Scoring engine
  - Terminal reporting

sprobe never installs packages. It downloads to a temporary directory,
analyzes, reports, and cleans up. The user decides whether to install.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("sprobe")

from sprobe.domain.package_info import PackageInfo
from sprobe.domain.risk_verdict import RiskVerdict
from sprobe.domain.scan_finding import ScanFinding
from sprobe.fetching.pypi_fetcher import PyPIFetcher
from sprobe.metadata.pypi_metadata_analyzer import PyPIMetadataAnalyzer
from sprobe.patterns.pattern_definition import PatternDefinition
from sprobe.patterns.pattern_loader import load_all_patterns
from sprobe.ports.package_fetcher import PackageFetchError
from sprobe.reporting.terminal_reporter import TerminalReporter
from sprobe.sandbox.bwrap_runner import BwrapSandboxRunner
from sprobe.scoring.risk_scorer import compute_verdict
from sprobe.static_analysis.ast_analyzer import ASTStaticAnalyzer


class ScanOrchestrator:
    """
    Coordinates the full analysis pipeline for a package.

    Receives pluggable analyzers, fetcher, and reporter via constructor injection.
    The orchestrator itself holds no detection logic — it only sequences
    the layers and passes data between them.
    """

    def __init__(
        self,
        static_analyzer: Optional[ASTStaticAnalyzer] = None,
        fetcher: Optional[PyPIFetcher] = None,
        reporter: Optional[TerminalReporter] = None,
        extra_pattern_dirs: Optional[List[Path]] = None,
        skip_sandbox: bool = False,
    ) -> None:
        """
        Initialize with pluggable components.

        :param static_analyzer: Static analysis adapter. Defaults to ASTStaticAnalyzer.
        :param fetcher: Package fetcher adapter. Defaults to PyPIFetcher.
        :param reporter: Report renderer. Defaults to TerminalReporter.
        :param extra_pattern_dirs: Additional directories to load patterns from.
        :param skip_sandbox: If True, skip sandbox analysis entirely.
        """
        self._static_analyzer = static_analyzer or ASTStaticAnalyzer()
        self._metadata_analyzer = PyPIMetadataAnalyzer()
        self._sandbox_runner: Optional[BwrapSandboxRunner] = (
            None if skip_sandbox else BwrapSandboxRunner()
        )
        self._fetcher = fetcher or PyPIFetcher()
        self._reporter = reporter or TerminalReporter()
        self._patterns: List[PatternDefinition] = load_all_patterns(
            extra_dirs=extra_pattern_dirs,
        )

    async def scan_local(
        self,
        source_path: Path,
        package_name: str,
        package_version: str = "unknown",
    ) -> RiskVerdict:
        """
        Scan an unpacked local package directory.

        :param source_path: Path to unpacked package source.
        :param package_name: Package name for display and expected_for filtering.
        :param package_version: Package version for display.
        :returns: Computed risk verdict.
        """
        package = PackageInfo(
            name=package_name,
            version=package_version,
            source_path=source_path,
        )

        return await self._run_analysis(package)

    async def check_pypi(self, package_specifier: str) -> RiskVerdict:
        """
        Download a single package from PyPI, analyze it, report, and clean up.

        Downloads to a temporary directory, runs all analysis layers,
        renders the report, then deletes the temporary directory.
        Never installs anything.

        :param package_specifier: Package name with optional version
                                  (e.g. 'requests', 'flask==3.0.0').
        :returns: Computed risk verdict.
        :raises PackageFetchError: If download or verification fails.
        """
        package = await self._fetcher.fetch(package_specifier)
        temp_root = package.source_path.parent

        try:
            return await self._run_analysis(package)
        finally:
            logger.debug("Cleaning up temporary directory: %s", temp_root)
            shutil.rmtree(temp_root, ignore_errors=True)

    async def check_pypi_batch(
        self,
        package_specifiers: List[str],
    ) -> List[RiskVerdict]:
        """
        Download and analyze multiple packages concurrently.

        Non-existent or unfetchable packages are logged as warnings
        and skipped. Remaining packages are analyzed concurrently.

        :param package_specifiers: List of package names with optional versions.
        :returns: List of verdicts for successfully fetched packages.
        """
        async with asyncio.TaskGroup() as task_group:
            tasks = [
                task_group.create_task(self._check_single_safe(specifier))
                for specifier in package_specifiers
            ]

        return [task.result() for task in tasks if task.result() is not None]

    async def _check_single_safe(
        self,
        package_specifier: str,
    ) -> RiskVerdict | None:
        """
        Fetch and analyze a single package, returning None on failure.

        Catches PackageFetchError so one bad package does not
        abort the entire batch.

        :param package_specifier: Package name with optional version.
        :returns: Risk verdict, or None if the package could not be fetched.
        """
        try:
            return await self.check_pypi(package_specifier)
        except PackageFetchError as fetch_error:
            logger.warning("Skipping '%s': %s", package_specifier, fetch_error)
            self._reporter.render_skip(package_specifier, str(fetch_error))
            return None

    async def _run_analysis(self, package: PackageInfo) -> RiskVerdict:
        """
        Run all analysis layers on a package and return the verdict.

        :param package: Package info with source_path pointing to source code.
        :returns: Computed risk verdict.
        """
        logger.info("Scanning %s==%s", package.name, package.version)

        all_findings: List[ScanFinding] = []

        # Layer 1: Static analysis
        static_findings = await self._static_analyzer.analyze(package, self._patterns)
        all_findings.extend(static_findings)

        # Layer 2: Metadata analysis
        metadata_findings = await self._metadata_analyzer.analyze(package)
        all_findings.extend(metadata_findings)

        # Layer 3: Sandbox execution
        if self._sandbox_runner is not None:
            sandbox_findings = await self._sandbox_runner.analyze(package)
            all_findings.extend(sandbox_findings)

        verdict = compute_verdict(
            package_name=package.name,
            package_version=package.version,
            findings=all_findings,
        )

        self._reporter.render(verdict)

        return verdict


__all__ = [
    "ScanOrchestrator",
]
