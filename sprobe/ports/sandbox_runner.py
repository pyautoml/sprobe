"""
Sandbox runner port.

Defines the contract for executing a package in an isolated environment
and monitoring its runtime behavior via syscall tracing.
"""

from __future__ import annotations

from typing import List, Protocol

from sprobe.domain.package_info import PackageInfo
from sprobe.domain.scan_finding import ScanFinding


class SandboxRunner(Protocol):
    """Interface for sandbox-based runtime analysis."""

    async def analyze(self, package: PackageInfo) -> List[ScanFinding]:
        """
        Execute a package inside an isolated sandbox and monitor its behavior.

        Runs the package import in a bubblewrap sandbox with strace monitoring
        and honeypot secrets. Never installs — only imports the already-unpacked
        source code.

        :param package: Package info with source_path pointing to unpacked source.
        :returns: Findings from runtime behavior analysis.
        """


__all__ = [
    "SandboxRunner",
]
