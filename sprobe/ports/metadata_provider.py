"""
Metadata provider port.

Defines the contract for analyzing package metadata from a registry.
Metadata analysis detects supply chain signals that static code analysis
cannot catch: package age, maintainer changes, typosquatting.
"""

from __future__ import annotations

from typing import List, Protocol

from sprobe.domain.package_info import PackageInfo
from sprobe.domain.scan_finding import ScanFinding


class MetadataProvider(Protocol):
    """Interface for analyzing package metadata from a registry."""

    async def analyze(self, package: PackageInfo) -> List[ScanFinding]:
        """
        Analyze package metadata for supply chain risk signals.

        :param package: Package info with pypi_metadata populated.
        :returns: Findings based on metadata analysis.
        """


__all__ = [
    "MetadataProvider",
]
