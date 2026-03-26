"""
Package fetcher port.

Defines the contract for downloading and unpacking packages
from a package index. The orchestrator depends on this Protocol,
never on a concrete implementation.
"""

from __future__ import annotations

from typing import Protocol

from sprobe.domain.package_info import PackageInfo


class PackageFetcher(Protocol):
    """Interface for fetching packages from a remote index."""

    async def fetch(self, package_specifier: str) -> PackageInfo:
        """
        Download and unpack a package into a temporary directory.

        The caller is responsible for cleaning up source_path after use.

        :param package_specifier: Package name with optional version pin
                                  (e.g. 'requests', 'flask==3.0.0').
        :returns: PackageInfo with source_path pointing to unpacked source.
        :raises PackageFetchError: If download, hash verification, or unpacking fails.
        """


class PackageFetchError(Exception):
    """Raised when package fetching fails at any stage."""


__all__ = [
    "PackageFetcher",
    "PackageFetchError",
]
