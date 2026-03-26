"""
Package information data type.

Holds all metadata about a package being analyzed: identity, local paths
after download, and optional PyPI metadata fetched during analysis.
This is the input that flows through the entire analysis pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass(frozen=True, slots=True)
class PackageInfo:
    """
    Information about a package under analysis.

    :param name: Package name as specified by the user.
    :param version: Resolved version string (latest if not specified).
    :param source_path: Local path to the unpacked package source.
    :param sdist_path: Local path to the downloaded sdist or wheel archive.
    :param pypi_metadata: Raw metadata from PyPI JSON API, if fetched.
    """

    name: str
    version: str
    source_path: Path
    sdist_path: Optional[Path] = None
    pypi_metadata: Dict[str, Any] = field(default_factory=dict)


__all__ = [
    "PackageInfo",
]
