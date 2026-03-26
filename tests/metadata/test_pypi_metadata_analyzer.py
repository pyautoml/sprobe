"""Tests for PyPI metadata analyzer."""

import asyncio
from pathlib import Path

from sprobe.domain.package_info import PackageInfo
from sprobe.metadata.pypi_metadata_analyzer import PyPIMetadataAnalyzer


def _make_package(
    name: str = "test-package",
    metadata: dict | None = None,
) -> PackageInfo:
    """
    Create a PackageInfo with given metadata for testing.

    :param name: Package name.
    :param metadata: PyPI metadata dict.
    :returns: PackageInfo instance.
    """
    return PackageInfo(
        name=name,
        version="1.0.0",
        source_path=Path("/tmp/nonexistent"),
        pypi_metadata=metadata or {},
    )


def test_typosquatting_detected() -> None:
    """Packages with names close to popular packages must be flagged."""
    package = _make_package(name="requets", metadata={"summary": "A lib"})
    analyzer = PyPIMetadataAnalyzer()
    findings = asyncio.run(analyzer.analyze(package))
    typo_findings = [finding for finding in findings if finding.pattern_id == "typosquatting"]
    assert len(typo_findings) == 1
    assert typo_findings[0].severity.name == "CRITICAL"


def test_empty_description_flagged() -> None:
    """Packages with no description must be flagged."""
    package = _make_package(metadata={"summary": ""})
    analyzer = PyPIMetadataAnalyzer()
    findings = asyncio.run(analyzer.analyze(package))
    desc_findings = [finding for finding in findings if finding.pattern_id == "empty_description"]
    assert len(desc_findings) == 1


def test_no_maintainer_flagged() -> None:
    """Packages with no author info must be flagged."""
    package = _make_package(
        metadata={
            "summary": "A legit description",
            "author": "",
            "author_email": "",
            "maintainer": "",
            "maintainer_email": "",
        }
    )
    analyzer = PyPIMetadataAnalyzer()
    findings = asyncio.run(analyzer.analyze(package))
    maintainer_findings = [
        finding for finding in findings if finding.pattern_id == "no_maintainer"
    ]
    assert len(maintainer_findings) == 1


def test_no_project_urls_flagged() -> None:
    """Packages with no project URLs must be flagged."""
    package = _make_package(
        metadata={
            "summary": "A legit description",
            "author": "Someone",
            "project_urls": None,
            "home_page": "",
        }
    )
    analyzer = PyPIMetadataAnalyzer()
    findings = asyncio.run(analyzer.analyze(package))
    url_findings = [finding for finding in findings if finding.pattern_id == "no_project_urls"]
    assert len(url_findings) == 1


def test_healthy_package_no_findings() -> None:
    """A well-maintained package must produce no metadata findings."""
    package = _make_package(
        name="my-unique-lib",
        metadata={
            "summary": "A well-described package for doing useful things",
            "author": "Jane Developer",
            "author_email": "jane@example.com",
            "project_urls": {"Homepage": "https://github.com/jane/my-lib"},
            "home_page": "https://github.com/jane/my-lib",
        },
    )
    analyzer = PyPIMetadataAnalyzer()
    findings = asyncio.run(analyzer.analyze(package))
    assert len(findings) == 0


def test_no_metadata_skipped() -> None:
    """Packages with no PyPI metadata produce no findings (not an error)."""
    package = _make_package(metadata={})
    analyzer = PyPIMetadataAnalyzer()
    findings = asyncio.run(analyzer.analyze(package))
    assert len(findings) == 0
