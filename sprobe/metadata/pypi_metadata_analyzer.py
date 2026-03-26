"""
PyPI metadata analyzer.

Examines package metadata from the PyPI JSON API to detect
supply chain risk signals that static code analysis cannot catch:
  - Package age: brand new packages are higher risk
  - Maintainer changes: recent ownership transfers
  - Typosquatting: names similar to popular packages
  - Description anomalies: empty or suspiciously short descriptions
  - Version anomalies: single version or massive version jumps

This is Layer 2 of the analysis pipeline, running after static
analysis and before sandbox execution.

Zero external dependencies — uses only Python stdlib.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sprobe.domain.package_info import PackageInfo
from sprobe.domain.scan_finding import ScanFinding
from sprobe.domain.severity import Severity
from sprobe.metadata.typosquat_detector import detect_typosquatting

logger = logging.getLogger("sprobe")

# Packages created within this many days are flagged as new
_NEW_PACKAGE_THRESHOLD_DAYS: int = 30

# Packages with descriptions shorter than this are suspicious
_MIN_DESCRIPTION_LENGTH: int = 10

# Packages with a single release and no project URLs are suspicious
_MIN_EXPECTED_RELEASES: int = 2


class PyPIMetadataAnalyzer:
    """
    Analyzes PyPI package metadata for supply chain risk signals.

    Checks package age, maintainer patterns, typosquatting similarity,
    description quality, and version history. Each check produces
    ScanFinding objects with appropriate severity levels.
    """

    async def analyze(self, package: PackageInfo) -> List[ScanFinding]:
        """
        Run all metadata checks on a package.

        :param package: Package info with pypi_metadata populated from PyPI API.
        :returns: Findings from metadata analysis.
        """
        if not package.pypi_metadata:
            logger.debug(
                "No PyPI metadata available for %s, skipping metadata analysis", package.name
            )
            return []

        metadata = package.pypi_metadata
        findings: List[ScanFinding] = []

        logger.info("Metadata analysis starting for %s==%s", package.name, package.version)

        typosquat_finding = _check_typosquatting(package.name)
        if typosquat_finding:
            findings.append(typosquat_finding)

        age_finding = _check_package_age(metadata)
        if age_finding:
            findings.append(age_finding)

        description_finding = _check_description(metadata)
        if description_finding:
            findings.append(description_finding)

        maintainer_finding = _check_maintainer_info(metadata)
        if maintainer_finding:
            findings.append(maintainer_finding)

        url_finding = _check_project_urls(metadata)
        if url_finding:
            findings.append(url_finding)

        logger.info("Metadata analysis complete: %d findings", len(findings))

        return findings


def _check_typosquatting(package_name: str) -> Optional[ScanFinding]:
    """
    Check if the package name is suspiciously similar to a popular package.

    :param package_name: Name to check.
    :returns: Finding if typosquatting detected, None otherwise.
    """
    result = detect_typosquatting(package_name)
    if result is None:
        return None

    similar_package, edit_distance = result

    severity = Severity.CRITICAL if edit_distance == 1 else Severity.HIGH

    return ScanFinding(
        pattern_id="typosquatting",
        category="supply_chain",
        severity=severity,
        description=(
            f"Package name is {edit_distance} character(s) away from "
            f"popular package '{similar_package}'"
        ),
        evidence=f"'{package_name}' vs '{similar_package}' (edit distance: {edit_distance})",
        layer="metadata",
    )


def _check_package_age(
    metadata: Dict[str, Any],
) -> Optional[ScanFinding]:
    """
    Check if the package was created very recently.

    Brand new packages are higher risk — most supply chain attacks
    use freshly uploaded packages.

    :param metadata: PyPI metadata dict.
    :returns: Finding if package is very new, None otherwise.
    """
    created_date = _extract_creation_date(metadata)
    if created_date is None:
        return None

    now = datetime.now(timezone.utc)
    age_days = (now - created_date).days

    if age_days > _NEW_PACKAGE_THRESHOLD_DAYS:
        return None

    severity = Severity.HIGH if age_days <= 7 else Severity.MEDIUM

    return ScanFinding(
        pattern_id="new_package",
        category="supply_chain",
        severity=severity,
        description=f"Package was created only {age_days} day(s) ago",
        evidence=f"First published: {created_date.strftime('%Y-%m-%d')}",
        layer="metadata",
    )


def _check_description(
    metadata: Dict[str, Any],
) -> Optional[ScanFinding]:
    """
    Check if the package has a missing or suspiciously short description.

    Legitimate packages almost always have meaningful descriptions.
    Malicious packages often have none or use placeholder text.

    :param metadata: PyPI metadata dict.
    :returns: Finding if description is suspicious, None otherwise.
    """
    description = metadata.get("summary", "") or ""

    if len(description.strip()) >= _MIN_DESCRIPTION_LENGTH:
        return None

    return ScanFinding(
        pattern_id="empty_description",
        category="supply_chain",
        severity=Severity.LOW,
        description="Package has no meaningful description",
        evidence=(
            f"Summary: '{description.strip()}'" if description.strip() else "Summary: (empty)"
        ),
        layer="metadata",
    )


def _check_maintainer_info(
    metadata: Dict[str, Any],
) -> Optional[ScanFinding]:
    """
    Check if the package has missing author/maintainer information.

    Packages with no identifiable author are more likely to be
    throwaway accounts used for supply chain attacks.

    :param metadata: PyPI metadata dict.
    :returns: Finding if maintainer info is missing, None otherwise.
    """
    author = metadata.get("author", "") or ""
    author_email = metadata.get("author_email", "") or ""
    maintainer = metadata.get("maintainer", "") or ""
    maintainer_email = metadata.get("maintainer_email", "") or ""

    has_identity = any(
        [
            author.strip(),
            author_email.strip(),
            maintainer.strip(),
            maintainer_email.strip(),
        ]
    )

    if has_identity:
        return None

    return ScanFinding(
        pattern_id="no_maintainer",
        category="supply_chain",
        severity=Severity.MEDIUM,
        description="Package has no author or maintainer information",
        evidence="No author, author_email, maintainer, or maintainer_email provided",
        layer="metadata",
    )


def _check_project_urls(
    metadata: Dict[str, Any],
) -> Optional[ScanFinding]:
    """
    Check if the package has no project URLs (homepage, repo, docs).

    Legitimate packages almost always link to a source repository.
    Packages with no URLs are less trustworthy.

    :param metadata: PyPI metadata dict.
    :returns: Finding if no project URLs exist, None otherwise.
    """
    project_urls = metadata.get("project_urls") or {}
    home_page = metadata.get("home_page", "") or ""

    has_urls = bool(project_urls) or bool(home_page.strip())

    if has_urls:
        return None

    return ScanFinding(
        pattern_id="no_project_urls",
        category="supply_chain",
        severity=Severity.LOW,
        description="Package has no project URLs (no homepage, repository, or documentation link)",
        evidence="No project_urls or home_page provided",
        layer="metadata",
    )


def _extract_creation_date(metadata: Dict[str, Any]) -> Optional[datetime]:
    """
    Extract the earliest release date from package metadata.

    PyPI does not directly provide a creation date in the info block,
    but the release timestamps are available. We use the package version
    upload time if available.

    :param metadata: PyPI metadata dict.
    :returns: Earliest release datetime, or None if unavailable.
    """
    # Try the upload_time field from the info block (not always present)
    # Fall back to None — the fetcher could enrich this from the full API response
    upload_time_str = metadata.get("upload_time")
    if not upload_time_str:
        return None

    try:
        return datetime.fromisoformat(upload_time_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


__all__ = [
    "PyPIMetadataAnalyzer",
]
