"""
PyPI package fetcher.

Downloads source distributions from PyPI, verifies SHA256 integrity,
and unpacks them into a temporary directory for analysis.
Uses only Python stdlib (urllib.request, hashlib, tarfile, zipfile).

Flow:
  1. Parse package specifier ('requests', 'flask==3.0.0')
  2. Query PyPI JSON API for release metadata
  3. Find the sdist (source distribution) download URL
  4. Download the archive
  5. Verify SHA256 against PyPI's published digest
  6. Unpack into temporary directory
  7. Return PackageInfo pointing to unpacked source

Prefers sdist over wheel because we need Python source code for analysis.
Wheels contain compiled bytecode which is harder to inspect statically.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import shutil
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from sprobe.domain.package_info import PackageInfo
from sprobe.ports.package_fetcher import PackageFetchError

logger = logging.getLogger("sprobe")

_PYPI_JSON_API = "https://pypi.org/pypi"

# Maximum download size: 50 MB — reject anything larger
# Legitimate packages rarely exceed this; protects against zip bombs
_MAX_DOWNLOAD_BYTES: int = 50 * 1024 * 1024

# HTTP timeout for PyPI API and download requests
_REQUEST_TIMEOUT_SECONDS: float = 30.0


class PyPIFetcher:
    """
    Fetches packages from PyPI with SHA256 integrity verification.

    Downloads the source distribution, verifies its hash against
    the PyPI-published digest, and unpacks it for static analysis.
    All files are stored in a temporary directory that the caller
    must clean up after use.

    Uses stdlib urllib.request — zero external dependencies.
    Blocking I/O is run via asyncio.run_in_executor for concurrency.
    """

    def __init__(
        self,
        pypi_url: str = _PYPI_JSON_API,
        max_download_bytes: int = _MAX_DOWNLOAD_BYTES,
    ) -> None:
        """
        Initialize with PyPI API base URL.

        :param pypi_url: Base URL for PyPI JSON API. Override for private indexes.
        :param max_download_bytes: Maximum download size in bytes. Default 50 MB.
        """
        self._pypi_url = pypi_url
        self._max_download_bytes = max_download_bytes

    async def fetch(self, package_specifier: str) -> PackageInfo:
        """
        Download, verify, and unpack a package from PyPI.

        :param package_specifier: Package name with optional version
                                  (e.g. 'requests', 'flask==3.0.0').
        :returns: PackageInfo with source_path pointing to unpacked source.
        :raises PackageFetchError: On any failure during the fetch pipeline.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._fetch_sync, package_specifier)

    def _fetch_sync(self, package_specifier: str) -> PackageInfo:
        """
        Synchronous fetch pipeline — runs in executor thread.

        :param package_specifier: Package name with optional version.
        :returns: PackageInfo with source_path pointing to unpacked source.
        :raises PackageFetchError: On any failure.
        """
        package_name, requested_version = _parse_specifier(package_specifier)

        logger.info(
            "Fetching %s%s from PyPI",
            package_name,
            f"=={requested_version}" if requested_version else " (latest)",
        )

        pypi_metadata = self._fetch_pypi_metadata(package_name, requested_version)
        resolved_version = pypi_metadata["info"]["version"]

        sdist_info = _find_sdist(pypi_metadata, resolved_version)
        download_url = sdist_info["url"]
        expected_sha256 = sdist_info["digests"]["sha256"]
        filename = sdist_info["filename"]
        file_size_bytes = sdist_info.get("size", 0)

        if file_size_bytes > self._max_download_bytes:
            size_mb = file_size_bytes / (1024 * 1024)
            limit_mb = self._max_download_bytes // (1024 * 1024)
            raise PackageFetchError(
                f"Package size is {size_mb:.0f} MB, exceeds {limit_mb} MB limit. "
                f"Use --max-size {int(size_mb) + 10} to override."
            )

        temp_directory = Path(tempfile.mkdtemp(prefix="probe_"))

        try:
            archive_path = temp_directory / filename
            _download_archive(download_url, archive_path, self._max_download_bytes)
            _verify_sha256(archive_path, expected_sha256)
            source_path = _unpack_archive(archive_path, temp_directory)

            logger.info(
                "Fetched %s==%s — SHA256 verified, unpacked to %s",
                package_name,
                resolved_version,
                source_path,
            )

            return PackageInfo(
                name=package_name,
                version=resolved_version,
                source_path=source_path,
                sdist_path=archive_path,
                pypi_metadata=pypi_metadata["info"],
            )

        except Exception:
            shutil.rmtree(temp_directory, ignore_errors=True)
            raise

    def _fetch_pypi_metadata(
        self,
        package_name: str,
        version: Optional[str],
    ) -> Dict[str, Any]:
        """
        Query PyPI JSON API for package metadata.

        :param package_name: Normalized package name.
        :param version: Specific version, or None for latest.
        :returns: Full PyPI JSON response.
        :raises PackageFetchError: If the package or version is not found.
        """
        if version:
            api_url = f"{self._pypi_url}/{package_name}/{version}/json"
        else:
            api_url = f"{self._pypi_url}/{package_name}/json"

        request = urllib.request.Request(
            api_url,
            headers={"Accept": "application/json", "User-Agent": "sprobe/0.1.3"},
        )

        try:
            with urllib.request.urlopen(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as http_error:
            if http_error.code == 404:
                raise PackageFetchError(
                    f"Package '{package_name}'"
                    f"{'==' + version if version else ''} not found on PyPI"
                ) from http_error
            raise PackageFetchError(
                f"PyPI API returned HTTP {http_error.code} for '{package_name}'"
            ) from http_error
        except urllib.error.URLError as url_error:
            raise PackageFetchError(f"Cannot reach PyPI: {url_error.reason}") from url_error


def _parse_specifier(package_specifier: str) -> Tuple[str, Optional[str]]:
    """
    Parse a package specifier into name and optional version.

    Supports: 'requests', 'flask==3.0.0', 'numpy==1.26.4'.

    :param package_specifier: Raw user input.
    :returns: Tuple of (package_name, version_or_none).
    """
    if "==" in package_specifier:
        parts = package_specifier.split("==", maxsplit=1)
        return parts[0].strip().lower(), parts[1].strip()
    return package_specifier.strip().lower(), None


def _find_sdist(
    pypi_metadata: Dict[str, Any],
    version: str,
) -> Dict[str, Any]:
    """
    Find the source distribution (sdist) entry in PyPI release data.

    Prefers sdist over wheel because we need Python source for analysis.
    Falls back to wheel if no sdist exists.

    :param pypi_metadata: Full PyPI JSON response.
    :param version: Resolved version string.
    :returns: URL entry dict with 'url', 'digests', 'filename' keys.
    :raises PackageFetchError: If no downloadable distribution is found.
    """
    urls = pypi_metadata.get("urls", [])

    if not urls:
        releases = pypi_metadata.get("releases", {})
        urls = releases.get(version, [])

    if not urls:
        raise PackageFetchError(f"No downloadable distributions found for version {version}")

    for url_entry in urls:
        if url_entry.get("packagetype") == "sdist":
            return url_entry

    logger.warning(
        "No sdist found for version %s, falling back to wheel",
        version,
    )
    return urls[0]


def _download_archive(
    download_url: str,
    destination: Path,
    max_bytes: int = _MAX_DOWNLOAD_BYTES,
) -> None:
    """
    Download a package archive with size limit enforcement.

    :param download_url: Direct URL to the sdist archive.
    :param destination: Local path to save the downloaded file.
    :param max_bytes: Maximum allowed download size in bytes.
    :raises PackageFetchError: If download fails or size limit exceeded.
    """
    request = urllib.request.Request(
        download_url,
        headers={"User-Agent": "sprobe/0.1.3"},
    )

    try:
        with urllib.request.urlopen(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:
            downloaded_bytes = 0
            with open(destination, "wb") as archive_file:
                while True:
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    downloaded_bytes += len(chunk)
                    if downloaded_bytes > max_bytes:
                        raise PackageFetchError(
                            f"Download exceeds {max_bytes // (1024 * 1024)} MB limit"
                        )
                    archive_file.write(chunk)
    except urllib.error.URLError as url_error:
        raise PackageFetchError(f"Download failed: {url_error.reason}") from url_error

    logger.debug("Downloaded %d KB to %s", downloaded_bytes // 1024, destination)


def _verify_sha256(archive_path: Path, expected_hash: str) -> None:
    """
    Verify SHA256 hash of a downloaded file against PyPI's published digest.

    Protects against MITM attacks, CDN tampering, and corrupted downloads.

    :param archive_path: Path to the downloaded archive.Consider explicitly
        re-raisingusing 'raise PackageFetchError(f"Package '{package_name}'
        {'==' + version if version else ''} not found on PyPI") from http_error'
    :param expected_hash: Expected SHA256 hex digest from PyPI.
    :raises PackageFetchError: If hash does not match.
    """
    sha256_hasher = hashlib.sha256()

    with open(archive_path, "rb") as archive_file:
        while True:
            chunk = archive_file.read(65536)
            if not chunk:
                break
            sha256_hasher.update(chunk)

    computed_hash = sha256_hasher.hexdigest()

    if computed_hash != expected_hash:
        raise PackageFetchError(
            f"SHA256 mismatch for {archive_path.name}.\n"
            f"  Expected: {expected_hash}\n"
            f"  Got:      {computed_hash}\n"
            f"  The downloaded file may have been tampered with."
        )

    logger.debug("SHA256 verified: %s...", computed_hash[:16])


def _unpack_archive(archive_path: Path, temp_directory: Path) -> Path:
    """
    Unpack a tar.gz or .zip archive into the temporary directory.

    Returns the path to the top-level unpacked directory.

    :param archive_path: Path to the archive file.
    :param temp_directory: Parent directory to unpack into.
    :returns: Path to the unpacked source root.
    :raises PackageFetchError: If archive format is unsupported or extraction fails.
    """
    unpack_target = temp_directory / "source"
    unpack_target.mkdir(exist_ok=True)

    filename_lower = archive_path.name.lower()

    try:
        if filename_lower.endswith(".tar.gz") or filename_lower.endswith(".tgz"):
            _unpack_tarball(archive_path, unpack_target)
        elif filename_lower.endswith(".zip") or filename_lower.endswith(".whl"):
            _unpack_zip(archive_path, unpack_target)
        else:
            raise PackageFetchError(f"Unsupported archive format: {archive_path.name}")
    except (tarfile.TarError, zipfile.BadZipFile) as unpack_error:
        raise PackageFetchError(
            f"Failed to unpack {archive_path.name}: {unpack_error}"
        ) from unpack_error

    unpacked_contents = list(unpack_target.iterdir())
    if len(unpacked_contents) == 1 and unpacked_contents[0].is_dir():
        return unpacked_contents[0]

    return unpack_target


def _unpack_tarball(archive_path: Path, destination: Path) -> None:
    """
    Safely unpack a tar.gz archive, rejecting path traversal attacks.

    :param archive_path: Path to the .tar.gz file.
    :param destination: Directory to extract into.
    :raises PackageFetchError: If any member attempts path traversal.
    """
    with tarfile.open(archive_path, "r:gz") as tar_handle:
        for member in tar_handle.getmembers():
            member_path = (destination / member.name).resolve()
            if not str(member_path).startswith(str(destination.resolve())):
                raise PackageFetchError(f"Path traversal detected in archive: {member.name}")
        tar_handle.extractall(path=destination, filter="data")


def _unpack_zip(archive_path: Path, destination: Path) -> None:
    """
    Safely unpack a .zip archive, rejecting path traversal attacks.

    :param archive_path: Path to the .zip file.
    :param destination: Directory to extract into.
    :raises PackageFetchError: If any member attempts path traversal.
    """
    with zipfile.ZipFile(archive_path, "r") as zip_handle:
        for zip_entry in zip_handle.namelist():
            entry_path = (destination / zip_entry).resolve()
            if not str(entry_path).startswith(str(destination.resolve())):
                raise PackageFetchError(f"Path traversal detected in archive: {zip_entry}")
        zip_handle.extractall(path=destination)


__all__ = [
    "PyPIFetcher",
]
