"""
Pattern loader.

Scans directories for TOML pattern files and loads them into
PatternDefinition objects. Uses Python's built-in tomllib (3.11+),
zero external dependencies.

Supports two sources:
  1. Built-in patterns shipped with sprobe (patterns/ in package root)
  2. User-defined patterns (~/.sprobe/patterns/)

Pattern files are grouped by category subdirectories.
Duplicate pattern IDs across files raise a warning and the last one wins.
"""

from __future__ import annotations

import logging
import tomllib
from pathlib import Path
from typing import Dict, List, Optional

from sprobe.patterns.pattern_definition import PatternDefinition, severity_from_string

logger = logging.getLogger("sprobe")

# Built-in patterns ship inside the package (sprobe/patterns/builtin/)
_BUILTIN_PATTERNS_DIR: Path = Path(__file__).resolve().parent / "builtin"

# User-contributed patterns
_USER_PATTERNS_DIR: Path = Path.home() / ".sprobe" / "patterns"

_VALID_TOML_SUFFIX = ".toml"


def load_all_patterns(
    extra_dirs: Optional[List[Path]] = None,
) -> List[PatternDefinition]:
    """
    Load patterns from built-in, user, and any extra directories.

    Directories are scanned recursively for .toml files.
    Each file must contain exactly one pattern definition.

    :param extra_dirs: Additional directories to scan for patterns.
    :returns: All loaded patterns, deduplicated by pattern_id (last wins).
    """
    patterns_by_id: Dict[str, PatternDefinition] = {}

    directories_to_scan: List[Path] = [_BUILTIN_PATTERNS_DIR]

    if _USER_PATTERNS_DIR.is_dir():
        directories_to_scan.append(_USER_PATTERNS_DIR)

    if extra_dirs:
        directories_to_scan.extend(extra_dirs)

    for directory in directories_to_scan:
        loaded = _load_patterns_from_directory(directory)
        for pattern in loaded:
            if pattern.pattern_id in patterns_by_id:
                logger.warning(
                    "Duplicate pattern_id '%s', overwriting with version from %s",
                    pattern.pattern_id,
                    directory,
                )
            patterns_by_id[pattern.pattern_id] = pattern

    logger.info(
        "Loaded %d patterns from %d directories", len(patterns_by_id), len(directories_to_scan)
    )

    return list(patterns_by_id.values())


def _load_patterns_from_directory(directory: Path) -> List[PatternDefinition]:
    """
    Recursively load all TOML pattern files from a directory.

    :param directory: Root directory to scan.
    :returns: List of loaded patterns. Invalid files are skipped with a warning.
    """
    if not directory.is_dir():
        logger.debug("Pattern directory does not exist, skipping: %s", directory)
        return []

    patterns: List[PatternDefinition] = []

    for toml_file in sorted(directory.rglob("*")):
        if toml_file.suffix.lower() != _VALID_TOML_SUFFIX:
            continue

        parsed_pattern = _parse_pattern_file(toml_file)
        if parsed_pattern is not None:
            patterns.append(parsed_pattern)

    return patterns


def _parse_pattern_file(file_path: Path) -> Optional[PatternDefinition]:
    """
    Parse a single TOML pattern file into a PatternDefinition.

    :param file_path: Path to the TOML file.
    :returns: Parsed pattern, or None if the file is invalid.
    """
    try:
        with open(file_path, "rb") as toml_handle:
            raw_data = tomllib.load(toml_handle)
    except tomllib.TOMLDecodeError as toml_error:
        logger.warning("Invalid TOML in %s: %s", file_path, toml_error)
        return None

    if not isinstance(raw_data, dict):
        logger.warning("Pattern file %s does not contain a mapping", file_path)
        return None

    required_fields = ("id", "category", "severity", "description", "detection")
    missing_fields = [field_name for field_name in required_fields if field_name not in raw_data]
    if missing_fields:
        logger.warning(
            "Pattern file %s missing required fields: %s",
            file_path,
            missing_fields,
        )
        return None

    detection_block = raw_data["detection"]
    if not isinstance(detection_block, dict):
        logger.warning("Pattern %s: 'detection' must be a mapping", file_path)
        return None

    try:
        pattern = PatternDefinition(
            pattern_id=str(raw_data["id"]),
            category=str(raw_data["category"]),
            severity=severity_from_string(str(raw_data["severity"])),
            description=str(raw_data["description"]),
            detection_type=detection_block.get("type", "regex"),
            detection_target=detection_block.get("target", "source"),
            rules=detection_block.get("rules", []),
            file_scope=_normalize_file_scope(detection_block.get("file_scope", [])),
            expected_for=raw_data.get("expected_for", []),
            tags=raw_data.get("tags", []),
        )
    except (ValueError, KeyError) as parse_error:
        logger.warning("Pattern file %s has invalid data: %s", file_path, parse_error)
        return None

    return pattern


def _normalize_file_scope(raw_scope: str | list) -> List[str]:
    """
    Normalize file_scope from TOML to a list of filenames.

    Accepts a single string or a list of strings.

    :param raw_scope: Raw file_scope value from TOML.
    :returns: List of filename strings.
    """
    if isinstance(raw_scope, str):
        return [raw_scope] if raw_scope else []
    if isinstance(raw_scope, list):
        return [str(entry) for entry in raw_scope]
    return []


__all__ = [
    "load_all_patterns",
]
