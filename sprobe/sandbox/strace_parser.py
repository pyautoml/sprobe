"""
Strace output parser.

Parses strace log output to detect suspicious runtime behavior:
  - File access to honeypot paths (openat syscalls)
  - Network connection attempts (connect syscalls)
  - Subprocess execution (execve syscalls)

The parser reads line-by-line and matches against known syscall patterns.
Only successful syscalls (return value >= 0) are considered, except for
connect() where even failed attempts indicate intent.

Zero external dependencies.
"""

from __future__ import annotations

import logging
import re
from typing import List

from sprobe.domain.scan_finding import ScanFinding
from sprobe.domain.severity import Severity
from sprobe.sandbox.honeypot_injector import HoneypotEnvironment

logger = logging.getLogger("sprobe")

# Regex patterns for parsing strace output lines
# Format: PID syscall(args) = return_value
_OPENAT_PATTERN = re.compile(
    r'openat\(.*?"([^"]+)"',
)
# Matches both inet_addr("1.2.3.4") and inet_pton(AF_INET, "1.2.3.4")
_CONNECT_PATTERN = re.compile(
    r"connect\(\d+,\s*\{sa_family=AF_INET[6]?,\s*sin6?_port=htons\((\d+)\),"
    r'\s*sin6?_addr=(?:inet_(?:addr|pton)\((?:AF_INET[6]?,\s*)?")([^"]+)',
)
_EXECVE_PATTERN = re.compile(
    r'execve\("([^"]+)"',
)
# Match return value at end of line
_RETURN_VALUE_PATTERN = re.compile(r"=\s*(-?\d+)")


def parse_strace_output(
    strace_log_path: str,
    honeypot: HoneypotEnvironment,
) -> List[ScanFinding]:
    """
    Parse strace log file and extract suspicious behaviors.

    :param strace_log_path: Path to the strace output file.
    :param honeypot: Honeypot environment for cross-referencing canary paths.
    :returns: Findings from runtime behavior analysis.
    """
    findings: List[ScanFinding] = []

    try:
        with open(strace_log_path, "r", encoding="utf-8", errors="replace") as log_file:
            strace_lines = log_file.readlines()
    except OSError as read_error:
        logger.warning("Cannot read strace log %s: %s", strace_log_path, read_error)
        return []

    logger.debug("Parsing %d strace log lines", len(strace_lines))

    seen_patterns: set[str] = set()

    for line in strace_lines:
        file_finding = _check_honeypot_access(line, honeypot, seen_patterns)
        if file_finding:
            findings.append(file_finding)

        network_finding = _check_network_connect(line, seen_patterns)
        if network_finding:
            findings.append(network_finding)

        exec_finding = _check_subprocess_exec(line, seen_patterns)
        if exec_finding:
            findings.append(exec_finding)

    return findings


def _check_honeypot_access(
    line: str,
    honeypot: HoneypotEnvironment,
    seen_patterns: set[str],
) -> ScanFinding | None:
    """
    Check if an openat syscall accessed a honeypot file.

    :param line: Single strace log line.
    :param honeypot: Honeypot environment with canary paths.
    :param seen_patterns: Already-seen pattern IDs to avoid duplicates.
    :returns: Finding if honeypot was accessed, None otherwise.
    """
    openat_match = _OPENAT_PATTERN.search(line)
    if not openat_match:
        return None

    accessed_path = openat_match.group(1)

    for canary_path in honeypot.canary_paths:
        if canary_path in accessed_path or accessed_path.endswith(canary_path.split("/")[-1]):
            dedup_key = f"honeypot_{canary_path}"
            if dedup_key in seen_patterns:
                return None
            seen_patterns.add(dedup_key)

            return ScanFinding(
                pattern_id="honeypot_access",
                category="credential_theft",
                severity=Severity.CRITICAL,
                description=f"Package accessed honeypot file at runtime: {canary_path}",
                evidence=f"openat: {accessed_path}",
                layer="sandbox",
            )

    return None


def _check_network_connect(
    line: str,
    seen_patterns: set[str],
) -> ScanFinding | None:
    """
    Check if a connect syscall attempted a network connection.

    Even failed connect() calls indicate the package tried to phone home.
    Localhost connections (127.0.0.1, ::1) are excluded.

    :param line: Single strace log line.
    :param seen_patterns: Already-seen pattern IDs to avoid duplicates.
    :returns: Finding if network connection attempted, None otherwise.
    """
    if "connect(" not in line:
        return None

    connect_match = _CONNECT_PATTERN.search(line)
    if not connect_match:
        return None

    port = connect_match.group(1)
    address = connect_match.group(2)

    # Skip localhost connections — many packages do this legitimately
    if address in ("127.0.0.1", "::1", "0.0.0.0"):
        return None

    dedup_key = f"network_{address}_{port}"
    if dedup_key in seen_patterns:
        return None
    seen_patterns.add(dedup_key)

    return ScanFinding(
        pattern_id="runtime_network_connect",
        category="network",
        severity=Severity.HIGH,
        description=f"Package attempted network connection to {address}:{port} at runtime",
        evidence=line.strip(),
        layer="sandbox",
    )


def _check_subprocess_exec(
    line: str,
    seen_patterns: set[str],
) -> ScanFinding | None:
    """
    Check if an execve syscall launched a subprocess.

    Filters out the Python interpreter itself and strace — only flags
    unexpected subprocess execution.

    :param line: Single strace log line.
    :param seen_patterns: Already-seen pattern IDs to avoid duplicates.
    :returns: Finding if unexpected subprocess launched, None otherwise.
    """
    execve_match = _EXECVE_PATTERN.search(line)
    if not execve_match:
        return None

    executed_binary = execve_match.group(1)

    # Filter out expected binaries — python interpreter, strace itself, and ld-linux
    expected_binaries = (
        "/usr/bin/python",
        "/bin/python",
        "/usr/bin/strace",
        "/bin/strace",
        "/usr/lib/python",
        "/lib/ld-linux",
        "/lib64/ld-linux",
    )
    if any(executed_binary.startswith(expected) for expected in expected_binaries):
        return None

    dedup_key = f"execve_{executed_binary}"
    if dedup_key in seen_patterns:
        return None
    seen_patterns.add(dedup_key)

    return ScanFinding(
        pattern_id="runtime_subprocess",
        category="code_execution",
        severity=Severity.HIGH,
        description=f"Package executed subprocess at runtime: {executed_binary}",
        evidence=line.strip(),
        layer="sandbox",
    )


__all__ = [
    "parse_strace_output",
]
