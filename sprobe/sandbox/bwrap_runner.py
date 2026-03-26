"""
Bubblewrap sandbox runner.

Executes a package import inside an isolated bubblewrap (bwrap) sandbox
with strace monitoring and honeypot secrets. Detects runtime malicious
behavior that static analysis cannot catch:
  - Credential file access (honeypot tripwires)
  - Network connection attempts (blocked by --unshare-net)
  - Unexpected subprocess execution

The sandbox is fully isolated:
  - Filesystem: read-only host mounts, tmpfs for writable areas
  - Network: disabled via --unshare-net (connect attempts still logged)
  - PID namespace: isolated process tree
  - Auto-killed after timeout

Zero external Python dependencies. Requires bwrap and strace system packages.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional

from sprobe.domain.package_info import PackageInfo
from sprobe.domain.scan_finding import ScanFinding
from sprobe.sandbox.honeypot_injector import HoneypotEnvironment, create_honeypot_environment
from sprobe.sandbox.strace_parser import parse_strace_output

logger = logging.getLogger("sprobe")

# Maximum time to wait for sandbox execution before killing
_SANDBOX_TIMEOUT_SECONDS: int = 30

# Python import script template — runs inside the sandbox
_IMPORT_SCRIPT = 'import sys; sys.path.insert(0, "/pkg"); import {module_name}'


class BwrapSandboxRunner:
    """
    Executes packages in a bubblewrap sandbox with strace monitoring.

    Creates an isolated environment with honeypot secrets, runs
    the package import, monitors syscalls via strace, and returns
    findings based on observed behavior.
    """

    async def analyze(self, package: PackageInfo) -> List[ScanFinding]:
        """
        Run a package inside the sandbox and return behavioral findings.

        :param package: Package info with source_path pointing to unpacked source.
        :returns: Findings from runtime behavior analysis.
        """
        if not _check_prerequisites():
            logger.warning("Sandbox prerequisites not met (bwrap/strace missing), skipping")
            return []

        module_name = _resolve_module_name(package)
        if module_name is None:
            logger.warning(
                "Cannot determine importable module for %s, skipping sandbox",
                package.name,
            )
            return []

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            self._run_sandbox_sync,
            package,
            module_name,
        )

    def _run_sandbox_sync(
        self,
        package: PackageInfo,
        module_name: str,
    ) -> List[ScanFinding]:
        """
        Synchronous sandbox execution — runs in executor thread.

        :param package: Package info.
        :param module_name: Python module name to import inside sandbox.
        :returns: Findings from runtime behavior analysis.
        """
        sandbox_temp = Path(tempfile.mkdtemp(prefix="probe_sandbox_"))

        try:
            honeypot = create_honeypot_environment(sandbox_temp)
            strace_log_path = sandbox_temp / "strace.log"

            bwrap_command = _build_bwrap_command(
                package_source=package.source_path,
                honeypot=honeypot,
                strace_log=strace_log_path,
                module_name=module_name,
            )

            logger.info("Sandbox starting for %s (module: %s)", package.name, module_name)
            logger.debug("bwrap command: %s", " ".join(bwrap_command))

            try:
                result = subprocess.run(
                    bwrap_command,
                    capture_output=True,
                    text=True,
                    timeout=_SANDBOX_TIMEOUT_SECONDS,
                    check=False,
                )
                logger.debug("Sandbox exited with code %d", result.returncode)
                if result.stderr:
                    logger.debug("Sandbox stderr: %s", result.stderr[:500])
            except subprocess.TimeoutExpired:
                logger.warning("Sandbox timed out after %d seconds", _SANDBOX_TIMEOUT_SECONDS)

            findings = parse_strace_output(str(strace_log_path), honeypot)
            logger.info("Sandbox analysis complete: %d findings", len(findings))

            return findings

        finally:
            shutil.rmtree(sandbox_temp, ignore_errors=True)


def _check_prerequisites() -> bool:
    """
    Verify that bwrap and strace are available on the system.

    :returns: True if both tools are installed and accessible.
    """
    bwrap_available = shutil.which("bwrap") is not None
    strace_available = shutil.which("strace") is not None

    if not bwrap_available:
        logger.warning("bubblewrap (bwrap) not found — install with: apt install bubblewrap")
    if not strace_available:
        logger.warning("strace not found — install with: apt install strace")

    return bwrap_available and strace_available


def _resolve_module_name(package: PackageInfo) -> Optional[str]:
    """
    Determine the importable module name from the package source.

    Looks for directories containing __init__.py or single .py files
    at the package root. Normalizes dashes to underscores.

    :param package: Package info with source_path.
    :returns: Module name to import, or None if undetermined.
    """
    source_path = package.source_path

    # Check for a directory with __init__.py matching the package name
    normalized_name = package.name.replace("-", "_").lower()

    for candidate_dir in source_path.iterdir():
        if not candidate_dir.is_dir():
            continue
        init_file = candidate_dir / "__init__.py"
        if init_file.exists():
            dir_name = candidate_dir.name.lower()
            if dir_name == normalized_name or dir_name.replace("-", "_") == normalized_name:
                return candidate_dir.name

    # Fallback: first directory with __init__.py
    for candidate_dir in sorted(source_path.iterdir()):
        if candidate_dir.is_dir() and (candidate_dir / "__init__.py").exists():
            # Skip test/doc directories
            skip_names = {"tests", "test", "docs", "doc", "examples", "benchmarks"}
            if candidate_dir.name.lower() not in skip_names:
                return candidate_dir.name

    return None


def _build_bwrap_command(
    package_source: Path,
    honeypot: HoneypotEnvironment,
    strace_log: Path,
    module_name: str,
) -> List[str]:
    """
    Build the complete bwrap + strace command line.

    Sandbox configuration:
      - Read-only host mounts for /usr, /lib, /bin, /etc
      - Package source mounted at /pkg (read-only)
      - Honeypot home directory mounted at /home/user
      - Strace output directory writable
      - Network disabled (--unshare-net)
      - PID namespace isolated (--unshare-pid)
      - Process killed when parent dies (--die-with-parent)

    :param package_source: Path to unpacked package source on host.
    :param honeypot: Honeypot environment with home dir and env vars.
    :param strace_log: Path where strace should write its output.
    :param module_name: Python module name to import.
    :returns: Command list ready for subprocess.run().
    """
    python_path = sys.executable
    strace_output_dir = strace_log.parent

    command = ["bwrap"]

    # Read-only filesystem mounts
    for host_path in ("/usr", "/lib", "/lib64", "/bin", "/sbin"):
        resolved = Path(host_path)
        if resolved.exists():
            command.extend(["--ro-bind", str(resolved), host_path])

    # /etc is needed for Python to find encodings, SSL certs, etc.
    if Path("/etc").exists():
        command.extend(["--ro-bind", "/etc", "/etc"])

    # Proc and dev
    command.extend(["--proc", "/proc"])
    command.extend(["--dev", "/dev"])

    # Writable temp inside sandbox
    command.extend(["--tmpfs", "/tmp"])

    # Package source (read-only)
    command.extend(["--ro-bind", str(package_source), "/pkg"])

    # Honeypot home directory
    command.extend(["--bind", str(honeypot.home_dir), "/home/user"])

    # Strace output directory (writable from inside sandbox)
    command.extend(["--bind", str(strace_output_dir), "/strace_out"])

    # Environment variables
    command.extend(["--setenv", "HOME", "/home/user"])
    command.extend(["--setenv", "PYTHONPATH", "/pkg"])
    command.extend(["--setenv", "PYTHONDONTWRITEBYTECODE", "1"])

    for env_name, env_value in honeypot.env_vars.items():
        command.extend(["--setenv", env_name, env_value])

    # Isolation
    command.extend(
        [
            "--unshare-net",
            "--unshare-pid",
            "--die-with-parent",
        ]
    )

    # The actual command: strace wrapping python import
    import_script = _IMPORT_SCRIPT.format(module_name=module_name)

    command.extend(
        [
            "--",
            "strace",
            "-f",
            "-e",
            "trace=openat,connect,sendto,execve",
            "-o",
            "/strace_out/strace.log",
            python_path,
            "-c",
            import_script,
        ]
    )

    return command


__all__ = [
    "BwrapSandboxRunner",
]
