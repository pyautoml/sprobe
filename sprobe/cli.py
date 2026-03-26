"""
CLI entrypoint for sprobe.

Provides the command-line interface via stdlib argparse:
  - sprobe scan <path>: Analyze a local package directory
  - sprobe check <packages...>: Download from PyPI, analyze, report, clean up
  - sprobe version: Show version

sprobe never installs packages. It is a security scanner only.
The user reads the report and decides whether to install.

Zero external dependencies — uses only Python stdlib.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path
from typing import List

from sprobe.domain.severity import Decision
from sprobe.orchestrator import ScanOrchestrator
from sprobe.playbook_runner import print_playbook_summary, run_all_playbooks


def main() -> None:
    """
    Parse CLI arguments and dispatch to the appropriate command.

    Entry point for both 'python -m sprobe' and the 'sprobe' console script.
    """
    parser = argparse.ArgumentParser(
        prog="sprobe",
        description="Zero-trust Python package scanner. "
        "Analyzes packages for malicious behavior. Never installs.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # sprobe scan <path>
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a local package directory for suspicious behavior.",
    )
    scan_parser.add_argument(
        "path",
        type=Path,
        help="Path to unpacked package source directory.",
    )
    scan_parser.add_argument(
        "--name",
        "-n",
        default="",
        help="Package name. Defaults to directory name.",
    )
    scan_parser.add_argument(
        "--version",
        "-v",
        default="unknown",
        dest="pkg_version",
        help="Package version for display.",
    )
    scan_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging output.",
    )

    # sprobe check <packages...>
    check_parser = subparsers.add_parser(
        "check",
        help="Download packages from PyPI, analyze, and report. Never installs.",
    )
    check_parser.add_argument(
        "packages",
        nargs="+",
        help="One or more PyPI package names (e.g. 'requests flask==3.0 numpy').",
    )
    check_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging output.",
    )
    check_parser.add_argument(
        "--max-size",
        type=int,
        default=50,
        dest="max_size_mb",
        help="Maximum download size in MB (default: 50).",
    )

    # sprobe test-playbooks
    playbook_parser = subparsers.add_parser(
        "test-playbooks",
        help="Run all threat playbooks and verify detection capabilities.",
    )
    playbook_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging output.",
    )
    playbook_parser.add_argument(
        "--skip-sandbox",
        action="store_true",
        help="Skip sandbox analysis for faster testing (static-only).",
    )

    # sprobe version
    subparsers.add_parser("version", help="Show sprobe version.")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "version":
        print("sprobe 0.1.3")
        sys.exit(0)

    verbose = getattr(args, "verbose", False)
    _configure_logging(verbose)

    if args.command == "scan":
        _handle_scan(args)
    elif args.command == "check":
        _handle_check(args)
    elif args.command == "test-playbooks":
        _handle_test_playbooks(args)


def _handle_scan(args: argparse.Namespace) -> None:
    """
    Handle the 'scan' subcommand.

    :param args: Parsed CLI arguments.
    """
    source_path = args.path.resolve()

    if not source_path.is_dir():
        print(f"Error: '{source_path}' is not a directory.", file=sys.stderr)
        sys.exit(1)

    resolved_name = args.name or source_path.name

    orchestrator = ScanOrchestrator()
    verdict = asyncio.run(
        orchestrator.scan_local(
            source_path=source_path,
            package_name=resolved_name,
            package_version=args.pkg_version,
        )
    )

    _exit_with_verdict(verdict.decision)


def _handle_check(args: argparse.Namespace) -> None:
    """
    Handle the 'check' subcommand.

    :param args: Parsed CLI arguments.
    """
    packages: List[str] = args.packages
    max_size_bytes = args.max_size_mb * 1024 * 1024

    from sprobe.fetching.pypi_fetcher import PyPIFetcher

    fetcher = PyPIFetcher(max_download_bytes=max_size_bytes)
    orchestrator = ScanOrchestrator(fetcher=fetcher)
    verdicts = asyncio.run(orchestrator.check_pypi_batch(package_specifiers=packages))

    worst_decision = max(
        (verdict.decision for verdict in verdicts),
        default=Decision.SAFE,
    )

    _exit_with_verdict(worst_decision)


def _handle_test_playbooks(args: argparse.Namespace) -> None:
    """
    Handle the 'test-playbooks' subcommand.

    :param args: Parsed CLI arguments.
    """
    skip_sandbox = getattr(args, "skip_sandbox", False)

    try:
        results = asyncio.run(run_all_playbooks(skip_sandbox=skip_sandbox))
    except FileNotFoundError as not_found_error:
        print(str(not_found_error), file=sys.stderr)
        sys.exit(1)

    print_playbook_summary(results)

    all_passed = all(result.passed for result in results)
    if not all_passed:
        sys.exit(1)


def _configure_logging(verbose: bool) -> None:
    """
    Configure stdlib logging for CLI usage.

    :param verbose: If True, show DEBUG level. Otherwise, WARNING only.
    """
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
    )


def _exit_with_verdict(decision: Decision) -> None:
    """
    Exit with appropriate code based on the worst verdict.

    Exit code 0: SAFE or CAUTION.
    Exit code 1: DANGER or BLOCKED.

    :param decision: Worst decision across all scanned packages.
    """
    if decision >= Decision.DANGER:
        sys.exit(1)


if __name__ == "__main__":
    main()


__all__ = [
    "main",
]
