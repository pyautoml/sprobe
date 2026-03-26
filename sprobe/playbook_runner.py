"""
Threat playbook test runner.

Runs all threat playbooks through the full analysis pipeline and
verifies that each produces the expected verdict. Used for validating
that sprobe's detection capabilities are working correctly.

Each playbook directory contains a fake malicious (or clean) package.
The runner scans each one and compares the verdict against the
expected result defined in _PLAYBOOK_EXPECTATIONS.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List

from sprobe.domain.risk_verdict import RiskVerdict
from sprobe.domain.severity import Decision
from sprobe.orchestrator import ScanOrchestrator
from sprobe.reporting.terminal_reporter import TerminalReporter

logger = logging.getLogger("sprobe")

_PLAYBOOKS_DIR: Path = Path(__file__).resolve().parent.parent / "threat_playbooks"

# Minimum expected decision for each playbook
# BLOCKED = must be caught, SAFE = must not false-positive
_PLAYBOOK_EXPECTATIONS: dict[str, Decision] = {
    "steals_ssh_key": Decision.BLOCKED,
    "exfiltrates_env": Decision.CAUTION,
    "obfuscated_exec": Decision.DANGER,
    "honeypot_trigger": Decision.BLOCKED,
    "delayed_payload": Decision.CAUTION,
    "setup_py_backdoor": Decision.BLOCKED,
    "clean_package": Decision.SAFE,
}


@dataclass(frozen=True, slots=True)
class PlaybookResult:
    """
    Result of running a single playbook through the pipeline.

    :param playbook_name: Name of the playbook directory.
    :param expected_decision: Minimum expected decision.
    :param actual_decision: Decision from the scan.
    :param actual_score: Numeric risk score.
    :param finding_count: Number of findings detected.
    :param passed: Whether the playbook met expectations.
    """

    playbook_name: str
    expected_decision: Decision
    actual_decision: Decision
    actual_score: int
    finding_count: int
    passed: bool


async def run_all_playbooks(
    skip_sandbox: bool = False,
) -> List[PlaybookResult]:
    """
    Run all threat playbooks and return results.

    :param skip_sandbox: If True, skip sandbox analysis (faster, static-only check).
    :returns: List of results, one per playbook.
    :raises FileNotFoundError: If the playbooks directory does not exist
                               (e.g. when installed via pip without source checkout).
    """
    if not _PLAYBOOKS_DIR.is_dir():
        raise FileNotFoundError(
            f"Threat playbooks directory not found: {_PLAYBOOKS_DIR}\n"
            "Playbooks are only available when running from a source checkout.\n"
            "Clone the repository: git clone https://github.com/pyautoml/sprobe.git"
        )

    orchestrator = _create_orchestrator(skip_sandbox)

    results: List[PlaybookResult] = []

    for playbook_name, expected_decision in sorted(_PLAYBOOK_EXPECTATIONS.items()):
        playbook_path = _PLAYBOOKS_DIR / playbook_name

        if not playbook_path.is_dir():
            logger.warning("Playbook directory not found: %s", playbook_path)
            continue

        verdict = await orchestrator.scan_local(
            source_path=playbook_path,
            package_name=playbook_name,
            package_version="playbook",
        )

        passed = _check_expectation(verdict, expected_decision)

        results.append(
            PlaybookResult(
                playbook_name=playbook_name,
                expected_decision=expected_decision,
                actual_decision=verdict.decision,
                actual_score=verdict.score.value,
                finding_count=len(verdict.findings),
                passed=passed,
            )
        )

    return results


def _check_expectation(verdict: RiskVerdict, expected_decision: Decision) -> bool:
    """
    Check if a verdict meets the expected decision.

    For malicious playbooks (expected >= DANGER): actual must be >= expected.
    For clean playbooks (expected == SAFE): actual must be exactly SAFE.

    :param verdict: Actual scan verdict.
    :param expected_decision: Minimum expected decision.
    :returns: True if expectation is met.
    """
    if expected_decision == Decision.SAFE:
        return verdict.decision == Decision.SAFE

    return verdict.decision >= expected_decision


def _create_orchestrator(skip_sandbox: bool) -> ScanOrchestrator:
    """
    Create a ScanOrchestrator configured for playbook testing.

    Uses a silent reporter to avoid cluttering test output.

    :param skip_sandbox: If True, use a no-op sandbox.
    :returns: Configured orchestrator.
    """
    return ScanOrchestrator(reporter=TerminalReporter(), skip_sandbox=skip_sandbox)


def print_playbook_summary(results: List[PlaybookResult]) -> None:
    """
    Print a summary table of playbook results.

    :param results: Results from run_all_playbooks.
    """
    passed_count = sum(1 for result in results if result.passed)
    total_count = len(results)

    print("\n" + "=" * 65)
    print("  PLAYBOOK TEST RESULTS")
    print("=" * 65)

    for result in results:
        status = "\033[32mPASS\033[0m" if result.passed else "\033[31mFAIL\033[0m"
        print(
            f"  {status}  {result.playbook_name:25s} "
            f"expected={result.expected_decision.name:8s} "
            f"got={result.actual_decision.name:8s} "
            f"score={result.actual_score:3d} "
            f"findings={result.finding_count}"
        )

    print("-" * 65)
    color = "\033[32m" if passed_count == total_count else "\033[31m"
    print(f"  {color}{passed_count}/{total_count} passed\033[0m")
    print("=" * 65 + "\n")


__all__ = [
    "PlaybookResult",
    "run_all_playbooks",
    "print_playbook_summary",
]
