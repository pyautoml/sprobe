"""
Terminal report renderer.

Formats a RiskVerdict into colored terminal output using ANSI escape codes.
Zero external dependencies — uses only Python stdlib.

Designed to be immediately readable: verdict first, then findings
grouped by severity, then score breakdown.

Color output is automatically disabled when stdout is not a terminal
(e.g. piped to a file or CI log).
"""

from __future__ import annotations

import sys

from sprobe.domain.risk_verdict import RiskVerdict
from sprobe.domain.scan_finding import ScanFinding
from sprobe.domain.severity import Decision, Severity

# ANSI escape codes
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_ORANGE = "\033[38;5;208m"
_WHITE = "\033[37m"

# Color mapping for severity levels
_SEVERITY_COLORS: dict[Severity, str] = {
    Severity.LOW: _DIM,
    Severity.MEDIUM: _YELLOW,
    Severity.HIGH: _ORANGE,
    Severity.CRITICAL: _RED + _BOLD,
}

# Color mapping for decisions
_DECISION_COLORS: dict[Decision, str] = {
    Decision.SAFE: _GREEN + _BOLD,
    Decision.CAUTION: _YELLOW + _BOLD,
    Decision.DANGER: _ORANGE + _BOLD,
    Decision.BLOCKED: _RED + _BOLD,
}


class TerminalReporter:
    """
    Renders scan results to the terminal using ANSI escape codes.

    Outputs a structured report: header with verdict, findings table
    grouped by severity, and final score with recommendation.
    Disables color when output is not a TTY.
    """

    def __init__(self) -> None:
        """Initialize with TTY detection for color support."""
        self._use_color = sys.stdout.isatty()

    def render(self, verdict: RiskVerdict) -> None:
        """
        Render a full scan report to the terminal.

        :param verdict: The computed risk verdict to display.
        """
        self._render_header(verdict)
        self._render_findings(verdict)
        self._render_verdict(verdict)

    def render_skip(self, package_specifier: str, reason: str) -> None:
        """
        Render a skip notice for a package that could not be fetched.

        :param package_specifier: Package name that was requested.
        :param reason: Why it was skipped (e.g. not found on PyPI).
        """
        border = self._colorize("=" * 60, _YELLOW)
        label = self._colorize("SKIPPED", _YELLOW + _BOLD)
        name = self._colorize(package_specifier, _BOLD)

        print(f"\n{border}")
        print(f"  {name}  {label}")
        print(f"  {reason}")
        print(border)

    def _render_header(self, verdict: RiskVerdict) -> None:
        """
        Render the package name, version, and verdict header.

        :param verdict: Risk verdict to display.
        """
        decision = verdict.decision
        decision_color = _DECISION_COLORS[decision]

        border = self._colorize("=" * 60, decision_color)
        name = self._colorize(f"{verdict.package_name}=={verdict.package_version}", _BOLD)
        label = self._colorize(decision.name, decision_color)

        print(f"\n{border}")
        print(f"  sprobe scan | {name}  {label}")
        print(border)

    def _render_findings(self, verdict: RiskVerdict) -> None:
        """
        Render findings sorted by severity (highest first).

        :param verdict: Risk verdict containing findings.
        """
        if not verdict.findings:
            print(self._colorize("  No suspicious behaviors detected.", _GREEN))
            return

        sorted_findings = sorted(
            verdict.findings,
            key=lambda finding: finding.severity.value,
            reverse=True,
        )

        print()
        for finding in sorted_findings:
            self._render_single_finding(finding)

    def _render_single_finding(self, finding: ScanFinding) -> None:
        """
        Render a single finding as a compact block.

        :param finding: Scan finding to display.
        """
        severity_color = _SEVERITY_COLORS[finding.severity]
        severity_label = self._colorize(f"[{finding.severity.name}]", severity_color)
        location = _format_location(finding)

        print(f"  {severity_label} {finding.category}")
        print(f"    {finding.description}")
        if location:
            print(f"    {self._colorize(location, _DIM)}")
        if finding.evidence:
            print(f"    {self._colorize(finding.evidence, _DIM)}")
        print()

    def _render_verdict(self, verdict: RiskVerdict) -> None:
        """
        Render the numeric score, decision, and summary.

        :param verdict: Risk verdict to display.
        """
        decision = verdict.decision
        decision_color = _DECISION_COLORS[decision]

        border = self._colorize("-" * 60, decision_color)
        score_text = self._colorize(f"Risk Score: {verdict.score.value}/100", decision_color)

        print(border)
        print(f"  {score_text}")
        print(f"  {verdict.summary}")

        if decision == Decision.BLOCKED:
            print(f"  {self._colorize('High risk. Revise heavily before installing.', _RED + _BOLD)}")
        elif decision == Decision.DANGER:
            print(f"  {self._colorize('Elevated risk. Review findings before installing.', _ORANGE)}")

        print(self._colorize("=" * 60, decision_color))
        print()

    def _colorize(self, text: str, color_code: str) -> str:
        """
        Wrap text in ANSI color codes if terminal supports it.

        :param text: Text to colorize.
        :param color_code: ANSI escape code string.
        :returns: Colored text if TTY, plain text otherwise.
        """
        if not self._use_color:
            return text
        return f"{color_code}{text}{_RESET}"


def _format_location(finding: ScanFinding) -> str:
    """
    Format the file:line location string for a finding.

    :param finding: Scan finding with optional source_file and line_number.
    :returns: Formatted location string.
    """
    if finding.source_file and finding.line_number:
        return f"{finding.source_file}:{finding.line_number}"
    if finding.source_file:
        return finding.source_file
    return finding.layer


__all__ = [
    "TerminalReporter",
]
