"""
Abstract base class for all DNS security analyzers.

Every analyzer (SPF, DMARC, DKIM, etc.) inherits from BaseAnalyzer and
implements a single `analyze()` method. The base class provides:

    - Consistent interface across all 9 analyzers
    - Built-in execution timing
    - Structured error handling that never crashes the scan pipeline
    - Timeout enforcement per analyzer
    - Result dataclass with typed fields
    - Logging context injected automatically

Design contract:
    - analyze() MUST return a list[AnalyzerResult] — never raise to the caller
    - Any exception inside analyze() is caught, logged, and returned as a
      failed AnalyzerResult so one broken analyzer cannot kill the whole scan
    - Each analyzer is stateless — a new instance is created per scan

Usage (implementing a new analyzer):
    class MyAnalyzer(BaseAnalyzer):
        name = "my_check"
        description = "Checks something important"

        async def analyze(self, domain: str, resolver: DNSResolver) -> list[AnalyzerResult]:
            records = await resolver.query(domain, "TXT")
            if not records:
                return [self.fail(
                    check="record_exists",
                    title="TXT record missing",
                    description="No TXT records found.",
                    severity="high",
                    remediation="Add a TXT record to your DNS zone.",
                )]
            return [self.pass_check(
                check="record_exists",
                title="TXT record present",
                description="TXT records found.",
            )]
"""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dns_analyzer.utils.logger import get_logger

if TYPE_CHECKING:
    from dns_analyzer.core.resolver import DNSResolver

log = get_logger(__name__)


# ==============================================================================
# RESULT DATACLASS
# ==============================================================================

@dataclass
class AnalyzerResult:
    """
    The output of a single security check within an analyzer.

    This is the internal representation used throughout the scan pipeline.
    It maps 1:1 to the Finding ORM model and is converted at the end of
    the scan when results are persisted to the database.

    Attributes:
        analyzer:        Name of the analyzer that produced this result.
        check_name:      Specific check identifier (snake_case).
        title:           Short one-line summary.
        description:     Detailed explanation.
        severity:        critical | high | medium | low | info
        passed:          True if the check passed cleanly.
        evidence:        Raw DNS record or response data (for report display).
        affected_record: The specific misconfigured record value (if any).
        remediation:     Step-by-step fix guidance.
        reference_url:   Link to relevant RFC or documentation.
        cvss_score:      Optional numeric risk score (0.0–10.0).
        extra:           Arbitrary extra data for advanced reporting.
    """

    analyzer: str
    check_name: str
    title: str
    description: str
    severity: str
    passed: bool
    evidence: str | None = None
    affected_record: str | None = None
    remediation: str | None = None
    reference_url: str | None = None
    cvss_score: float | None = None
    extra: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        _valid_severities = {"critical", "high", "medium", "low", "info"}
        if self.severity not in _valid_severities:
            raise ValueError(
                f"Invalid severity {self.severity!r} in {self.analyzer}/{self.check_name}. "
                f"Must be one of: {_valid_severities}"
            )

    @property
    def is_issue(self) -> bool:
        """True if this result represents a real problem (not a pass or info)."""
        return not self.passed and self.severity != "info"


# ==============================================================================
# ABSTRACT BASE ANALYZER
# ==============================================================================

class BaseAnalyzer(ABC):
    """
    Abstract base class for all DNS security analyzers.

    Subclasses MUST set:
        name        : str  — snake_case identifier (e.g. "spf", "dmarc")
        description : str  — one-line human-readable purpose

    Subclasses MUST implement:
        analyze(domain, resolver) → list[AnalyzerResult]

    Subclasses MAY override:
        timeout_seconds : float  — per-analyzer execution timeout (default 30s)
        enabled         : bool   — whether this analyzer is active (default True)
    """

    name: str = "base"
    description: str = "Base analyzer"
    timeout_seconds: float = 30.0
    enabled: bool = True

    def __init__(self) -> None:
        self._log = get_logger(f"analyzer.{self.name}")

    @abstractmethod
    async def analyze(
        self,
        domain: str,
        resolver: "DNSResolver",
    ) -> list[AnalyzerResult]:
        """
        Run all security checks for this analyzer against the given domain.

        Args:
            domain:   The fully qualified domain name to analyze.
            resolver: The shared DNSResolver instance for making DNS queries.

        Returns:
            A list of AnalyzerResult objects — one per individual check.
            Must never be empty (return at least one info result if nothing found).

        Note:
            This method must NEVER raise an exception. Catch all errors internally
            and return them as failed AnalyzerResults. The base class run() method
            provides an outer safety net, but analyzers should handle their own errors.
        """
        ...

    async def run(
        self,
        domain: str,
        resolver: "DNSResolver",
    ) -> list[AnalyzerResult]:
        """
        Execute the analyzer with timeout enforcement and error handling.

        This is what the scanner calls — never call analyze() directly.
        Wraps analyze() with:
            - Execution timing
            - Per-analyzer timeout (asyncio.wait_for)
            - Exception catch-all that returns a structured error result
              instead of propagating exceptions to the scan pipeline

        Args:
            domain:   The domain to analyze.
            resolver: The shared DNS resolver.

        Returns:
            List of AnalyzerResult — guaranteed to be non-empty.
            On timeout or unexpected error, returns a single error result.
        """
        if not self.enabled:
            self._log.debug("analyzer.skipped", domain=domain, analyzer=self.name)
            return []

        start = time.monotonic()
        self._log.info("analyzer.started", domain=domain, analyzer=self.name)

        try:
            results = await asyncio.wait_for(
                self.analyze(domain, resolver),
                timeout=self.timeout_seconds,
            )
            duration_ms = int((time.monotonic() - start) * 1000)
            issues = sum(1 for r in results if r.is_issue)

            self._log.info(
                "analyzer.completed",
                domain=domain,
                analyzer=self.name,
                results=len(results),
                issues=issues,
                duration_ms=duration_ms,
            )
            return results

        except asyncio.TimeoutError:
            duration_ms = int((time.monotonic() - start) * 1000)
            self._log.warning(
                "analyzer.timeout",
                domain=domain,
                analyzer=self.name,
                timeout_seconds=self.timeout_seconds,
                duration_ms=duration_ms,
            )
            return [self._error_result(
                check_name="analyzer_timeout",
                title=f"{self.name.upper()} analyzer timed out",
                description=(
                    f"The {self.name} analyzer did not complete within "
                    f"{self.timeout_seconds}s. Results for this check are unavailable."
                ),
                severity="medium",
            )]

        except Exception as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            self._log.error(
                "analyzer.error",
                domain=domain,
                analyzer=self.name,
                error=str(exc),
                duration_ms=duration_ms,
                exc_info=True,
            )
            return [self._error_result(
                check_name="analyzer_error",
                title=f"{self.name.upper()} analyzer encountered an error",
                description=(
                    f"An unexpected error occurred in the {self.name} analyzer: {exc}. "
                    "This check could not be completed."
                ),
                severity="medium",
            )]

    # ── Result factory helpers ─────────────────────────────────────────────────

    def fail(
        self,
        *,
        check: str,
        title: str,
        description: str,
        severity: str,
        evidence: str | None = None,
        affected_record: str | None = None,
        remediation: str | None = None,
        reference_url: str | None = None,
        cvss_score: float | None = None,
        extra: dict | None = None,
    ) -> AnalyzerResult:
        """Create a failing (issue found) AnalyzerResult."""
        return AnalyzerResult(
            analyzer=self.name,
            check_name=check,
            title=title,
            description=description,
            severity=severity,
            passed=False,
            evidence=evidence,
            affected_record=affected_record,
            remediation=remediation,
            reference_url=reference_url,
            cvss_score=cvss_score,
            extra=extra or {},
        )

    def pass_check(
        self,
        *,
        check: str,
        title: str,
        description: str,
        evidence: str | None = None,
        extra: dict | None = None,
    ) -> AnalyzerResult:
        """Create a passing (check succeeded) AnalyzerResult."""
        return AnalyzerResult(
            analyzer=self.name,
            check_name=check,
            title=title,
            description=description,
            severity="info",
            passed=True,
            evidence=evidence,
            extra=extra or {},
        )

    def info(
        self,
        *,
        check: str,
        title: str,
        description: str,
        evidence: str | None = None,
        extra: dict | None = None,
    ) -> AnalyzerResult:
        """Create an informational AnalyzerResult (no pass/fail judgement)."""
        return AnalyzerResult(
            analyzer=self.name,
            check_name=check,
            title=title,
            description=description,
            severity="info",
            passed=True,
            evidence=evidence,
            extra=extra or {},
        )

    def _error_result(
        self,
        *,
        check_name: str,
        title: str,
        description: str,
        severity: str = "medium",
    ) -> AnalyzerResult:
        """Create an internal error result (used by run() on timeout/exception)."""
        return AnalyzerResult(
            analyzer=self.name,
            check_name=check_name,
            title=title,
            description=description,
            severity=severity,
            passed=False,
            remediation="Investigate the analyzer error in the application logs.",
        )

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name!r}, enabled={self.enabled})"