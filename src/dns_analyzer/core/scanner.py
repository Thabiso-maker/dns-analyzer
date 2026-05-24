"""
Scan orchestrator — the central brain of the DNS Security Analyzer.

The Scanner coordinates the full scan pipeline:
    1. Validate and prepare the domain
    2. Initialize the DNS resolver
    3. Run all enabled analyzers concurrently
    4. Query threat intelligence providers
    5. Score and grade the results
    6. Return a ScanResult ready for persistence and reporting

The Scanner is stateless — create a new instance per scan.

Usage:
    scanner = Scanner.from_settings()
    result  = await scanner.run("example.com")
    print(result.grade, result.score)
    for finding in result.findings:
        print(finding)
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

from dns_analyzer.config.constants import Grade, Severity
from dns_analyzer.config.settings import get_settings
from dns_analyzer.core.analyzers.analyzers import (
    AXFRAnalyzer,
    CAAAnalyzer,
    DKIMAnalyzer,
    DNSSECAnalyzer,
    MTASTSAnalyzer,
    SubdomainAnalyzer,
    TTLAnalyzer,
)
from dns_analyzer.core.analyzers.dmarc import DMARCAnalyzer
from dns_analyzer.core.analyzers.spf import SPFAnalyzer
from dns_analyzer.core.base_analyzer import AnalyzerResult, BaseAnalyzer
from dns_analyzer.core.resolver import DNSResolver
from dns_analyzer.utils.logger import get_logger, bind_contextvars, clear_contextvars
from dns_analyzer.utils.validators import validate_domain

log = get_logger(__name__)


# ==============================================================================
# SCAN RESULT
# ==============================================================================

@dataclass
class ScanResult:
    """
    The complete output of a domain scan.

    Contains all findings, the computed score and grade, timing information,
    and metadata about what analyzers and intel providers ran.

    This is the internal representation passed between the scanner,
    scorer, reporter, and database layer.
    """

    domain: str
    findings: list[AnalyzerResult] = field(default_factory=list)
    score: int = 0
    grade: str = "F"
    duration_ms: int = 0
    analyzers_run: list[str] = field(default_factory=list)
    analyzers_failed: list[str] = field(default_factory=list)
    intel_providers_queried: list[str] = field(default_factory=list)
    intel_data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    success: bool = True

    @property
    def issues(self) -> list[AnalyzerResult]:
        """All findings that represent real problems (non-passing, non-info)."""
        return [f for f in self.findings if f.is_issue]

    @property
    def critical_findings(self) -> list[AnalyzerResult]:
        return [f for f in self.findings if f.severity == "critical"]

    @property
    def high_findings(self) -> list[AnalyzerResult]:
        return [f for f in self.findings if f.severity == "high"]

    @property
    def findings_by_analyzer(self) -> dict[str, list[AnalyzerResult]]:
        groups: dict[str, list[AnalyzerResult]] = {}
        for f in self.findings:
            groups.setdefault(f.analyzer, []).append(f)
        return groups

    def summary(self) -> str:
        """Return a one-line human-readable scan summary."""
        return (
            f"{self.domain} | Grade: {self.grade} | Score: {self.score}/100 | "
            f"Issues: {len(self.issues)} | Duration: {self.duration_ms}ms"
        )


# ==============================================================================
# SCANNER
# ==============================================================================

class Scanner:
    """
    Orchestrates a complete DNS security scan against a domain.

    Args:
        analyzers:       List of analyzer instances to run.
        resolver:        DNS resolver engine (shared across all analyzers).
        include_intel:   Whether to query threat intelligence providers.
        max_concurrency: Maximum number of analyzers to run simultaneously.
    """

    def __init__(
        self,
        analyzers: list[BaseAnalyzer],
        resolver: DNSResolver,
        *,
        include_intel: bool = True,
        max_concurrency: int = 5,
    ) -> None:
        self.analyzers = [a for a in analyzers if a.enabled]
        self.resolver = resolver
        self.include_intel = include_intel
        self._semaphore = asyncio.Semaphore(max_concurrency)

    @classmethod
    def from_settings(
        cls,
        *,
        analyzer_names: list[str] | None = None,
        include_intel: bool = True,
    ) -> "Scanner":
        """
        Build a Scanner fully configured from application settings.

        Args:
            analyzer_names: Optional subset of analyzers to run.
                            If None, all enabled analyzers run.
            include_intel:  Whether to query threat intel providers.

        Returns:
            A fully configured Scanner instance.
        """
        settings = get_settings()
        features = settings.features

        all_analyzers: list[BaseAnalyzer] = [
            SPFAnalyzer(),
            DMARCAnalyzer(),
            DKIMAnalyzer(),
            CAAAnalyzer(),
            MTASTSAnalyzer(),
            TTLAnalyzer(),
        ]

        # Feature-flagged analyzers
        if features.dnssec_check:
            all_analyzers.append(DNSSECAnalyzer())
        if features.axfr_check:
            all_analyzers.append(AXFRAnalyzer())
        if features.subdomain_enumeration:
            all_analyzers.append(SubdomainAnalyzer())

        # Filter to requested subset if specified
        if analyzer_names:
            all_analyzers = [a for a in all_analyzers if a.name in analyzer_names]

        resolver = DNSResolver.from_settings()

        return cls(
            analyzers=all_analyzers,
            resolver=resolver,
            include_intel=include_intel and features.threat_intel,
        )

    # ── Main scan pipeline ─────────────────────────────────────────────────────

    async def run(self, domain: str, scan_id: str | None = None) -> ScanResult:
        """
        Execute the full scan pipeline against a domain.

        Args:
            domain:  Fully qualified domain name to scan.
            scan_id: Optional scan ID for log correlation.

        Returns:
            ScanResult with all findings, score, grade, and metadata.
        """
        # Normalize and validate domain
        domain = validate_domain(domain)

        # Bind scan context to all log calls in this scope
        bind_contextvars(domain=domain, scan_id=scan_id or "adhoc")
        start = time.monotonic()

        log.info("scanner.started", domain=domain, analyzers=len(self.analyzers))

        result = ScanResult(domain=domain)

        try:
            # ── Step 1: Run all analyzers concurrently ─────────────────────────
            analyzer_findings, analyzers_run, analyzers_failed = await self._run_analyzers(domain)
            result.findings = analyzer_findings
            result.analyzers_run = analyzers_run
            result.analyzers_failed = analyzers_failed

            # ── Step 2: Threat intelligence enrichment ─────────────────────────
            if self.include_intel:
                intel_data, providers = await self._run_intel(domain)
                result.intel_data = intel_data
                result.intel_providers_queried = providers

            # ── Step 3: Score and grade ────────────────────────────────────────
            result.score = self._compute_score(result.findings)
            result.grade = Grade.from_score(result.score)

            result.duration_ms = int((time.monotonic() - start) * 1000)

            log.info(
                "scanner.completed",
                domain=domain,
                score=result.score,
                grade=result.grade,
                findings=len(result.findings),
                issues=len(result.issues),
                duration_ms=result.duration_ms,
            )

        except Exception as exc:
            result.success = False
            result.error = str(exc)
            result.duration_ms = int((time.monotonic() - start) * 1000)
            log.error(
                "scanner.failed",
                domain=domain,
                error=str(exc),
                duration_ms=result.duration_ms,
                exc_info=True,
            )

        finally:
            clear_contextvars()

        return result

    async def _run_analyzers(
        self,
        domain: str,
    ) -> tuple[list[AnalyzerResult], list[str], list[str]]:
        """
        Run all enabled analyzers concurrently.

        Returns:
            Tuple of (all_findings, successful_analyzer_names, failed_analyzer_names)
        """
        async def run_with_semaphore(analyzer: BaseAnalyzer) -> tuple[str, list[AnalyzerResult]]:
            async with self._semaphore:
                findings = await analyzer.run(domain, self.resolver)
                return analyzer.name, findings

        tasks = [run_with_semaphore(a) for a in self.analyzers]
        task_results = await asyncio.gather(*tasks, return_exceptions=True)

        all_findings: list[AnalyzerResult] = []
        analyzers_run: list[str] = []
        analyzers_failed: list[str] = []

        for analyzer, task_result in zip(self.analyzers, task_results):
            if isinstance(task_result, Exception):
                analyzers_failed.append(analyzer.name)
                log.error(
                    "scanner.analyzer_crashed",
                    analyzer=analyzer.name,
                    error=str(task_result),
                )
                continue

            name, findings = task_result
            analyzers_run.append(name)
            all_findings.extend(findings)

        return all_findings, analyzers_run, analyzers_failed

    async def _run_intel(self, domain: str) -> tuple[dict[str, Any], list[str]]:
        """
        Query all enabled threat intelligence providers.

        Returns:
            Tuple of (combined_intel_data, provider_names_queried)
        """
        try:
            from dns_analyzer.intelligence.manager import IntelligenceManager
            manager = IntelligenceManager.from_settings()
            intel_data = await manager.enrich_domain(domain)
            providers = list(intel_data.keys())
            return intel_data, providers
        except Exception as exc:
            log.warning("scanner.intel_failed", domain=domain, error=str(exc))
            return {}, []

    def _compute_score(self, findings: list[AnalyzerResult]) -> int:
        """
        Compute a 0–100 security score from scan findings.

        Algorithm:
            Start at 100. Deduct weighted penalty for each failing check.
            Penalties are proportional to severity weights (critical=100, high=75, etc.)
            Score is capped at 0 and rounded to the nearest integer.

        A domain with no issues scores 100.
        A domain with one critical finding scores around 30–50.
        A domain with multiple critical findings scores 0.
        """
        if not findings:
            return 100

        # Total possible penalty = sum of all failing check weights
        # We normalise so a single critical finding drops you to ~30
        total_penalty = 0.0
        max_possible_penalty = 0.0

        for finding in findings:
            weight = Severity.WEIGHTS.get(finding.severity, 0)
            max_possible_penalty += weight
            if not finding.passed:
                total_penalty += weight

        if max_possible_penalty == 0:
            return 100

        # Scale penalty to a 0–100 deduction
        penalty_ratio = min(total_penalty / max_possible_penalty, 1.0)

        # Apply non-linear scaling: first issues hurt most
        scaled_penalty = penalty_ratio ** 0.6 * 100

        score = max(0, round(100 - scaled_penalty))
        return score

    def __repr__(self) -> str:
        names = [a.name for a in self.analyzers]
        return f"Scanner(analyzers={names}, include_intel={self.include_intel})"