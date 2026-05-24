"""
Report builder — orchestrates the full report generation pipeline.

Pipeline:
    1. Score findings via RiskScorer → ScoreReport
    2. Select exporter based on requested format
    3. Render the ScoreReport to file
    4. Return (file_path, file_size_bytes)

Usage:
    builder = ReportBuilder.from_settings()

    # From a DB Scan object (API flow):
    file_path, size = await builder.build(scan, format="pdf")

    # From a raw ScanResult (CLI flow):
    file_path, size = await builder.build_from_result(result, format="html", output_path=Path("report.html"))
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from dns_analyzer.config.settings import get_settings
from dns_analyzer.reporting.scorer import RiskScorer, ScoreReport
from dns_analyzer.utils.logger import get_logger

if TYPE_CHECKING:
    from dns_analyzer.core.scanner import ScanResult
    from dns_analyzer.models.scan import Scan

log = get_logger(__name__)


class ReportBuilder:
    """
    Orchestrates the full report generation pipeline.

    Accepts either a DB Scan model instance (API flow) or a raw ScanResult
    (CLI flow) and delegates rendering to the appropriate exporter.

    Args:
        output_dir:    Directory where report files are written.
        template_dir:  Directory containing Jinja2 HTML templates.
    """

    def __init__(self, output_dir: Path, template_dir: Path) -> None:
        self.output_dir  = output_dir
        self.template_dir = template_dir
        self._scorer = RiskScorer()
        output_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_settings(cls) -> "ReportBuilder":
        """Build a ReportBuilder from application settings."""
        settings = get_settings()
        return cls(
            output_dir=settings.reporting.output_dir,
            template_dir=settings.reporting.template_dir,
        )

    async def build(
        self,
        scan: "Scan",
        *,
        format: str = "html",
        title: str | None = None,
        include_passing_checks: bool = False,
    ) -> tuple[Path, int]:
        """
        Generate a report from a DB Scan model instance.

        Args:
            scan:                   A completed Scan ORM instance with findings loaded.
            format:                 Output format: html | pdf | json.
            title:                  Optional custom report title.
            include_passing_checks: Include passing (info) findings in output.

        Returns:
            Tuple of (output_file_path, file_size_bytes).
        """
        from dns_analyzer.core.base_analyzer import AnalyzerResult

        # Convert ORM Finding objects to AnalyzerResult dataclasses
        findings = [
            AnalyzerResult(
                analyzer=f.analyzer,
                check_name=f.check_name,
                title=f.title,
                description=f.description,
                severity=f.severity,
                passed=f.passed,
                evidence=f.evidence,
                affected_record=f.affected_record,
                remediation=f.remediation,
                reference_url=f.reference_url,
                cvss_score=f.cvss_score,
            )
            for f in scan.findings
        ]

        score_report = self._scorer.score(scan.domain_name, findings)
        output_path  = self._make_output_path(scan.domain_name, scan.id, format)

        return await self._render(
            score_report=score_report,
            output_path=output_path,
            format=format,
            title=title or f"DNS Security Report — {scan.domain_name}",
            include_passing_checks=include_passing_checks,
            scan_id=scan.id,
        )

    async def build_from_result(
        self,
        result: "ScanResult",
        *,
        format: str = "html",
        output_path: Path | None = None,
        title: str | None = None,
        include_passing_checks: bool = False,
    ) -> tuple[Path, int]:
        """
        Generate a report from a raw ScanResult (CLI / test flow).

        Args:
            result:      ScanResult from Scanner.run().
            format:      Output format.
            output_path: Override the auto-generated file path.
            title:       Optional custom report title.

        Returns:
            Tuple of (output_file_path, file_size_bytes).
        """
        score_report = self._scorer.score(result.domain, result.findings)
        scan_id      = str(uuid.uuid4())[:8]
        path         = output_path or self._make_output_path(result.domain, scan_id, format)

        return await self._render(
            score_report=score_report,
            output_path=path,
            format=format,
            title=title or f"DNS Security Report — {result.domain}",
            include_passing_checks=include_passing_checks,
            scan_id=scan_id,
        )

    async def _render(
        self,
        score_report: ScoreReport,
        output_path: Path,
        format: str,
        title: str,
        include_passing_checks: bool,
        scan_id: str,
    ) -> tuple[Path, int]:
        """Dispatch to the correct exporter and return (path, size)."""
        from dns_analyzer.reporting.exporters.html_exporter import HTMLExporter
        from dns_analyzer.reporting.exporters.json_exporter import JSONExporter
        from dns_analyzer.reporting.exporters.pdf_exporter  import PDFExporter

        exporters = {
            "html": HTMLExporter(self.template_dir),
            "pdf":  PDFExporter(self.template_dir),
            "json": JSONExporter(),
        }

        exporter = exporters.get(format)
        if exporter is None:
            raise ValueError(f"Unsupported report format: {format!r}. Use html, pdf, or json.")

        log.info(
            "builder.rendering",
            domain=score_report.domain,
            format=format,
            output_path=str(output_path),
        )

        await exporter.render(
            score_report=score_report,
            output_path=output_path,
            title=title,
            include_passing_checks=include_passing_checks,
            scan_id=scan_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

        if not output_path.exists():
            raise RuntimeError(f"Exporter did not create output file at {output_path}")

        file_size = output_path.stat().st_size
        log.info(
            "builder.rendered",
            domain=score_report.domain,
            format=format,
            output_path=str(output_path),
            file_size_bytes=file_size,
        )

        return output_path, file_size

    def _make_output_path(self, domain: str, scan_id: str, format: str) -> Path:
        """Generate a unique output file path for a scan report."""
        safe_domain = domain.replace(".", "_").replace("-", "_")
        short_id    = scan_id[:8] if len(scan_id) >= 8 else scan_id
        filename    = f"dns_report_{safe_domain}_{short_id}.{format}"
        return self.output_dir / filename