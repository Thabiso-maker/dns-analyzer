"""
Report entity — a generated report artifact linked to a completed scan.

A Report is created after a scan completes and the reporting pipeline
renders the results into HTML, PDF, or JSON format.

Relationships:
    Report → Scan (one-to-one) : Each report belongs to exactly one scan
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from dns_analyzer.database.connection import Base

if TYPE_CHECKING:
    from dns_analyzer.models.scan import Scan


class Report(Base):
    """
    A rendered report artifact for a completed scan.

    Attributes:
        id:               UUID primary key (from Base).
        scan_id:          FK to scans.id (unique — one report per scan per format).
        domain_name:      Denormalized domain name for fast queries.
        format:           Output format: html | pdf | json.
        file_path:        Absolute path to the rendered report file on disk.
        file_size_bytes:  Size of the rendered file in bytes.
        title:            Human-readable report title.
        summary:          Short executive summary paragraph.
        score:            Copied from scan.score for fast list queries.
        grade:            Copied from scan.grade for fast list queries.
        total_findings:   Total number of findings in the report.
        critical_count:   Number of critical findings.
        high_count:       Number of high findings.
        medium_count:     Number of medium findings.
        low_count:        Number of low findings.
        expires_at:       When this report file will be auto-deleted.
        generated_at:     When report generation completed.
        created_at:       Row creation timestamp (from Base).
        updated_at:       Row last-update timestamp (from Base).
        scan:             Relationship back to the parent Scan.
    """

    __tablename__ = "reports"
    __table_args__ = (
        UniqueConstraint("scan_id", "format", name="uq_reports_scan_format"),
        {"comment": "Generated report artifacts (HTML/PDF/JSON) linked to completed scans"},
    )

    # ── Foreign key ────────────────────────────────────────────────────────────
    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="FK to the scan this report was generated from",
    )

    # Denormalized for fast list queries
    domain_name: Mapped[str] = mapped_column(
        String(253),
        nullable=False,
        index=True,
        comment="Denormalized domain name for fast listing without joins",
    )

    # ── Report identity ────────────────────────────────────────────────────────
    format: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        comment="Output format of the report: html | pdf | json",
    )
    file_path: Mapped[str] = mapped_column(
        String(1000),
        nullable=False,
        comment="Absolute filesystem path to the rendered report file",
    )
    file_size_bytes: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Size of the rendered file in bytes",
    )

    # ── Content ────────────────────────────────────────────────────────────────
    title: Mapped[str] = mapped_column(
        String(300),
        nullable=False,
        default="DNS Security Report",
        comment="Human-readable title shown at the top of the report",
    )
    summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Short executive summary paragraph for the report introduction",
    )

    # ── Score snapshot (denormalized from scan) ────────────────────────────────
    score: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Security score (0–100) copied from the parent scan",
    )
    grade: Mapped[str | None] = mapped_column(
        String(2),
        nullable=True,
        comment="Letter grade copied from the parent scan",
    )

    # ── Finding counts (denormalized for fast summary display) ─────────────────
    total_findings: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Total number of findings (all severities) included in this report",
    )
    critical_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of critical-severity findings",
    )
    high_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of high-severity findings",
    )
    medium_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of medium-severity findings",
    )
    low_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        comment="Number of low-severity findings",
    )

    # ── Lifecycle timestamps ───────────────────────────────────────────────────
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="When this report file will be automatically deleted from disk",
    )
    generated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="Timestamp when report rendering completed",
    )

    # ── Relationship ───────────────────────────────────────────────────────────
    scan: Mapped[Scan] = relationship(
        "Scan",
        back_populates="report",
        lazy="select",
    )

    # ── Helpers ────────────────────────────────────────────────────────────────
    @property
    def file_exists(self) -> bool:
        """Return True if the report file still exists on disk."""
        return Path(self.file_path).exists()

    @property
    def is_expired(self) -> bool:
        """Return True if the report has passed its expiry date."""
        if self.expires_at is None:
            return False
        from datetime import timezone
        from datetime import datetime
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def download_filename(self) -> str:
        """Return a clean filename for HTTP Content-Disposition headers."""
        safe_domain = self.domain_name.replace(".", "_")
        return f"dns_report_{safe_domain}_{self.scan_id[:8]}.{self.format}"

    def populate_finding_counts(self, findings: list) -> None:
        """
        Compute and store all finding count fields from a list of Finding objects.

        Call this after the scan completes, before saving the report to the DB.
        """
        self.total_findings = len(findings)
        self.critical_count = sum(1 for f in findings if f.severity == "critical")
        self.high_count     = sum(1 for f in findings if f.severity == "high")
        self.medium_count   = sum(1 for f in findings if f.severity == "medium")
        self.low_count      = sum(1 for f in findings if f.severity == "low")

    def __str__(self) -> str:
        return f"Report({self.format.upper()}, {self.domain_name}, score={self.score})"