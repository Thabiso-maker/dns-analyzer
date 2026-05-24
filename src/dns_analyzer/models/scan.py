"""
Scan entity — represents one full security analysis run against a domain.

A Scan is created when a scan is requested and updated as it progresses
through the pipeline. When complete, it holds the aggregated score, grade,
duration, and links to all individual findings.

Relationships:
    Scan → Domain   (many-to-one)  : Every scan belongs to one domain
    Scan → Finding  (one-to-many)  : A scan produces zero or more findings
    Scan → Report   (one-to-one)   : A completed scan may have a report
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from dns_analyzer.database.connection import Base

if TYPE_CHECKING:
    from dns_analyzer.models.domain import Domain
    from dns_analyzer.models.finding import Finding
    from dns_analyzer.models.report import Report


class Scan(Base):
    """
    Represents a single DNS security scan run.

    Lifecycle:
        pending → running → completed | failed | cancelled

    Attributes:
        id:               UUID primary key (from Base).
        domain_id:        FK to domains.id.
        domain_name:      Denormalized domain name for fast lookups without joins.
        status:           Current lifecycle state of the scan.
        triggered_by:     How the scan was started ("api", "cli", "scheduler").
        requested_by_ip:  IP address of the API caller (audit trail).
        score:            Aggregate security score (0–100) after completion.
        grade:            Letter grade after completion.
        duration_ms:      Wall-clock duration of the scan in milliseconds.
        error_message:    Set when status = "failed". Human-readable failure reason.
        resolver_used:    JSON array of resolver IPs used during the scan.
        analyzers_run:    Comma-separated list of analyzers that executed.
        intel_providers:  Comma-separated list of intel providers queried.
        started_at:       When the scan pipeline began executing.
        completed_at:     When the scan pipeline finished (success or failure).
        created_at:       Row creation timestamp (from Base).
        updated_at:       Row last-update timestamp (from Base).
        domain:           Relationship back to the Domain.
        findings:         Relationship to all Finding records for this scan.
        report:           Relationship to the generated Report (if any).
    """

    __tablename__ = "scans"
    __table_args__ = {
        "comment": "Individual DNS security scan runs and their aggregated results",
    }

    # ── Foreign key ────────────────────────────────────────────────────────────
    domain_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("domains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="FK to the domain this scan belongs to",
    )

    # Denormalized for fast queries without joining to domains table
    domain_name: Mapped[str] = mapped_column(
        String(253),
        nullable=False,
        index=True,
        comment="Denormalized domain name copied from domains.name at scan creation",
    )

    # ── Status ─────────────────────────────────────────────────────────────────
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pending",
        index=True,
        comment="Lifecycle state: pending | running | completed | failed | cancelled",
    )
    triggered_by: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="api",
        comment="What initiated this scan: api | cli | scheduler",
    )
    requested_by_ip: Mapped[str | None] = mapped_column(
        String(45),    # Max IPv6 length
        nullable=True,
        comment="IP address of the API caller for audit purposes",
    )

    # ── Results (populated after completion) ───────────────────────────────────
    score: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Aggregate security score 0–100 (higher = better posture)",
    )
    grade: Mapped[str | None] = mapped_column(
        String(2),
        nullable=True,
        comment="Letter grade: A+, A, B, C, D, F",
    )
    duration_ms: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Wall-clock time from scan start to completion in milliseconds",
    )

    # ── Failure info ───────────────────────────────────────────────────────────
    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Human-readable failure reason when status = failed",
    )

    # ── Execution metadata ─────────────────────────────────────────────────────
    resolver_used: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="JSON array of DNS resolver IPs used during this scan",
    )
    analyzers_run: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
        comment="Comma-separated list of analyzer names that ran successfully",
    )
    intel_providers_queried: Mapped[str | None] = mapped_column(
        String(200),
        nullable=True,
        comment="Comma-separated list of threat intel providers queried",
    )

    # ── Timestamps ─────────────────────────────────────────────────────────────
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        comment="When the scan pipeline began executing",
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="When the scan pipeline finished (success or failure)",
    )

    # ── Relationships ──────────────────────────────────────────────────────────
    domain: Mapped[Domain] = relationship(
        "Domain",
        back_populates="scans",
        lazy="select",
    )
    findings: Mapped[list[Finding]] = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan",
        order_by="Finding.severity_order",
        lazy="select",
    )
    report: Mapped[Report | None] = relationship(
        "Report",
        back_populates="scan",
        cascade="all, delete-orphan",
        uselist=False,   # One-to-one
        lazy="select",
    )

    # ── Lifecycle helpers ──────────────────────────────────────────────────────

    def mark_running(self) -> None:
        """Transition status to running and record the start time."""
        self.status = "running"
        self.started_at = datetime.now(timezone.utc)

    def mark_completed(self, score: int, grade: str, analyzers: list[str], providers: list[str]) -> None:
        """Transition to completed and record results."""
        now = datetime.now(timezone.utc)
        self.status = "completed"
        self.completed_at = now
        self.score = score
        self.grade = grade
        self.analyzers_run = ",".join(analyzers)
        self.intel_providers_queried = ",".join(providers)
        if self.started_at:
            delta = now - self.started_at
            self.duration_ms = int(delta.total_seconds() * 1000)

    def mark_failed(self, reason: str) -> None:
        """Transition to failed and record the error message."""
        self.status = "failed"
        self.completed_at = datetime.now(timezone.utc)
        self.error_message = reason

    def mark_cancelled(self) -> None:
        """Transition to cancelled."""
        self.status = "cancelled"
        self.completed_at = datetime.now(timezone.utc)

    @property
    def is_terminal(self) -> bool:
        """Return True if the scan has reached a final state."""
        return self.status in ("completed", "failed", "cancelled")

    @property
    def findings_by_severity(self) -> dict[str, list[Finding]]:
        """Group findings by severity level for quick access."""
        groups: dict[str, list[Finding]] = {}
        for finding in self.findings:
            groups.setdefault(finding.severity, []).append(finding)
        return groups

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")