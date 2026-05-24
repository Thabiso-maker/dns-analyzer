"""
Domain entity — represents a domain being tracked and monitored.

A Domain is the top-level object in the system. Every scan belongs to a domain,
and every monitoring schedule is attached to a domain.

Relationships:
    Domain → Scan (one-to-many)   : A domain can have many scan history entries
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from dns_analyzer.database.connection import Base

if TYPE_CHECKING:
    from dns_analyzer.models.scan import Scan


class Domain(Base):
    """
    Represents a domain under monitoring or analysis.

    Attributes:
        id:                   UUID primary key (from Base).
        name:                 Fully qualified domain name (e.g. "example.com").
        description:          Optional human-readable description or tag.
        is_monitored:         Whether the domain is enrolled in scheduled scanning.
        monitor_interval_h:   Hours between scheduled scans (default 24).
        last_scanned_at:      Timestamp of the most recent completed scan.
        last_score:           Overall security score from the most recent scan (0–100).
        last_grade:           Letter grade from the most recent scan (A+, A, B … F).
        tags:                 Comma-separated tags for grouping (e.g. "production,critical").
        owner_email:          Contact email for scan result notifications.
        notes:                Free-text notes for analysts.
        created_at:           Row creation timestamp (from Base).
        updated_at:           Row last-update timestamp (from Base).
        scans:                Back-populated relationship to Scan records.
    """

    __tablename__ = "domains"
    __table_args__ = (
        UniqueConstraint("name", name="uq_domains_name"),
        {"comment": "Domains registered for DNS security analysis and monitoring"},
    )

    # ── Core fields ────────────────────────────────────────────────────────────
    name: Mapped[str] = mapped_column(
        String(253),
        nullable=False,
        index=True,
        comment="Fully qualified domain name (max 253 chars per RFC 1035)",
    )
    description: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Optional human-readable description or purpose of this domain",
    )

    # ── Monitoring ─────────────────────────────────────────────────────────────
    is_monitored: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        index=True,
        comment="Whether this domain is enrolled in scheduled automatic scanning",
    )
    monitor_interval_h: Mapped[int] = mapped_column(
        Integer,
        default=24,
        nullable=False,
        comment="Hours between scheduled scans (1–168)",
    )

    # ── Latest scan summary (denormalized for fast list queries) ──────────────
    last_scanned_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Timestamp of the most recently completed scan",
    )
    last_score: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
        comment="Overall security score (0–100) from the most recent scan",
    )
    last_grade: Mapped[str | None] = mapped_column(
        String(2),
        nullable=True,
        comment="Letter grade (A+, A, B, C, D, F) from the most recent scan",
    )

    # ── Metadata ───────────────────────────────────────────────────────────────
    tags: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
        comment="Comma-separated tags for grouping and filtering (e.g. 'production,critical')",
    )
    owner_email: Mapped[str | None] = mapped_column(
        String(254),
        nullable=True,
        comment="Email address to notify when scan results are ready or issues are found",
    )
    notes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Free-text analyst notes about this domain",
    )

    # ── Relationships ──────────────────────────────────────────────────────────
    scans: Mapped[list[Scan]] = relationship(
        "Scan",
        back_populates="domain",
        cascade="all, delete-orphan",
        order_by="Scan.created_at.desc()",
        lazy="select",
    )

    # ── Helpers ────────────────────────────────────────────────────────────────
    @property
    def tag_list(self) -> list[str]:
        """Return tags as a Python list."""
        if not self.tags:
            return []
        return [t.strip() for t in self.tags.split(",") if t.strip()]

    def set_tags(self, tags: list[str]) -> None:
        """Set tags from a Python list."""
        self.tags = ",".join(t.strip().lower() for t in tags if t.strip())

    def update_last_scan_summary(self, score: int, grade: str, scanned_at: datetime) -> None:
        """
        Update the denormalized last-scan summary fields.

        Called by the scan pipeline after a scan completes, so the domain
        list view always shows fresh scores without joining to the scans table.
        """
        self.last_score = score
        self.last_grade = grade
        self.last_scanned_at = scanned_at

    def __str__(self) -> str:
        return self.name