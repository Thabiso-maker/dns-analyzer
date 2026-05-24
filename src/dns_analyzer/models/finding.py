"""
Finding entity — one individual security check result within a scan.

Each analyzer (SPF, DMARC, DKIM, etc.) produces one or more findings.
A finding describes a specific issue (or a passing check), its severity,
the raw evidence, and actionable remediation guidance.

Relationships:
    Finding → Scan (many-to-one) : Every finding belongs to exactly one scan
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from dns_analyzer.database.connection import Base

if TYPE_CHECKING:
    from dns_analyzer.models.scan import Scan


# Numeric sort order for severity levels (lower = more severe, sorts to top)
_SEVERITY_ORDER: dict[str, int] = {
    "critical": 1,
    "high":     2,
    "medium":   3,
    "low":      4,
    "info":     5,
}


class Finding(Base):
    """
    A single security finding produced by one analyzer during a scan.

    A finding can represent either a problem (severity: critical/high/medium/low)
    or a passing check (severity: info) — both are stored so reports can show
    a complete picture of what was checked.

    Attributes:
        id:               UUID primary key (from Base).
        scan_id:          FK to scans.id.
        analyzer:         Name of the analyzer that produced this finding
                          (e.g. "spf", "dmarc", "subdomain").
        check_name:       Specific check within the analyzer
                          (e.g. "spf_lookup_count", "dmarc_policy_strength").
        title:            Short one-line description of the finding.
        description:      Detailed explanation of the issue or passing check.
        severity:         One of: critical | high | medium | low | info.
        severity_order:   Numeric sort key (1=critical … 5=info).
        passed:           True if the check passed, False if it found an issue.
        evidence:         Raw DNS record or API response that triggered this finding.
        remediation:      Step-by-step guidance for fixing the issue.
        reference_url:    Link to relevant RFC, documentation, or best practice.
        affected_record:  The specific DNS record that is misconfigured (if any).
        cvss_score:       Optional CVSS-like numeric risk score (0.0–10.0).
        created_at:       Row creation timestamp (from Base).
        updated_at:       Row last-update timestamp (from Base).
        scan:             Relationship back to the parent Scan.
    """

    __tablename__ = "findings"
    __table_args__ = {
        "comment": "Individual security check results produced by each analyzer during a scan",
    }

    # ── Foreign key ────────────────────────────────────────────────────────────
    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="FK to the scan that produced this finding",
    )

    # ── Analyzer identification ────────────────────────────────────────────────
    analyzer: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
        comment="Name of the analyzer module (e.g. spf, dmarc, dkim, dnssec)",
    )
    check_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
        comment="Specific check identifier within the analyzer (e.g. spf_lookup_count)",
    )

    # ── Finding content ────────────────────────────────────────────────────────
    title: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
        comment="Short one-line summary of the finding",
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Detailed explanation of what was found and why it matters",
    )

    # ── Severity ───────────────────────────────────────────────────────────────
    severity: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        index=True,
        comment="Risk level: critical | high | medium | low | info",
    )
    severity_order: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=5,
        index=True,
        comment="Numeric sort key for severity (1=critical, 5=info) — used for ORDER BY",
    )
    passed: Mapped[bool] = mapped_column(
        nullable=False,
        default=False,
        index=True,
        comment="True = check passed cleanly; False = issue found",
    )

    # ── Evidence ───────────────────────────────────────────────────────────────
    evidence: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Raw DNS record, API response, or other data that triggered this finding",
    )
    affected_record: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
        comment="The specific DNS record value that is misconfigured or missing",
    )

    # ── Remediation ────────────────────────────────────────────────────────────
    remediation: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Step-by-step guidance for resolving this finding",
    )
    reference_url: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
        comment="Link to the relevant RFC, standard, or documentation page",
    )

    # ── Risk scoring ───────────────────────────────────────────────────────────
    cvss_score: Mapped[float | None] = mapped_column(
        nullable=True,
        comment="Optional CVSS-like numeric risk score (0.0–10.0)",
    )

    # ── Relationships ──────────────────────────────────────────────────────────
    scan: Mapped[Scan] = relationship(
        "Scan",
        back_populates="findings",
        lazy="select",
    )

    # ── Class method constructor ───────────────────────────────────────────────
    @classmethod
    def create(
        cls,
        *,
        scan_id: str,
        analyzer: str,
        check_name: str,
        title: str,
        description: str,
        severity: str,
        passed: bool,
        evidence: str | None = None,
        affected_record: str | None = None,
        remediation: str | None = None,
        reference_url: str | None = None,
        cvss_score: float | None = None,
    ) -> "Finding":
        """
        Factory method for creating a Finding with auto-computed severity_order.

        Using a factory method (rather than __init__) ensures severity_order
        is always set correctly and severity is always validated.

        Raises:
            ValueError: If severity is not a recognised level.
        """
        if severity not in _SEVERITY_ORDER:
            raise ValueError(
                f"Invalid severity: {severity!r}. "
                f"Must be one of: {list(_SEVERITY_ORDER.keys())}"
            )

        return cls(
            scan_id=scan_id,
            analyzer=analyzer,
            check_name=check_name,
            title=title,
            description=description,
            severity=severity,
            severity_order=_SEVERITY_ORDER[severity],
            passed=passed,
            evidence=evidence,
            affected_record=affected_record,
            remediation=remediation,
            reference_url=reference_url,
            cvss_score=cvss_score,
        )

    # ── Properties ─────────────────────────────────────────────────────────────
    @property
    def is_issue(self) -> bool:
        """True if this finding represents a real problem (not a passing check)."""
        return not self.passed and self.severity != "info"

    @property
    def severity_emoji(self) -> str:
        """Return a terminal-friendly severity indicator for CLI output."""
        return {
            "critical": "[CRITICAL]",
            "high":     "[HIGH]",
            "medium":   "[MEDIUM]",
            "low":      "[LOW]",
            "info":     "[INFO]",
        }.get(self.severity, "[?]")

    def __str__(self) -> str:
        status = "PASS" if self.passed else "FAIL"
        return f"[{status}] [{self.severity.upper()}] {self.analyzer}/{self.check_name}: {self.title}"