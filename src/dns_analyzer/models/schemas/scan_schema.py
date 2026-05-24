"""
Pydantic API schemas for Domain, Scan, Report, and Finding.

These schemas are the contract between the API layer and its callers.
They are completely separate from the SQLAlchemy ORM models — this prevents
internal DB structures from leaking into the public API surface.

Naming convention:
    <Model>Create   : Fields required to create a new record (POST body)
    <Model>Update   : Fields that can be updated (PATCH body, all optional)
    <Model>Response : Fields returned to the caller (GET response)
    <Model>Summary  : Lightweight version for list endpoints
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

from dns_analyzer.utils.validators import validate_domain as _validate_domain
from dns_analyzer.utils.validators import validate_monitor_interval, validate_report_format


# ==============================================================================
# SHARED CONFIG
# ==============================================================================

class _Base(BaseModel):
    """Shared Pydantic config for all schemas."""
    model_config = ConfigDict(
        from_attributes=True,    # Allow construction from ORM model instances
        populate_by_name=True,
        str_strip_whitespace=True,
    )


# ==============================================================================
# FINDING SCHEMAS
# ==============================================================================

class FindingResponse(_Base):
    """A single security finding returned in scan and report responses."""

    id: str
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
    created_at: datetime

    @property
    def is_issue(self) -> bool:
        return not self.passed and self.severity != "info"


# ==============================================================================
# DOMAIN SCHEMAS
# ==============================================================================

class DomainCreate(_Base):
    """Request body for POST /domains — register a new domain."""

    name: str = Field(
        ...,
        description="Fully qualified domain name to register (e.g. example.com).",
        examples=["example.com", "mail.company.org"],
    )
    description: str | None = Field(
        default=None,
        max_length=500,
        description="Optional human-readable description.",
    )
    is_monitored: bool = Field(
        default=False,
        description="Enroll this domain in automatic scheduled scanning.",
    )
    monitor_interval_h: int = Field(
        default=24,
        ge=1,
        le=168,
        description="Hours between scheduled scans (1–168). Only used when is_monitored=true.",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Optional tags for grouping (e.g. ['production', 'critical']).",
    )
    owner_email: EmailStr | None = Field(
        default=None,
        description="Email address to notify when scan results are ready.",
    )
    notes: str | None = Field(
        default=None,
        max_length=2000,
        description="Free-text analyst notes.",
    )

    @field_validator("name", mode="before")
    @classmethod
    def validate_domain_name(cls, v: str) -> str:
        return _validate_domain(v)

    @field_validator("tags", mode="before")
    @classmethod
    def normalize_tags(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            return [t.strip().lower() for t in v.split(",") if t.strip()]
        if isinstance(v, list):
            return [str(t).strip().lower() for t in v if str(t).strip()]
        return []


class DomainUpdate(_Base):
    """Request body for PATCH /domains/{id} — partial update."""

    description: str | None = Field(default=None, max_length=500)
    is_monitored: bool | None = None
    monitor_interval_h: int | None = Field(default=None, ge=1, le=168)
    tags: list[str] | None = None
    owner_email: EmailStr | None = None
    notes: str | None = Field(default=None, max_length=2000)


class DomainSummary(_Base):
    """Lightweight domain representation for list endpoints."""

    id: str
    name: str
    description: str | None
    is_monitored: bool
    last_scanned_at: datetime | None
    last_score: int | None
    last_grade: str | None
    tags: str | None
    created_at: datetime

    @property
    def tag_list(self) -> list[str]:
        if not self.tags:
            return []
        return [t.strip() for t in self.tags.split(",") if t.strip()]


class DomainResponse(DomainSummary):
    """Full domain representation including all fields."""

    monitor_interval_h: int
    owner_email: str | None
    notes: str | None
    updated_at: datetime


# ==============================================================================
# SCAN SCHEMAS
# ==============================================================================

class ScanCreate(_Base):
    """Request body for POST /scan — trigger a new scan."""

    domain: str = Field(
        ...,
        description="Domain to scan.",
        examples=["example.com"],
    )
    analyzers: list[str] | None = Field(
        default=None,
        description=(
            "Optional subset of analyzers to run. "
            "Omit to run all enabled analyzers. "
            "Options: spf, dmarc, dkim, dnssec, axfr, caa, mta_sts, subdomain, ttl"
        ),
    )
    include_intel: bool = Field(
        default=True,
        description="Whether to query threat intelligence providers.",
    )
    report_format: str | None = Field(
        default=None,
        description="Auto-generate a report after the scan completes. Options: html, pdf, json.",
    )

    @field_validator("domain", mode="before")
    @classmethod
    def validate_domain_name(cls, v: str) -> str:
        return _validate_domain(v)

    @field_validator("report_format", mode="before")
    @classmethod
    def validate_format(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return validate_report_format(v)

    @field_validator("analyzers", mode="before")
    @classmethod
    def validate_analyzers(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        _valid = {"spf", "dmarc", "dkim", "dnssec", "axfr", "caa", "mta_sts", "subdomain", "ttl"}
        invalid = set(v) - _valid
        if invalid:
            raise ValueError(f"Unknown analyzer(s): {invalid}. Valid options: {_valid}")
        return v


class ScanSummary(_Base):
    """Lightweight scan representation for list endpoints."""

    id: str
    domain_name: str
    status: str
    triggered_by: str
    score: int | None
    grade: str | None
    duration_ms: int | None
    created_at: datetime
    completed_at: datetime | None


class ScanResponse(ScanSummary):
    """Full scan response including findings."""

    requested_by_ip: str | None
    error_message: str | None
    analyzers_run: str | None
    intel_providers_queried: str | None
    started_at: datetime | None
    updated_at: datetime
    findings: list[FindingResponse] = Field(default_factory=list)

    @property
    def findings_by_severity(self) -> dict[str, list[FindingResponse]]:
        groups: dict[str, list[FindingResponse]] = {}
        for finding in self.findings:
            groups.setdefault(finding.severity, []).append(finding)
        return groups


class BulkScanCreate(_Base):
    """Request body for POST /scan/bulk — scan multiple domains at once."""

    domains: list[str] = Field(
        ...,
        min_length=1,
        max_length=500,
        description="List of domain names to scan.",
    )
    include_intel: bool = Field(default=False, description="Query threat intel for each domain.")
    report_format: str | None = Field(default=None)

    @field_validator("domains", mode="before")
    @classmethod
    def validate_domains(cls, v: list[str]) -> list[str]:
        return [_validate_domain(d) for d in v]


class BulkScanResponse(_Base):
    """Response for bulk scan requests."""

    queued: list[str] = Field(description="Scan IDs that were successfully queued.")
    failed: list[dict[str, str]] = Field(description="Domains that could not be queued, with reasons.")
    total_queued: int
    total_failed: int


# ==============================================================================
# REPORT SCHEMAS
# ==============================================================================

class ReportSummary(_Base):
    """Lightweight report representation for list endpoints."""

    id: str
    scan_id: str
    domain_name: str
    format: str
    score: int | None
    grade: str | None
    total_findings: int
    critical_count: int
    high_count: int
    file_size_bytes: int | None
    generated_at: datetime | None
    expires_at: datetime | None
    created_at: datetime


class ReportResponse(ReportSummary):
    """Full report response including finding counts and summary."""

    title: str
    summary: str | None
    medium_count: int
    low_count: int
    file_exists: bool
    download_filename: str


class ReportGenerateRequest(_Base):
    """Request body for POST /reports/generate."""

    scan_id: str = Field(..., description="ID of a completed scan to generate a report for.")
    format: str = Field(default="html", description="Output format: html | pdf | json.")
    title: str | None = Field(default=None, max_length=200, description="Custom report title.")
    include_passing_checks: bool = Field(
        default=False,
        description="Include passing checks (severity=info) in the report.",
    )

    @field_validator("format", mode="before")
    @classmethod
    def validate_format(cls, v: str) -> str:
        return validate_report_format(v)


# ==============================================================================
# GENERIC API RESPONSE WRAPPERS
# ==============================================================================

class PaginatedResponse(_Base):
    """Generic paginated list response wrapper."""

    items: list[Any]
    total: int
    page: int
    page_size: int
    pages: int

    @model_validator(mode="after")
    def compute_pages(self) -> "PaginatedResponse":
        if self.page_size > 0:
            import math
            object.__setattr__(self, "pages", math.ceil(self.total / self.page_size))
        return self


class ErrorResponse(_Base):
    """Standard error response envelope returned by the API on failure."""

    error_code: str
    message: str
    detail: str | None = None
    context: dict[str, Any] | None = None


class HealthResponse(_Base):
    """Response body for GET /health."""

    status: str                          # "ok" | "degraded" | "error"
    version: str
    env: str
    database: dict[str, Any]
    cache: dict[str, Any]
    uptime_seconds: float | None = None