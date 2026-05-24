from __future__ import annotations
from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field, field_validator
from dns_analyzer.utils.validators import validate_domain as _validate_domain, validate_report_format

class _Base(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True, str_strip_whitespace=True)

class FindingResponse(_Base):
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

class DomainCreate(_Base):
    name: str = Field(..., description="Domain name")
    description: str | None = Field(default=None, max_length=500)
    is_monitored: bool = Field(default=False)
    monitor_interval_h: int = Field(default=24, ge=1, le=168)
    tags: list[str] = Field(default_factory=list)
    owner_email: str | None = Field(default=None)
    notes: str | None = Field(default=None, max_length=2000)

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
    description: str | None = None
    is_monitored: bool | None = None
    monitor_interval_h: int | None = Field(default=None, ge=1, le=168)
    tags: list[str] | None = None
    owner_email: str | None = None
    notes: str | None = None

class DomainSummary(_Base):
    id: str
    name: str
    description: str | None = None
    is_monitored: bool
    last_scanned_at: datetime | None = None
    last_score: int | None = None
    last_grade: str | None = None
    tags: str | None = None
    created_at: datetime

class DomainResponse(DomainSummary):
    monitor_interval_h: int
    owner_email: str | None = None
    notes: str | None = None
    updated_at: datetime

class ScanCreate(_Base):
    domain: str = Field(..., description="Domain to scan")
    analyzers: list[str] | None = Field(default=None)
    include_intel: bool = Field(default=False)
    report_format: str | None = Field(default=None)

    @field_validator("domain", mode="before")
    @classmethod
    def validate_domain_name(cls, v: str) -> str:
        return _validate_domain(v)

    @field_validator("report_format", mode="before")
    @classmethod
    def validate_fmt(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return validate_report_format(v)

class ScanSummary(_Base):
    id: str
    domain_name: str
    status: str
    triggered_by: str
    score: int | None = None
    grade: str | None = None
    duration_ms: int | None = None
    created_at: datetime
    completed_at: datetime | None = None

class ScanResponse(ScanSummary):
    requested_by_ip: str | None = None
    error_message: str | None = None
    analyzers_run: str | None = None
    intel_providers_queried: str | None = None
    started_at: datetime | None = None
    updated_at: datetime
    findings: list[FindingResponse] = Field(default_factory=list)

class BulkScanCreate(_Base):
    domains: list[str] = Field(..., min_length=1, max_length=500)
    include_intel: bool = Field(default=False)
    report_format: str | None = Field(default=None)

    @field_validator("domains", mode="before")
    @classmethod
    def validate_domains(cls, v: list[str]) -> list[str]:
        return [_validate_domain(d) for d in v]

class BulkScanResponse(_Base):
    queued: list[str]
    failed: list[dict[str, str]]
    total_queued: int
    total_failed: int

class ReportSummary(_Base):
    id: str
    scan_id: str
    domain_name: str
    format: str
    score: int | None = None
    grade: str | None = None
    total_findings: int
    critical_count: int
    high_count: int
    file_size_bytes: int | None = None
    generated_at: datetime | None = None
    expires_at: datetime | None = None
    created_at: datetime

class ReportResponse(ReportSummary):
    title: str
    summary: str | None = None
    medium_count: int
    low_count: int
    file_exists: bool
    download_filename: str

class ReportGenerateRequest(_Base):
    scan_id: str = Field(..., description="ID of completed scan")
    format: str = Field(default="html")
    title: str | None = Field(default=None, max_length=200)
    include_passing_checks: bool = Field(default=False)

    @field_validator("format", mode="before")
    @classmethod
    def validate_fmt(cls, v: str) -> str:
        return validate_report_format(v)

class ErrorResponse(_Base):
    error_code: str
    message: str
    detail: str | None = None
    context: dict[str, Any] | None = None

class HealthResponse(_Base):
    status: str
    version: str
    env: str
    database: dict[str, Any]
    cache: dict[str, Any]
    uptime_seconds: float | None = None