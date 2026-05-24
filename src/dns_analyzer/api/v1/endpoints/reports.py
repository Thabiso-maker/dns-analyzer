"""
Reports endpoints — generate, retrieve, download, and delete scan reports.

POST   /reports/generate     — generate a report from a completed scan
GET    /reports              — list all reports
GET    /reports/{id}         — get report metadata
GET    /reports/{id}/download — download report file (HTML/PDF/JSON)
DELETE /reports/{id}         — delete a report
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import FileResponse

from dns_analyzer.api.dependencies import Pagination, ReportRepo, RequireAuth, ScanRepo
from dns_analyzer.models.schemas.schemas import (
    ReportGenerateRequest,
    ReportResponse,
    ReportSummary,
)
from dns_analyzer.utils.logger import get_logger

router = APIRouter()
log    = get_logger(__name__)


@router.post(
    "/generate",
    summary="Generate a report from a completed scan",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
)
async def generate_report(
    body: ReportGenerateRequest,
    _: RequireAuth,
    scan_repo: ScanRepo,
    report_repo: ReportRepo,
) -> ReportResponse:
    """
    Generate an HTML, PDF, or JSON report from a completed scan.

    The scan must be in 'completed' status. Generating the same format
    for the same scan replaces the existing report.
    """
    # Verify scan exists and is complete
    scan = await scan_repo.get_with_findings(body.scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_code": "SCAN_NOT_FOUND", "message": f"Scan {body.scan_id!r} not found."},
        )

    if scan.status != "completed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error_code": "SCAN_NOT_COMPLETE",
                "message": f"Scan is not yet complete (status: {scan.status!r}). Wait for completion before generating a report.",
            },
        )

    # Build the report
    try:
        from dns_analyzer.reporting.builder import ReportBuilder
        builder = ReportBuilder.from_settings()
        file_path, file_size = await builder.build(
            scan=scan,
            format=body.format,
            title=body.title or f"DNS Security Report — {scan.domain_name}",
            include_passing_checks=body.include_passing_checks,
        )
    except Exception as exc:
        log.error("reports.generation_failed", scan_id=body.scan_id, error=str(exc), exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error_code": "REPORT_GENERATION_FAILED", "message": str(exc)},
        )

    # Delete existing report for same scan+format if present
    existing = await report_repo.get_by_scan(body.scan_id, format=body.format)
    if existing:
        await report_repo.delete(existing.id)

    # Persist report record
    from datetime import datetime, timedelta, timezone
    settings_obj = __import__("dns_analyzer.config.settings", fromlist=["get_settings"]).get_settings()
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings_obj.reporting.max_age_days)

    report = await report_repo.create_report(
        scan,
        format=body.format,
        file_path=str(file_path),
        file_size_bytes=file_size,
        title=body.title or f"DNS Security Report — {scan.domain_name}",
        expires_at=expires_at,
    )

    log.info(
        "reports.generated",
        report_id=report.id,
        scan_id=body.scan_id,
        format=body.format,
        file_size=file_size,
    )

    return ReportResponse(
        **ReportSummary.model_validate(report).model_dump(),
        title=report.title,
        summary=report.summary,
        medium_count=report.medium_count,
        low_count=report.low_count,
        file_exists=report.file_exists,
        download_filename=report.download_filename,
    )


@router.get(
    "",
    summary="List all reports",
    response_model=list[ReportSummary],
)
async def list_reports(
    _: RequireAuth,
    report_repo: ReportRepo,
    pagination: Pagination,
    domain: str | None = Query(default=None, description="Filter by domain name"),
    fmt: str | None = Query(default=None, alias="format", description="Filter by format (html/pdf/json)"),
) -> list[ReportSummary]:
    """Return a paginated list of generated reports."""
    if domain:
        reports = await report_repo.list_for_domain(
            domain,
            offset=pagination.offset,
            limit=pagination.limit,
            format=fmt,
        )
    else:
        reports = await report_repo.list_recent(limit=pagination.limit)

    return [ReportSummary.model_validate(r) for r in reports]


@router.get(
    "/{report_id}",
    summary="Get report metadata",
    response_model=ReportResponse,
)
async def get_report(
    report_id: str,
    _: RequireAuth,
    report_repo: ReportRepo,
) -> ReportResponse:
    """Retrieve metadata for a specific report."""
    report = await report_repo.get(report_id)
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_code": "REPORT_NOT_FOUND", "message": f"Report {report_id!r} not found."},
        )

    return ReportResponse(
        **ReportSummary.model_validate(report).model_dump(),
        title=report.title,
        summary=report.summary,
        medium_count=report.medium_count,
        low_count=report.low_count,
        file_exists=report.file_exists,
        download_filename=report.download_filename,
    )


@router.get(
    "/{report_id}/download",
    summary="Download report file",
)
async def download_report(
    report_id: str,
    _: RequireAuth,
    report_repo: ReportRepo,
) -> FileResponse:
    """
    Stream the report file to the client.

    Sets appropriate Content-Type and Content-Disposition headers
    so browsers download the file with the correct extension.
    """
    report = await report_repo.get(report_id)
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_code": "REPORT_NOT_FOUND", "message": f"Report {report_id!r} not found."},
        )

    if report.is_expired:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail={"error_code": "REPORT_EXPIRED", "message": "This report has expired and been deleted."},
        )

    if not report.file_exists:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_code": "REPORT_FILE_MISSING", "message": "Report file not found on disk."},
        )

    _MEDIA_TYPES = {
        "html": "text/html",
        "pdf":  "application/pdf",
        "json": "application/json",
    }
    media_type = _MEDIA_TYPES.get(report.format, "application/octet-stream")

    return FileResponse(
        path=report.file_path,
        filename=report.download_filename,
        media_type=media_type,
    )


@router.delete(
    "/{report_id}",
    summary="Delete a report",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_report(
    report_id: str,
    _: RequireAuth,
    report_repo: ReportRepo,
) -> None:
    """Delete a report record and its associated file from disk."""
    report = await report_repo.get(report_id)
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_code": "REPORT_NOT_FOUND", "message": f"Report {report_id!r} not found."},
        )

    # Delete file from disk
    if report.file_exists:
        try:
            Path(report.file_path).unlink(missing_ok=True)
        except OSError as exc:
            log.warning("reports.file_delete_failed", report_id=report_id, error=str(exc))

    await report_repo.delete(report_id)
    log.info("reports.deleted", report_id=report_id)