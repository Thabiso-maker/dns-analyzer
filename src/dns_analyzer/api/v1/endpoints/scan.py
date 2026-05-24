"""
Scan endpoints — trigger, monitor, and retrieve DNS security scans.

POST   /scan              — trigger a new scan
GET    /scan/{id}         — get scan result with findings
GET    /scan              — list recent scans
POST   /scan/bulk         — scan multiple domains
DELETE /scan/{id}         — cancel a running scan
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request, status

from dns_analyzer.api.dependencies import (
    DomainRepo,
    Pagination,
    RequireAuth,
    ScanRepo,
    get_client_ip,
)
from dns_analyzer.models.schemas.schemas import (
    BulkScanCreate,
    BulkScanResponse,
    ScanCreate,
    ScanResponse,
    ScanSummary,
)
from dns_analyzer.utils.exceptions import (
    InvalidDomainError,
    RecordNotFoundError,
    ScanAlreadyRunningError,
)
from dns_analyzer.utils.logger import get_logger

router = APIRouter()
log    = get_logger(__name__)


async def _run_scan_pipeline(
    scan_id: str,
    domain_name: str,
    domain_id: str,
    include_intel: bool,
    analyzer_names: list[str] | None,
) -> None:
    """
    Background task: execute the full scan pipeline and persist results.

    This runs after the HTTP response is returned to the caller, so the
    API immediately returns 202 Accepted and the scan runs asynchronously.
    """
    from datetime import datetime, timezone

    from dns_analyzer.core.scanner import Scanner
    from dns_analyzer.database.connection import db_session
    from dns_analyzer.database.repositories.repositories import (
        DomainRepository,
        ScanRepository,
    )
    from dns_analyzer.models.finding import Finding

    log.info("scan_pipeline.started", scan_id=scan_id, domain=domain_name)

    async with db_session() as session:
        scan_repo   = ScanRepository(session)
        domain_repo = DomainRepository(session)

        scan = await scan_repo.get_or_raise(scan_id)
        scan.mark_running()
        await scan_repo.update(scan)

        try:
            # Build and run scanner
            scanner = Scanner.from_settings(
                analyzer_names=analyzer_names,
                include_intel=include_intel,
            )
            result = await scanner.run(domain_name, scan_id=scan_id)

            # Persist findings
            findings = [
                Finding.create(
                    scan_id=scan_id,
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
                for f in result.findings
            ]
            await scan_repo.save_findings(findings)

            # Mark scan complete
            now = datetime.now(timezone.utc)
            scan.mark_completed(
                score=result.score,
                grade=result.grade,
                analyzers=result.analyzers_run,
                providers=result.intel_providers_queried,
            )
            await scan_repo.update(scan)

            # Update domain summary
            await domain_repo.update_last_scan_summary(
                domain_id,
                score=result.score,
                grade=result.grade,
                scanned_at=now,
            )

            log.info(
                "scan_pipeline.completed",
                scan_id=scan_id,
                domain=domain_name,
                score=result.score,
                grade=result.grade,
                findings=len(findings),
            )

        except Exception as exc:
            scan.mark_failed(str(exc))
            await scan_repo.update(scan)
            log.error(
                "scan_pipeline.failed",
                scan_id=scan_id,
                domain=domain_name,
                error=str(exc),
                exc_info=True,
            )


@router.post(
    "",
    summary="Trigger a DNS security scan",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanSummary,
)
async def trigger_scan(
    body: ScanCreate,
    request: Request,
    background_tasks: BackgroundTasks,
    _: RequireAuth,
    domain_repo: DomainRepo,
    scan_repo: ScanRepo,
) -> ScanSummary:
    """
    Trigger a new DNS security scan for a domain.

    The scan runs asynchronously. Returns 202 Accepted immediately with
    the scan ID. Poll GET /scan/{id} to get results.

    If the domain is not yet registered, it is auto-registered.
    """
    domain_name = body.domain
    client_ip   = get_client_ip(request)

    # Auto-register domain if not already registered
    domain = await domain_repo.get_by_name(domain_name)
    if domain is None:
        domain = await domain_repo.create_domain(name=domain_name)
        log.info("scan.domain_auto_registered", domain=domain_name)

    # Check for already-running scan
    running = await scan_repo.get_running_for_domain(domain_name)
    if running:
        raise ScanAlreadyRunningError(domain_name, existing_scan_id=running.id)

    # Create scan record in pending state
    scan = await scan_repo.create_scan(
        domain_id=domain.id,
        domain_name=domain_name,
        triggered_by="api",
        requested_by_ip=client_ip,
    )

    # Queue the scan pipeline as a background task
    background_tasks.add_task(
        _run_scan_pipeline,
        scan_id=scan.id,
        domain_name=domain_name,
        domain_id=domain.id,
        include_intel=body.include_intel,
        analyzer_names=body.analyzers,
    )

    log.info(
        "scan.queued",
        scan_id=scan.id,
        domain=domain_name,
        client_ip=client_ip,
    )

    return ScanSummary.model_validate(scan)


@router.get(
    "",
    summary="List recent scans",
    response_model=list[ScanSummary],
)
async def list_scans(
    _: RequireAuth,
    scan_repo: ScanRepo,
    pagination: Pagination,
    domain: str | None = Query(default=None, description="Filter by domain name"),
    scan_status: str | None = Query(default=None, alias="status", description="Filter by status"),
) -> list[ScanSummary]:
    """Return a paginated list of recent scans across all domains."""
    if domain:
        scans = await scan_repo.list_for_domain(
            domain,
            offset=pagination.offset,
            limit=pagination.limit,
            status=scan_status,
        )
    else:
        scans = await scan_repo.list_recent(limit=pagination.limit)

    return [ScanSummary.model_validate(s) for s in scans]


@router.get(
    "/{scan_id}",
    summary="Get scan results",
    response_model=ScanResponse,
)
async def get_scan(
    scan_id: str,
    _: RequireAuth,
    scan_repo: ScanRepo,
) -> ScanResponse:
    """
    Retrieve full scan results including all findings.

    If the scan is still running (status=running or pending),
    findings will be empty — poll until status=completed.
    """
    scan = await scan_repo.get_with_findings(scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_code": "SCAN_NOT_FOUND", "message": f"Scan {scan_id!r} not found."},
        )
    return ScanResponse.model_validate(scan)


@router.post(
    "/bulk",
    summary="Bulk scan multiple domains",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=BulkScanResponse,
)
async def bulk_scan(
    body: BulkScanCreate,
    request: Request,
    background_tasks: BackgroundTasks,
    _: RequireAuth,
    domain_repo: DomainRepo,
    scan_repo: ScanRepo,
) -> BulkScanResponse:
    """
    Trigger scans for multiple domains in one request.

    Returns immediately with a list of queued scan IDs.
    Failed domains (e.g. already running) are reported separately.
    """
    client_ip = get_client_ip(request)
    queued: list[str] = []
    failed: list[dict[str, str]] = []

    for domain_name in body.domains:
        try:
            domain = await domain_repo.get_by_name(domain_name)
            if domain is None:
                domain = await domain_repo.create_domain(name=domain_name)

            running = await scan_repo.get_running_for_domain(domain_name)
            if running:
                failed.append({
                    "domain": domain_name,
                    "reason": f"Scan {running.id} is already running",
                })
                continue

            scan = await scan_repo.create_scan(
                domain_id=domain.id,
                domain_name=domain_name,
                triggered_by="api",
                requested_by_ip=client_ip,
            )

            background_tasks.add_task(
                _run_scan_pipeline,
                scan_id=scan.id,
                domain_name=domain_name,
                domain_id=domain.id,
                include_intel=body.include_intel,
                analyzer_names=None,
            )
            queued.append(scan.id)

        except InvalidDomainError as exc:
            failed.append({"domain": domain_name, "reason": exc.message})
        except Exception as exc:
            failed.append({"domain": domain_name, "reason": str(exc)})

    log.info(
        "scan.bulk_queued",
        total=len(body.domains),
        queued=len(queued),
        failed=len(failed),
    )

    return BulkScanResponse(
        queued=queued,
        failed=failed,
        total_queued=len(queued),
        total_failed=len(failed),
    )


@router.delete(
    "/{scan_id}",
    summary="Cancel a running scan",
    status_code=status.HTTP_200_OK,
)
async def cancel_scan(
    scan_id: str,
    _: RequireAuth,
    scan_repo: ScanRepo,
) -> None:
    """
    Attempt to cancel a pending or running scan.

    Note: Background tasks cannot be forcibly stopped in all cases.
    The scan status will be set to 'cancelled' and results discarded.
    """
    scan = await scan_repo.get(scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_code": "SCAN_NOT_FOUND", "message": f"Scan {scan_id!r} not found."},
        )

    if scan.is_terminal:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error_code": "SCAN_ALREADY_TERMINAL",
                "message": f"Scan is already in terminal state: {scan.status!r}",
            },
        )

    scan.mark_cancelled()
    await scan_repo.update(scan)
    log.info("scan.cancelled", scan_id=scan_id)
