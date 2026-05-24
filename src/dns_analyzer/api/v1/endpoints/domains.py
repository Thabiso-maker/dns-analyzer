"""
Domains endpoints — register, list, update, delete monitored domains.

GET    /domains              — paginated list of all domains
POST   /domains              — register a new domain
GET    /domains/{id}         — get domain details
PATCH  /domains/{id}         — update domain settings
DELETE /domains/{id}         — remove a domain
GET    /domains/{id}/scans   — scan history for a domain
POST   /domains/{id}/monitor — toggle monitoring on/off
GET    /domains/search       — search domains by name
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from dns_analyzer.api.dependencies import DomainRepo, Pagination, RequireAuth, ScanRepo
from dns_analyzer.models.schemas.schemas import (
    DomainCreate,
    DomainResponse,
    DomainSummary,
    DomainUpdate,
    ScanSummary,
)
from dns_analyzer.utils.exceptions import DuplicateRecordError, RecordNotFoundError
from dns_analyzer.utils.logger import get_logger

router = APIRouter()
log    = get_logger(__name__)


@router.get(
    "",
    summary="List all domains",
    response_model=list[DomainSummary],
)
async def list_domains(
    _: RequireAuth,
    repo: DomainRepo,
    pagination: Pagination,
    monitored_only: bool = Query(default=False, description="Filter to monitored domains only"),
) -> list[DomainSummary]:
    """Return a paginated list of all registered domains."""
    filters = {"is_monitored": True} if monitored_only else {}
    domains = await repo.list(
        offset=pagination.offset,
        limit=pagination.limit,
        **filters,
    )
    return [DomainSummary.model_validate(d) for d in domains]


@router.post(
    "",
    summary="Register a domain",
    response_model=DomainResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register_domain(
    body: DomainCreate,
    _: RequireAuth,
    repo: DomainRepo,
) -> DomainResponse:
    """Register a new domain for scanning and optional monitoring."""
    try:
        domain = await repo.create_domain(
            name=body.name,
            description=body.description,
            is_monitored=body.is_monitored,
            monitor_interval_h=body.monitor_interval_h,
            tags=body.tags,
            owner_email=str(body.owner_email) if body.owner_email else None,
            notes=body.notes,
        )
        log.info("domain.registered", name=domain.name, is_monitored=domain.is_monitored)
        return DomainResponse.model_validate(domain)
    except DuplicateRecordError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=exc.to_dict(),
        )


@router.get(
    "/search",
    summary="Search domains",
    response_model=list[DomainSummary],
)
async def search_domains(
    _: RequireAuth,
    repo: DomainRepo,
    q: str = Query(..., min_length=2, description="Search query"),
    limit: int = Query(default=20, ge=1, le=100),
) -> list[DomainSummary]:
    """Full-text search across domain names."""
    domains = await repo.search(q, limit=limit)
    return [DomainSummary.model_validate(d) for d in domains]


@router.get(
    "/{domain_id}",
    summary="Get domain details",
    response_model=DomainResponse,
)
async def get_domain(
    domain_id: str,
    _: RequireAuth,
    repo: DomainRepo,
) -> DomainResponse:
    """Retrieve full details for a single domain by ID."""
    try:
        domain = await repo.get_or_raise(domain_id)
        return DomainResponse.model_validate(domain)
    except RecordNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.to_dict())


@router.patch(
    "/{domain_id}",
    summary="Update domain settings",
    response_model=DomainResponse,
)
async def update_domain(
    domain_id: str,
    body: DomainUpdate,
    _: RequireAuth,
    repo: DomainRepo,
) -> DomainResponse:
    """Partially update a domain's settings (monitoring, tags, owner email, etc.)."""
    try:
        domain = await repo.get_or_raise(domain_id)
    except RecordNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.to_dict())

    update_data = body.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        if field == "tags" and isinstance(value, list):
            domain.set_tags(value)
        elif field == "owner_email":
            setattr(domain, field, str(value) if value else None)
        else:
            setattr(domain, field, value)

    updated = await repo.update(domain)
    log.info("domain.updated", domain_id=domain_id, fields=list(update_data.keys()))
    return DomainResponse.model_validate(updated)


@router.delete(
    "/{domain_id}",
    summary="Delete a domain",
    status_code=status.HTTP_200_OK,
)
async def delete_domain(
    domain_id: str,
    _: RequireAuth,
    repo: DomainRepo,
) -> None:
    """Remove a domain and all its associated scans and reports."""
    deleted = await repo.delete(domain_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error_code": "DOMAIN_NOT_FOUND", "message": f"Domain {domain_id!r} not found."},
        )
    log.info("domain.deleted", domain_id=domain_id)


@router.get(
    "/{domain_id}/scans",
    summary="Get scan history for a domain",
    response_model=list[ScanSummary],
)
async def get_domain_scans(
    domain_id: str,
    _: RequireAuth,
    domain_repo: DomainRepo,
    scan_repo: ScanRepo,
    pagination: Pagination,
    status_filter: str | None = Query(default=None, alias="status", description="Filter by scan status"),
) -> list[ScanSummary]:
    """Return paginated scan history for a domain."""
    try:
        domain = await domain_repo.get_or_raise(domain_id)
    except RecordNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.to_dict())

    scans = await scan_repo.list_for_domain(
        domain.name,
        offset=pagination.offset,
        limit=pagination.limit,
        status=status_filter,
    )
    return [ScanSummary.model_validate(s) for s in scans]


@router.post(
    "/{domain_id}/monitor",
    summary="Toggle domain monitoring",
    response_model=DomainResponse,
)
async def toggle_monitoring(
    domain_id: str,
    _: RequireAuth,
    repo: DomainRepo,
    enabled: bool = Query(..., description="True to enable monitoring, False to disable"),
) -> DomainResponse:
    """Enable or disable scheduled automatic scanning for a domain."""
    try:
        domain = await repo.get_or_raise(domain_id)
    except RecordNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=exc.to_dict())

    domain.is_monitored = enabled
    updated = await repo.update(domain)
    log.info("domain.monitoring_toggled", domain_id=domain_id, enabled=enabled)
    return DomainResponse.model_validate(updated)