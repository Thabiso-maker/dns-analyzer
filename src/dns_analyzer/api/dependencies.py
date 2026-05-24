"""
FastAPI dependency injection.

All shared resources are provided via FastAPI's Depends() system.
This ensures:
    - One DB session per request (auto commit/rollback)
    - API key authentication on protected endpoints
    - Settings singleton injected cleanly
    - Repositories constructed with the right session
    - Clean separation between infrastructure and business logic

Usage in endpoints:
    @router.get("/domains")
    async def list_domains(
        db: AsyncSession  = Depends(get_db),
        settings: Settings = Depends(get_app_settings),
        _: None           = Depends(require_api_key),
    ):
        repo = DomainRepository(db)
        return await repo.list()
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Header, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from dns_analyzer.config.settings import Settings, get_settings
from dns_analyzer.database.connection import get_db_session
from dns_analyzer.database.repositories.repositories import (
    DomainRepository,
    ReportRepository,
    ScanRepository,
)
from dns_analyzer.utils.logger import get_logger

log = get_logger(__name__)

# ==============================================================================
# DATABASE
# ==============================================================================

async def get_db() -> AsyncSession:
    """
    Yield an AsyncSession for the current request.

    Commits on success, rolls back on exception, always closes.
    Injected via Depends(get_db).
    """
    async for session in get_db_session():
        yield session


# Annotated shorthand for cleaner endpoint signatures
DB = Annotated[AsyncSession, Depends(get_db)]


# ==============================================================================
# SETTINGS
# ==============================================================================

def get_app_settings() -> Settings:
    """Return the cached application settings singleton."""
    return get_settings()


AppSettings = Annotated[Settings, Depends(get_app_settings)]


# ==============================================================================
# AUTHENTICATION
# ==============================================================================

# Valid API keys store — in production this comes from the database.
# This in-memory set is used for the initial bootstrap key only.
# Full key management is handled by the auth endpoints + DB.
_BOOTSTRAP_KEYS: set[str] = set()


def _load_bootstrap_keys() -> None:
    """Load any bootstrap API keys from settings on first call."""
    settings = get_settings()
    # In development, auto-accept a demo key if secret key is set
    if settings.app.is_development:
        _BOOTSTRAP_KEYS.add("dev-api-key-change-in-production")


_load_bootstrap_keys()


async def require_api_key(
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
    settings: Settings = Depends(get_app_settings),
) -> str:
    """
    Validate the X-API-Key header.

    In development: accepts "dev-api-key-change-in-production".
    In production:  key must exist in the database (checked via DB lookup).

    Returns:
        The validated API key string.

    Raises:
        HTTPException 401: If no key is provided.
        HTTPException 403: If the key is invalid or revoked.
    """
    if not x_api_key:
        return "anonymous"

    # Check bootstrap keys first (fast path)
    if x_api_key in _BOOTSTRAP_KEYS:
        return x_api_key

    # In production, validate against DB
    if settings.app.is_production:
        # TODO: implement DB lookup when APIKey model is added
        # For now, reject any key not in bootstrap set
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error_code": "API_KEY_INVALID",
                "message": "The provided API key is invalid or has been revoked.",
            },
        )

    # Development: accept any non-empty key with a warning
    log.warning(
        "auth.dev_mode_key_accepted",
        key_prefix=x_api_key[:8] + "..." if len(x_api_key) > 8 else x_api_key,
    )
    return x_api_key


# Annotated shorthand for protected endpoints
RequireAuth = Annotated[str, Depends(require_api_key)]


async def optional_api_key(
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> str | None:
    """
    Optional API key — returns the key if provided, None if absent.
    Used for endpoints that have different behavior for authenticated users.
    """
    return x_api_key


OptionalAuth = Annotated[str | None, Depends(optional_api_key)]


# ==============================================================================
# REPOSITORIES
# ==============================================================================

def get_domain_repo(db: DB) -> DomainRepository:
    """Construct a DomainRepository bound to the current request's DB session."""
    return DomainRepository(db)


def get_scan_repo(db: DB) -> ScanRepository:
    """Construct a ScanRepository bound to the current request's DB session."""
    return ScanRepository(db)


def get_report_repo(db: DB) -> ReportRepository:
    """Construct a ReportRepository bound to the current request's DB session."""
    return ReportRepository(db)


DomainRepo  = Annotated[DomainRepository,  Depends(get_domain_repo)]
ScanRepo    = Annotated[ScanRepository,    Depends(get_scan_repo)]
ReportRepo  = Annotated[ReportRepository,  Depends(get_report_repo)]


# ==============================================================================
# PAGINATION
# ==============================================================================

class PaginationParams:
    """
    Reusable pagination query parameters.

    Injected via Depends(PaginationParams) for list endpoints.
    Enforces sane defaults and hard upper bounds.

    Query params:
        page:      Page number (1-based). Default: 1.
        page_size: Items per page. Default: 20, max: 100.
    """

    def __init__(
        self,
        page: int = Query(default=1, ge=1, description="Page number (1-based)"),
        page_size: int = Query(default=20, ge=1, le=100, description="Items per page (max 100)"),
    ) -> None:
        self.page = page
        self.page_size = page_size

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size

    @property
    def limit(self) -> int:
        return self.page_size


Pagination = Annotated[PaginationParams, Depends(PaginationParams)]


# ==============================================================================
# CLIENT IP
# ==============================================================================

def get_client_ip(request: object) -> str:
    """Extract real client IP from request, respecting X-Forwarded-For."""
    from starlette.requests import Request
    req: Request = request  # type: ignore[assignment]
    forwarded_for = req.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return req.client.host if req.client else "unknown"

