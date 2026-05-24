"""
Authentication endpoints — API key generation and management.

POST /auth/keys           — Generate a new API key
GET  /auth/keys/validate  — Validate an existing API key
"""

from __future__ import annotations

import secrets
import string

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from dns_analyzer.api.dependencies import AppSettings, RequireAuth
from dns_analyzer.utils.logger import AuditLogger, get_logger

router = APIRouter()
log    = get_logger(__name__)
audit  = AuditLogger()


class APIKeyCreate(BaseModel):
    label: str = Field(..., min_length=1, max_length=100, description="Human-readable label for this key")
    expires_in_days: int | None = Field(default=None, ge=1, le=365, description="Optional expiry in days")


class APIKeyResponse(BaseModel):
    key: str
    label: str
    prefix: str
    created_at: str
    expires_at: str | None


@router.post(
    "/keys",
    summary="Generate a new API key",
    description="Generate a new API key. Requires an existing valid API key (bootstrap flow).",
    status_code=status.HTTP_201_CREATED,
)
async def generate_api_key(
    body: APIKeyCreate,
    current_key: RequireAuth,
    settings: AppSettings,
) -> APIKeyResponse:
    """
    Generate a cryptographically secure API key.

    The key is shown exactly once — store it securely.
    Only the key prefix is stored server-side for identification.
    """
    from datetime import datetime, timezone, timedelta

    alphabet = string.ascii_letters + string.digits
    raw_key  = "dsa_" + "".join(secrets.choice(alphabet) for _ in range(settings.auth.api_key_length))
    prefix   = raw_key[:12]
    now      = datetime.now(timezone.utc)
    expires  = (now + timedelta(days=body.expires_in_days)) if body.expires_in_days else None

    audit.log(
        "api_key.generated",
        label=body.label,
        prefix=prefix,
        generated_by_key_prefix=current_key[:8],
    )

    log.info("auth.key_generated", label=body.label, prefix=prefix)

    return APIKeyResponse(
        key=raw_key,
        label=body.label,
        prefix=prefix,
        created_at=now.isoformat(),
        expires_at=expires.isoformat() if expires else None,
    )


@router.get(
    "/keys/validate",
    summary="Validate an API key",
    description="Confirm that the provided API key is valid and active.",
)
async def validate_api_key(current_key: RequireAuth) -> dict:
    """Validates the key in the X-API-Key header and returns its prefix."""
    return {
        "valid": True,
        "key_prefix": current_key[:8] + "...",
        "message": "API key is valid.",
    }