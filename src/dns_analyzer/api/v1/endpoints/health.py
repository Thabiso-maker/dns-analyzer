"""Health check endpoints — used by Docker, Kubernetes, and load balancers."""

from __future__ import annotations

import time

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from dns_analyzer.config.settings import get_settings
from dns_analyzer.database.connection import check_db_health

router = APIRouter()

_start_time = time.monotonic()


@router.get(
    "",
    summary="Health check",
    description="Returns application health status. Used for liveness and readiness probes.",
    response_description="Health status of all system components",
)
async def health_check() -> JSONResponse:
    """
    Full health check — verifies database and cache connectivity.

    Returns:
        200: All systems healthy
        503: One or more systems degraded or unavailable
    """
    settings = get_settings()
    db_health = await check_db_health()

    # Check Redis connectivity
    cache_health: dict = {"status": "ok"}
    try:
        import redis.asyncio as redis_client
        r = redis_client.from_url(settings.redis.url)
        await r.ping()
        await r.aclose()
    except Exception as exc:
        cache_health = {"status": "error", "detail": str(exc)}

    all_healthy = db_health["status"] == "ok" and cache_health["status"] == "ok"
    overall = "ok" if all_healthy else "degraded"

    uptime = round(time.monotonic() - _start_time, 2)

    payload = {
        "status": overall,
        "version": settings.app.version,
        "env": settings.app.env,
        "uptime_seconds": uptime,
        "database": db_health,
        "cache": cache_health,
    }

    return JSONResponse(
        content=payload,
        status_code=200 if all_healthy else 503,
    )


@router.get("/ping", summary="Liveness ping", include_in_schema=False)
async def ping() -> dict:
    """Minimal liveness check — just confirms the process is alive."""
    return {"status": "ok", "message": "pong"}