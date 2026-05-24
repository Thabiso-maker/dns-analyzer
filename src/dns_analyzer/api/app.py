from __future__ import annotations
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dns_analyzer.api.middleware import LoggingMiddleware, RateLimitMiddleware, RequestIDMiddleware
from dns_analyzer.api.v1.router import api_router
from dns_analyzer.config.settings import get_settings
from dns_analyzer.database.connection import check_db_health, close_db, init_db
from dns_analyzer.utils.exceptions import DNSAnalyzerError
from dns_analyzer.utils.logger import configure_logging, get_logger

log = get_logger(__name__)
_start_time: float = 0.0

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _start_time
    _start_time = time.monotonic()
    settings = get_settings()
    configure_logging()
    log.info("app.starting", name=settings.app_name, version=settings.app_version, env=settings.app_env)
    try:
        await init_db()
        log.info("app.database_initialized")
    except Exception as exc:
        log.error("app.startup_failed", error=str(exc))
        raise
    yield
    log.info("app.shutting_down")
    await close_db()
    log.info("app.shutdown_complete", uptime_seconds=round(time.monotonic() - _start_time, 2))

def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Enterprise DNS Security Analyzer — scan domains for DNS security issues.",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
        debug=settings.app_debug,
    )
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                       allow_methods=["*"], allow_headers=["*"])
    if settings.rate_limit_enabled:
        app.add_middleware(RateLimitMiddleware,
                           requests_per_minute=settings.rate_limit_per_minute,
                           burst=settings.rate_limit_burst)
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(LoggingMiddleware)
    app.include_router(api_router, prefix=settings.app_api_prefix)

    @app.exception_handler(DNSAnalyzerError)
    async def dns_error_handler(request: Request, exc: DNSAnalyzerError) -> JSONResponse:
        return JSONResponse(status_code=exc.http_status, content=exc.to_dict())

    @app.exception_handler(Exception)
    async def general_error_handler(request: Request, exc: Exception) -> JSONResponse:
        log.error("api.unhandled_exception", error=str(exc), exc_info=True)
        return JSONResponse(status_code=500, content={"error_code":"INTERNAL_ERROR","message":str(exc)})

    return app
