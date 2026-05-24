"""
FastAPI middleware stack.

Three middleware components:

    RequestIDMiddleware:
        Injects a unique X-Request-ID header into every request and response.
        Binds the ID to the structlog async context so every log line within
        the request handler automatically includes the request ID.

    LoggingMiddleware:
        Logs every incoming request and outgoing response with:
        method, path, status code, duration, client IP, user agent.
        Uses the request ID from RequestIDMiddleware for correlation.

    RateLimitMiddleware:
        Enforces per-IP token bucket rate limiting using the InMemoryRateLimiter.
        Returns HTTP 429 with Retry-After header when the limit is exceeded.
        Bypasses rate limiting for the /health endpoint.
"""

from __future__ import annotations

import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from dns_analyzer.utils.logger import bind_contextvars, clear_contextvars, get_logger
from dns_analyzer.utils.rate_limiter import InMemoryRateLimiter

log = get_logger(__name__)

# Endpoints exempt from rate limiting
_RATE_LIMIT_EXEMPT_PATHS = frozenset({
    "/health",
    "/api/v1/health",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/favicon.ico",
})


# ==============================================================================
# REQUEST ID MIDDLEWARE
# ==============================================================================

class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Injects a unique request ID into every request/response cycle.

    - Checks for an incoming X-Request-ID header (from upstream proxy/load balancer)
    - Generates a new UUID4 if none is present
    - Adds it to the response headers
    - Binds it to the structlog async context for the duration of the request
    """

    async def dispatch(self, request: Request, call_next: object) -> Response:
        request_id = (
            request.headers.get("X-Request-ID")
            or str(uuid.uuid4())
        )
        request.state.request_id = request_id

        # Bind to async log context — all logs in this request will include it
        bind_contextvars(request_id=request_id)

        try:
            response: Response = await call_next(request)  # type: ignore[operator]
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            clear_contextvars()


# ==============================================================================
# LOGGING MIDDLEWARE
# ==============================================================================

class LoggingMiddleware(BaseHTTPMiddleware):
    """
    Structured request/response logging middleware.

    Logs:
        - Incoming: method, path, query string, client IP, user agent
        - Outgoing: status code, duration in milliseconds

    Health check endpoints (/health) are logged at DEBUG level to avoid
    cluttering production logs with Kubernetes liveness probe noise.
    """

    # Paths to log at DEBUG instead of INFO (high-frequency, low-value)
    _DEBUG_PATHS = frozenset({"/health", "/api/v1/health"})

    async def dispatch(self, request: Request, call_next: object) -> Response:
        start = time.monotonic()
        path = request.url.path
        method = request.method
        client_ip = self._get_client_ip(request)

        log_level = "debug" if path in self._DEBUG_PATHS else "info"

        getattr(log, log_level)(
            "http.request",
            method=method,
            path=path,
            query=str(request.url.query) or None,
            client_ip=client_ip,
            user_agent=request.headers.get("User-Agent"),
        )

        try:
            response: Response = await call_next(request)  # type: ignore[operator]
            duration_ms = int((time.monotonic() - start) * 1000)

            getattr(log, log_level)(
                "http.response",
                method=method,
                path=path,
                status_code=response.status_code,
                duration_ms=duration_ms,
                client_ip=client_ip,
            )

            response.headers["X-Process-Time"] = str(duration_ms)
            return response

        except Exception as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            log.error(
                "http.error",
                method=method,
                path=path,
                error=str(exc),
                duration_ms=duration_ms,
                exc_info=True,
            )
            raise

    @staticmethod
    def _get_client_ip(request: Request) -> str:
        """Extract real client IP, respecting X-Forwarded-For from proxy."""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "unknown"


# ==============================================================================
# RATE LIMIT MIDDLEWARE
# ==============================================================================

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Per-IP token bucket rate limiter middleware.

    Maintains one InMemoryRateLimiter per client IP.
    Returns HTTP 429 with Retry-After and X-RateLimit-* headers
    when the limit is exceeded.

    Args:
        requests_per_minute: Sustained rate limit per IP.
        burst:               Maximum burst tokens per IP.
    """

    def __init__(
        self,
        app: ASGIApp,
        requests_per_minute: int = 60,
        burst: int = 10,
    ) -> None:
        super().__init__(app)
        self._rpm = requests_per_minute
        self._burst = burst
        # Per-IP limiter cache — in production replace with RedisRateLimiter
        self._limiters: dict[str, InMemoryRateLimiter] = {}

    def _get_limiter(self, client_ip: str) -> InMemoryRateLimiter:
        """Get or create a rate limiter for the given IP."""
        if client_ip not in self._limiters:
            self._limiters[client_ip] = InMemoryRateLimiter(
                self._rpm,
                burst=self._burst,
                name=f"client:{client_ip}",
            )
        return self._limiters[client_ip]

    async def dispatch(self, request: Request, call_next: object) -> Response:
        path = request.url.path

        # Skip rate limiting for exempt paths
        if path in _RATE_LIMIT_EXEMPT_PATHS:
            return await call_next(request)  # type: ignore[operator]

        client_ip = LoggingMiddleware._get_client_ip(request)
        limiter = self._get_limiter(client_ip)
        tokens = await limiter.available_tokens()

        # Compute retry-after: time until 1 token is available
        retry_after = max(1, int(60 / self._rpm))

        if not await limiter.try_acquire():
            log.warning(
                "rate_limit.exceeded",
                client_ip=client_ip,
                path=path,
                rpm=self._rpm,
            )
            return JSONResponse(
                status_code=429,
                content={
                    "error_code": "RATE_LIMIT_EXCEEDED",
                    "message": f"Rate limit exceeded. Maximum {self._rpm} requests per minute.",
                    "detail": f"Retry after {retry_after} seconds.",
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(self._rpm),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(retry_after),
                },
            )

        response: Response = await call_next(request)  # type: ignore[operator]

        # Add rate limit headers to successful responses
        remaining = max(0, int(await limiter.available_tokens()))
        response.headers["X-RateLimit-Limit"] = str(self._rpm)
        response.headers["X-RateLimit-Remaining"] = str(remaining)

        return response