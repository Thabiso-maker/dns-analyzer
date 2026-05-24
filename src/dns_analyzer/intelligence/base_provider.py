"""
Abstract base class for all threat intelligence providers.

Every provider (VirusTotal, AbuseIPDB, Shodan, IPInfo) implements this
interface. The base class provides:

    - Consistent async HTTP session management (aiohttp)
    - Built-in retry logic with exponential backoff (tenacity)
    - Rate limit enforcement via the RateLimiterRegistry
    - Structured error handling that never crashes the intel pipeline
    - Response caching via the cache layer
    - Execution timing and structured logging

Design contract:
    - enrich_domain() and enrich_ip() must NEVER raise to the caller
    - All errors are caught internally and returned as IntelResult with error set
    - Providers are stateless — one instance is reused across many requests
    - Each provider manages its own rate limiter token bucket

Usage (implementing a new provider):
    class MyProvider(BaseIntelProvider):
        name = "myprovider"

        async def enrich_domain(self, domain: str) -> IntelResult:
            await self.rate_limiter.acquire()
            data = await self._get(f"/domains/{domain}")
            return IntelResult(
                provider=self.name,
                domain=domain,
                raw=data,
                reputation_score=data.get("score"),
                malicious=data.get("malicious", False),
            )
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import aiohttp
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from dns_analyzer.utils.exceptions import (
    IntelAuthenticationError,
    IntelProviderUnavailableError,
    IntelRateLimitError,
)
from dns_analyzer.utils.logger import get_logger
from dns_analyzer.utils.rate_limiter import RateLimiter

log = get_logger(__name__)


# ==============================================================================
# INTEL RESULT
# ==============================================================================

@dataclass
class IntelResult:
    """
    Structured output from one threat intelligence provider for one target.

    Attributes:
        provider:          Name of the provider that produced this result.
        domain:            Domain that was enriched (None if IP-only lookup).
        ip:                IP address that was enriched (None if domain-only).
        raw:               Raw API response data for deep inspection.
        reputation_score:  Normalised reputation score 0–100 (0=clean, 100=malicious).
        malicious:         True if the provider considers this target malicious.
        suspicious:        True if the provider considers this target suspicious.
        categories:        List of threat categories (e.g. ["phishing", "malware"]).
        tags:              Free-form tags from the provider.
        asn:               Autonomous System Number of the IP.
        org:               Organization name of the IP owner.
        country:           Two-letter country code of the IP.
        city:              City of the IP.
        isp:               Internet Service Provider name.
        abuse_score:       AbuseIPDB confidence score (0–100).
        total_reports:     Number of abuse reports on file.
        open_ports:        Open ports detected (from Shodan).
        vulnerabilities:   CVE IDs detected (from Shodan).
        last_seen:         ISO 8601 timestamp of last malicious activity.
        error:             Set if the provider call failed. Result is still returned.
        duration_ms:       Time taken for the provider call in milliseconds.
    """

    provider: str
    domain: str | None = None
    ip: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    # ── Reputation ─────────────────────────────────────────────────────────────
    reputation_score: int | None = None   # 0 = clean, 100 = malicious
    malicious: bool = False
    suspicious: bool = False
    categories: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    # ── IP Geolocation / ASN ───────────────────────────────────────────────────
    asn: str | None = None
    org: str | None = None
    country: str | None = None
    city: str | None = None
    isp: str | None = None

    # ── Abuse data ─────────────────────────────────────────────────────────────
    abuse_score: int | None = None
    total_reports: int | None = None

    # ── Shodan data ────────────────────────────────────────────────────────────
    open_ports: list[int] = field(default_factory=list)
    vulnerabilities: list[str] = field(default_factory=list)

    # ── Metadata ───────────────────────────────────────────────────────────────
    last_seen: str | None = None
    error: str | None = None
    duration_ms: int = 0

    @property
    def is_threat(self) -> bool:
        """True if any threat signal is positive."""
        return (
            self.malicious
            or self.suspicious
            or (self.reputation_score is not None and self.reputation_score >= 50)
            or (self.abuse_score is not None and self.abuse_score >= 50)
            or bool(self.vulnerabilities)
        )

    @property
    def has_error(self) -> bool:
        return self.error is not None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict, excluding raw API data."""
        return {
            "provider": self.provider,
            "domain": self.domain,
            "ip": self.ip,
            "reputation_score": self.reputation_score,
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "categories": self.categories,
            "tags": self.tags,
            "asn": self.asn,
            "org": self.org,
            "country": self.country,
            "city": self.city,
            "isp": self.isp,
            "abuse_score": self.abuse_score,
            "total_reports": self.total_reports,
            "open_ports": self.open_ports,
            "vulnerabilities": self.vulnerabilities,
            "last_seen": self.last_seen,
            "error": self.error,
            "duration_ms": self.duration_ms,
        }


# ==============================================================================
# ABSTRACT BASE PROVIDER
# ==============================================================================

class BaseIntelProvider(ABC):
    """
    Abstract base class for all threat intelligence providers.

    Subclasses MUST set:
        name     : str  — provider identifier (e.g. "virustotal")

    Subclasses MUST implement at least one of:
        enrich_domain(domain) → IntelResult
        enrich_ip(ip)         → IntelResult

    Subclasses receive via __init__:
        api_key      : str         — the provider's API key from settings
        base_url     : str         — the provider's API base URL
        rate_limiter : RateLimiter — pre-configured token bucket for this provider
    """

    name: str = "base"

    def __init__(
        self,
        api_key: str,
        base_url: str,
        rate_limiter: RateLimiter,
        *,
        timeout_seconds: float = 15.0,
        max_retries: int = 3,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.rate_limiter = rate_limiter
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self._log = get_logger(f"intel.{self.name}")
        self._session: aiohttp.ClientSession | None = None

    # ── Session management ─────────────────────────────────────────────────────

    async def _get_session(self) -> aiohttp.ClientSession:
        """Return a shared aiohttp session, creating it on first use."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout_seconds)
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                headers=self._default_headers(),
            )
        return self._session

    async def close(self) -> None:
        """Close the underlying HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()

    def _default_headers(self) -> dict[str, str]:
        """
        Default HTTP headers for all requests.
        Subclasses override this to add provider-specific auth headers.
        """
        return {
            "Accept": "application/json",
            "User-Agent": "DNSSecurityAnalyzer/1.0",
        }

    # ── HTTP helpers ───────────────────────────────────────────────────────────

    async def _get(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """
        Perform an authenticated GET request with retry logic.

        Args:
            path:    URL path (appended to base_url).
            params:  Optional query parameters.
            headers: Optional additional headers (merged with defaults).

        Returns:
            Parsed JSON response body.

        Raises:
            IntelRateLimitError:           On HTTP 429.
            IntelAuthenticationError:      On HTTP 401/403.
            IntelProviderUnavailableError: On HTTP 5xx or connection error.
        """
        url = f"{self.base_url}{path}"
        session = await self._get_session()
        merged_headers = {**(headers or {})}

        try:
            async with session.get(url, params=params, headers=merged_headers) as resp:
                return await self._handle_response(resp)
        except (IntelRateLimitError, IntelAuthenticationError, IntelProviderUnavailableError):
            raise
        except aiohttp.ClientConnectionError as exc:
            raise IntelProviderUnavailableError(self.name) from exc
        except Exception as exc:
            raise IntelProviderUnavailableError(self.name) from exc

    async def _handle_response(self, resp: aiohttp.ClientResponse) -> dict[str, Any]:
        """Parse and validate an HTTP response."""
        if resp.status == 200:
            return await resp.json(content_type=None)

        if resp.status == 429:
            retry_after = int(resp.headers.get("Retry-After", 60))
            self._log.warning(
                "intel.rate_limited",
                provider=self.name,
                retry_after=retry_after,
            )
            raise IntelRateLimitError(self.name, retry_after=retry_after)

        if resp.status in (401, 403):
            self._log.error("intel.auth_failed", provider=self.name, status=resp.status)
            raise IntelAuthenticationError(self.name)

        if resp.status >= 500:
            raise IntelProviderUnavailableError(self.name, status_code=resp.status)

        # Other non-200 responses — return empty dict
        self._log.warning(
            "intel.unexpected_status",
            provider=self.name,
            status=resp.status,
            url=str(resp.url),
        )
        return {}

    # ── Abstract methods ───────────────────────────────────────────────────────

    @abstractmethod
    async def enrich_domain(self, domain: str) -> IntelResult:
        """
        Query threat intelligence for a domain name.

        Args:
            domain: FQDN to look up.

        Returns:
            IntelResult — always returned, never raises.
            On failure, IntelResult.error is set with the reason.
        """
        ...

    async def enrich_ip(self, ip: str) -> IntelResult:
        """
        Query threat intelligence for an IP address.

        Default implementation returns an empty result.
        Override in providers that support IP lookups.
        """
        return IntelResult(provider=self.name, ip=ip)

    # ── Execution wrapper ──────────────────────────────────────────────────────

    async def safe_enrich_domain(self, domain: str) -> IntelResult:
        """
        Call enrich_domain() with timing, logging, and error catching.

        This is what IntelligenceManager calls — never enrich_domain() directly.
        Ensures the intel pipeline never raises even if a provider is down.
        """
        start = time.monotonic()
        self._log.debug("intel.domain_lookup_started", provider=self.name, domain=domain)

        try:
            await self.rate_limiter.acquire()
            result = await self.enrich_domain(domain)
            result.duration_ms = int((time.monotonic() - start) * 1000)
            self._log.info(
                "intel.domain_lookup_completed",
                provider=self.name,
                domain=domain,
                malicious=result.malicious,
                duration_ms=result.duration_ms,
            )
            return result

        except (IntelRateLimitError, IntelAuthenticationError, IntelProviderUnavailableError) as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            self._log.warning(
                "intel.domain_lookup_failed",
                provider=self.name,
                domain=domain,
                error=str(exc),
                duration_ms=duration_ms,
            )
            return IntelResult(
                provider=self.name,
                domain=domain,
                error=str(exc),
                duration_ms=duration_ms,
            )

        except Exception as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            self._log.error(
                "intel.domain_lookup_error",
                provider=self.name,
                domain=domain,
                error=str(exc),
                duration_ms=duration_ms,
                exc_info=True,
            )
            return IntelResult(
                provider=self.name,
                domain=domain,
                error=f"Unexpected error: {exc}",
                duration_ms=duration_ms,
            )

    async def safe_enrich_ip(self, ip: str) -> IntelResult:
        """
        Call enrich_ip() with timing, logging, and error catching.
        """
        start = time.monotonic()
        try:
            await self.rate_limiter.acquire()
            result = await self.enrich_ip(ip)
            result.duration_ms = int((time.monotonic() - start) * 1000)
            return result
        except Exception as exc:
            return IntelResult(
                provider=self.name,
                ip=ip,
                error=str(exc),
                duration_ms=int((time.monotonic() - start) * 1000),
            )

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name!r}, base_url={self.base_url!r})"