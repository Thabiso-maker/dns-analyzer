"""
Custom exception hierarchy for DNS Security Analyzer.

Design principles:
- Every exception carries structured context (not just a message string)
- Exceptions map cleanly to HTTP status codes for the API layer
- All exceptions are serializable to JSON for structured logging
- Callers can catch broad base classes or specific leaf exceptions

Hierarchy:
    DNSAnalyzerError                    ← base for everything
    ├── ConfigurationError              ← bad settings / missing env vars
    ├── ValidationError                 ← invalid user input
    │   ├── InvalidDomainError
    │   ├── InvalidIPAddressError
    │   └── InvalidScanOptionsError
    ├── ScanError                       ← scan pipeline failures
    │   ├── ScanTimeoutError
    │   ├── ScanAlreadyRunningError
    │   └── ScanNotFoundException
    ├── DNSResolutionError              ← DNS query failures
    │   ├── DNSTimeoutError
    │   ├── DNSNXDomainError
    │   └── DNSServerFailureError
    ├── AnalyzerError                   ← individual check failures
    │   └── AnalyzerTimeoutError
    ├── IntelligenceError               ← threat intel provider failures
    │   ├── IntelProviderUnavailableError
    │   ├── IntelRateLimitError
    │   └── IntelAuthenticationError
    ├── DatabaseError                   ← persistence layer failures
    │   ├── RecordNotFoundError
    │   └── DuplicateRecordError
    ├── CacheError                      ← Redis / in-memory cache failures
    ├── ReportingError                  ← report generation failures
    │   └── ReportNotFoundError
    ├── NotificationError               ← alerting channel failures
    │   ├── EmailDeliveryError
    │   ├── SlackDeliveryError
    │   └── WebhookDeliveryError
    └── RateLimitError                  ← rate limit exceeded
"""

from __future__ import annotations

from http import HTTPStatus
from typing import Any


# ==============================================================================
# BASE EXCEPTION
# ==============================================================================

class DNSAnalyzerError(Exception):
    """
    Base exception for all DNS Analyzer errors.

    All custom exceptions inherit from this class, allowing callers to
    catch everything with a single `except DNSAnalyzerError` if needed.
    """

    # Default HTTP status code for this exception type.
    # Overridden by subclasses to map to appropriate HTTP responses.
    http_status: int = HTTPStatus.INTERNAL_SERVER_ERROR
    error_code: str = "INTERNAL_ERROR"

    def __init__(
        self,
        message: str,
        *,
        detail: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        """
        Args:
            message:  Short human-readable description of the error.
            detail:   Optional longer explanation or remediation hint.
            context:  Optional dict of structured key-value data for logging
                      (e.g. {"domain": "example.com", "resolver": "8.8.8.8"}).
        """
        super().__init__(message)
        self.message = message
        self.detail = detail
        self.context: dict[str, Any] = context or {}

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dict suitable for JSON API error responses."""
        payload: dict[str, Any] = {
            "error_code": self.error_code,
            "message": self.message,
        }
        if self.detail:
            payload["detail"] = self.detail
        if self.context:
            payload["context"] = self.context
        return payload

    def __repr__(self) -> str:
        ctx = f", context={self.context}" if self.context else ""
        return f"{self.__class__.__name__}(message={self.message!r}{ctx})"


# ==============================================================================
# CONFIGURATION ERRORS
# ==============================================================================

class ConfigurationError(DNSAnalyzerError):
    """Raised when the application is misconfigured (bad env vars, missing files, etc.)."""

    http_status = HTTPStatus.INTERNAL_SERVER_ERROR
    error_code = "CONFIGURATION_ERROR"


# ==============================================================================
# VALIDATION ERRORS  (HTTP 422)
# ==============================================================================

class ValidationError(DNSAnalyzerError):
    """Raised when user-supplied input fails validation."""

    http_status = HTTPStatus.UNPROCESSABLE_ENTITY
    error_code = "VALIDATION_ERROR"


class InvalidDomainError(ValidationError):
    """Raised when a domain name fails format or TLD validation."""

    error_code = "INVALID_DOMAIN"

    def __init__(self, domain: str, *, reason: str | None = None) -> None:
        super().__init__(
            message=f"Invalid domain name: {domain!r}",
            detail=reason or "Domain must be a valid FQDN (e.g. example.com).",
            context={"domain": domain},
        )
        self.domain = domain


class InvalidIPAddressError(ValidationError):
    """Raised when an IP address (v4 or v6) fails validation."""

    error_code = "INVALID_IP_ADDRESS"

    def __init__(self, ip: str) -> None:
        super().__init__(
            message=f"Invalid IP address: {ip!r}",
            detail="Must be a valid IPv4 (e.g. 1.2.3.4) or IPv6 address.",
            context={"ip": ip},
        )
        self.ip = ip


class InvalidScanOptionsError(ValidationError):
    """Raised when scan options (format, interval, etc.) are invalid."""

    error_code = "INVALID_SCAN_OPTIONS"


# ==============================================================================
# SCAN ERRORS  (HTTP 400 / 404 / 409)
# ==============================================================================

class ScanError(DNSAnalyzerError):
    """Base class for scan pipeline failures."""

    http_status = HTTPStatus.INTERNAL_SERVER_ERROR
    error_code = "SCAN_ERROR"


class ScanTimeoutError(ScanError):
    """Raised when a full domain scan exceeds its allotted time."""

    http_status = HTTPStatus.REQUEST_TIMEOUT
    error_code = "SCAN_TIMEOUT"

    def __init__(self, domain: str, timeout_seconds: float) -> None:
        super().__init__(
            message=f"Scan timed out for domain: {domain!r}",
            detail=f"Scan exceeded the {timeout_seconds}s time limit.",
            context={"domain": domain, "timeout_seconds": timeout_seconds},
        )
        self.domain = domain
        self.timeout_seconds = timeout_seconds


class ScanAlreadyRunningError(ScanError):
    """Raised when a scan is requested for a domain that is already being scanned."""

    http_status = HTTPStatus.CONFLICT
    error_code = "SCAN_ALREADY_RUNNING"

    def __init__(self, domain: str, existing_scan_id: str) -> None:
        super().__init__(
            message=f"Scan already in progress for domain: {domain!r}",
            detail=f"Wait for scan {existing_scan_id!r} to complete before starting a new one.",
            context={"domain": domain, "existing_scan_id": existing_scan_id},
        )
        self.domain = domain
        self.existing_scan_id = existing_scan_id


class ScanNotFoundException(ScanError):
    """Raised when a scan ID is not found in the database."""

    http_status = HTTPStatus.NOT_FOUND
    error_code = "SCAN_NOT_FOUND"

    def __init__(self, scan_id: str) -> None:
        super().__init__(
            message=f"Scan not found: {scan_id!r}",
            context={"scan_id": scan_id},
        )
        self.scan_id = scan_id


# ==============================================================================
# DNS RESOLUTION ERRORS  (HTTP 502 / 504)
# ==============================================================================

class DNSResolutionError(DNSAnalyzerError):
    """Base class for DNS query failures."""

    http_status = HTTPStatus.BAD_GATEWAY
    error_code = "DNS_RESOLUTION_ERROR"

    def __init__(
        self,
        domain: str,
        record_type: str,
        *,
        resolver: str | None = None,
        message: str | None = None,
    ) -> None:
        super().__init__(
            message=message or f"DNS resolution failed for {record_type} record on {domain!r}",
            context={"domain": domain, "record_type": record_type, "resolver": resolver},
        )
        self.domain = domain
        self.record_type = record_type
        self.resolver = resolver


class DNSTimeoutError(DNSResolutionError):
    """Raised when a DNS query times out on all configured resolvers."""

    http_status = HTTPStatus.GATEWAY_TIMEOUT
    error_code = "DNS_TIMEOUT"

    def __init__(self, domain: str, record_type: str, timeout: float) -> None:
        super().__init__(
            domain=domain,
            record_type=record_type,
            message=f"DNS query timed out after {timeout}s for {record_type} on {domain!r}",
        )
        self.context["timeout_seconds"] = timeout


class DNSNXDomainError(DNSResolutionError):
    """Raised when a domain does not exist (NXDOMAIN response)."""

    http_status = HTTPStatus.NOT_FOUND
    error_code = "DNS_NXDOMAIN"

    def __init__(self, domain: str) -> None:
        super().__init__(
            domain=domain,
            record_type="ANY",
            message=f"Domain does not exist (NXDOMAIN): {domain!r}",
        )


class DNSServerFailureError(DNSResolutionError):
    """Raised when all DNS resolvers return SERVFAIL."""

    error_code = "DNS_SERVFAIL"

    def __init__(self, domain: str, record_type: str) -> None:
        super().__init__(
            domain=domain,
            record_type=record_type,
            message=f"All DNS resolvers returned SERVFAIL for {record_type} on {domain!r}",
        )


# ==============================================================================
# ANALYZER ERRORS
# ==============================================================================

class AnalyzerError(DNSAnalyzerError):
    """Raised when an individual security check (analyzer) fails unexpectedly."""

    http_status = HTTPStatus.INTERNAL_SERVER_ERROR
    error_code = "ANALYZER_ERROR"

    def __init__(self, analyzer_name: str, domain: str, *, reason: str) -> None:
        super().__init__(
            message=f"Analyzer {analyzer_name!r} failed for domain {domain!r}",
            detail=reason,
            context={"analyzer": analyzer_name, "domain": domain},
        )
        self.analyzer_name = analyzer_name
        self.domain = domain


class AnalyzerTimeoutError(AnalyzerError):
    """Raised when an individual analyzer exceeds its time budget."""

    error_code = "ANALYZER_TIMEOUT"

    def __init__(self, analyzer_name: str, domain: str, timeout: float) -> None:
        super().__init__(
            analyzer_name=analyzer_name,
            domain=domain,
            reason=f"Analyzer exceeded {timeout}s time limit.",
        )
        self.context["timeout_seconds"] = timeout


# ==============================================================================
# INTELLIGENCE ERRORS  (HTTP 502 / 503 / 429)
# ==============================================================================

class IntelligenceError(DNSAnalyzerError):
    """Base class for threat intelligence provider failures."""

    http_status = HTTPStatus.BAD_GATEWAY
    error_code = "INTEL_ERROR"

    def __init__(self, provider: str, *, message: str, detail: str | None = None) -> None:
        super().__init__(
            message=message,
            detail=detail,
            context={"provider": provider},
        )
        self.provider = provider


class IntelProviderUnavailableError(IntelligenceError):
    """Raised when a threat intel provider is unreachable or returns 5xx."""

    http_status = HTTPStatus.SERVICE_UNAVAILABLE
    error_code = "INTEL_PROVIDER_UNAVAILABLE"

    def __init__(self, provider: str, status_code: int | None = None) -> None:
        super().__init__(
            provider=provider,
            message=f"Threat intel provider {provider!r} is unavailable.",
            detail=f"HTTP {status_code}" if status_code else None,
        )
        if status_code:
            self.context["http_status_code"] = status_code


class IntelRateLimitError(IntelligenceError):
    """Raised when a threat intel provider's rate limit is exceeded."""

    http_status = HTTPStatus.TOO_MANY_REQUESTS
    error_code = "INTEL_RATE_LIMIT_EXCEEDED"

    def __init__(self, provider: str, retry_after: int | None = None) -> None:
        super().__init__(
            provider=provider,
            message=f"Rate limit exceeded for threat intel provider {provider!r}.",
            detail=f"Retry after {retry_after}s." if retry_after else "Back off and retry.",
        )
        if retry_after:
            self.context["retry_after_seconds"] = retry_after
        self.retry_after = retry_after


class IntelAuthenticationError(IntelligenceError):
    """Raised when a threat intel provider rejects the API key."""

    http_status = HTTPStatus.UNAUTHORIZED
    error_code = "INTEL_AUTH_FAILED"

    def __init__(self, provider: str) -> None:
        super().__init__(
            provider=provider,
            message=f"Authentication failed for threat intel provider {provider!r}.",
            detail="Check that the API key is valid and has not expired.",
        )


# ==============================================================================
# DATABASE ERRORS  (HTTP 404 / 409 / 500)
# ==============================================================================

class DatabaseError(DNSAnalyzerError):
    """Base class for persistence layer failures."""

    http_status = HTTPStatus.INTERNAL_SERVER_ERROR
    error_code = "DATABASE_ERROR"


class RecordNotFoundError(DatabaseError):
    """Raised when a DB lookup returns no rows."""

    http_status = HTTPStatus.NOT_FOUND
    error_code = "RECORD_NOT_FOUND"

    def __init__(self, model: str, identifier: str | int) -> None:
        super().__init__(
            message=f"{model} not found: {identifier!r}",
            context={"model": model, "identifier": str(identifier)},
        )
        self.model = model
        self.identifier = identifier


class DuplicateRecordError(DatabaseError):
    """Raised when an insert violates a unique constraint."""

    http_status = HTTPStatus.CONFLICT
    error_code = "DUPLICATE_RECORD"

    def __init__(self, model: str, field: str, value: str) -> None:
        super().__init__(
            message=f"{model} already exists with {field}={value!r}",
            context={"model": model, "field": field, "value": value},
        )


# ==============================================================================
# CACHE ERRORS
# ==============================================================================

class CacheError(DNSAnalyzerError):
    """Raised when a cache read/write operation fails."""

    http_status = HTTPStatus.INTERNAL_SERVER_ERROR
    error_code = "CACHE_ERROR"


# ==============================================================================
# REPORTING ERRORS
# ==============================================================================

class ReportingError(DNSAnalyzerError):
    """Base class for report generation failures."""

    http_status = HTTPStatus.INTERNAL_SERVER_ERROR
    error_code = "REPORTING_ERROR"


class ReportNotFoundError(ReportingError):
    """Raised when a requested report file or record does not exist."""

    http_status = HTTPStatus.NOT_FOUND
    error_code = "REPORT_NOT_FOUND"

    def __init__(self, report_id: str) -> None:
        super().__init__(
            message=f"Report not found: {report_id!r}",
            context={"report_id": report_id},
        )
        self.report_id = report_id


# ==============================================================================
# NOTIFICATION ERRORS
# ==============================================================================

class NotificationError(DNSAnalyzerError):
    """Base class for notification / alerting failures."""

    http_status = HTTPStatus.INTERNAL_SERVER_ERROR
    error_code = "NOTIFICATION_ERROR"

    def __init__(self, channel: str, *, message: str, detail: str | None = None) -> None:
        super().__init__(message=message, detail=detail, context={"channel": channel})
        self.channel = channel


class EmailDeliveryError(NotificationError):
    """Raised when an email notification fails to send."""

    error_code = "EMAIL_DELIVERY_FAILED"

    def __init__(self, recipient: str, *, reason: str) -> None:
        super().__init__(
            channel="email",
            message=f"Failed to deliver email to {recipient!r}",
            detail=reason,
        )
        self.context["recipient"] = recipient


class SlackDeliveryError(NotificationError):
    """Raised when a Slack webhook call fails."""

    error_code = "SLACK_DELIVERY_FAILED"

    def __init__(self, *, reason: str) -> None:
        super().__init__(channel="slack", message="Failed to deliver Slack notification.", detail=reason)


class WebhookDeliveryError(NotificationError):
    """Raised when a generic webhook call fails."""

    error_code = "WEBHOOK_DELIVERY_FAILED"

    def __init__(self, url: str, *, status_code: int | None = None) -> None:
        super().__init__(
            channel="webhook",
            message=f"Failed to deliver webhook to {url!r}",
            detail=f"HTTP {status_code}" if status_code else None,
        )
        self.context["url"] = url


# ==============================================================================
# RATE LIMIT ERROR  (HTTP 429)
# ==============================================================================

class RateLimitError(DNSAnalyzerError):
    """Raised when the application's own API rate limit is exceeded."""

    http_status = HTTPStatus.TOO_MANY_REQUESTS
    error_code = "RATE_LIMIT_EXCEEDED"

    def __init__(self, limit: int, window_seconds: int) -> None:
        super().__init__(
            message=f"Rate limit exceeded: {limit} requests per {window_seconds}s.",
            detail="Slow down your requests and try again.",
            context={"limit": limit, "window_seconds": window_seconds},
        )
        self.limit = limit
        self.window_seconds = window_seconds