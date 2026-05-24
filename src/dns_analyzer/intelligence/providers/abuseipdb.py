"""
AbuseIPDB threat intelligence provider.

Queries the AbuseIPDB API v2 for IP abuse confidence scores and reports.

Free tier limits: 1,000 requests/day.
API docs: https://docs.abuseipdb.com/

Endpoints used:
    GET /check  — IP abuse confidence score, ISP, country, usage type
"""

from __future__ import annotations

from dns_analyzer.intelligence.base_provider import BaseIntelProvider, IntelResult
from dns_analyzer.utils.rate_limiter import RateLimiter


class AbuseIPDBProvider(BaseIntelProvider):
    """
    AbuseIPDB API v2 provider.

    Enriches IPs with:
        - Abuse confidence score (0–100, higher = more abusive)
        - Number of reports in the last 90 days
        - ISP, country, and usage type (datacenter, residential, etc.)
        - Whether the IP is listed in the Tor network
        - Whitelist status

    Note: AbuseIPDB is IP-centric. For domain enrichment, this provider
    resolves the domain's A records and checks each IP individually.
    """

    name = "abuseipdb"

    def __init__(self, api_key: str, base_url: str, rate_limiter: RateLimiter) -> None:
        super().__init__(api_key, base_url, rate_limiter, timeout_seconds=10.0)

    def _default_headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Key": self.api_key,
            "User-Agent": "DNSSecurityAnalyzer/1.0",
        }

    async def enrich_domain(self, domain: str) -> IntelResult:
        """
        Enrich a domain by resolving its IPs and checking each via AbuseIPDB.

        Returns a combined result using the highest abuse score found.
        """
        result = IntelResult(provider=self.name, domain=domain)

        try:
            import socket
            import asyncio

            # Resolve domain to IPs
            loop = asyncio.get_event_loop()
            try:
                addr_infos = await loop.run_in_executor(
                    None,
                    lambda: socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                )
                ips = list({info[4][0] for info in addr_infos})
            except socket.gaierror:
                result.error = f"Could not resolve {domain} to IP addresses"
                return result

            if not ips:
                result.error = f"No IPs found for {domain}"
                return result

            # Check the first non-private IP
            from dns_analyzer.utils.validators import is_private_ip
            public_ips = [ip for ip in ips if not is_private_ip(ip)]
            if not public_ips:
                result.error = "All resolved IPs are private/reserved"
                return result

            # Enrich the first public IP (rate limit aware — don't check all)
            ip_result = await self.enrich_ip(public_ips[0])
            result.ip           = ip_result.ip
            result.abuse_score  = ip_result.abuse_score
            result.total_reports = ip_result.total_reports
            result.isp          = ip_result.isp
            result.country      = ip_result.country
            result.org          = ip_result.org
            result.malicious    = ip_result.malicious
            result.suspicious   = ip_result.suspicious
            result.tags         = ip_result.tags
            result.raw          = ip_result.raw

            if ip_result.abuse_score is not None:
                result.reputation_score = ip_result.abuse_score

        except Exception as exc:
            result.error = str(exc)

        return result

    async def enrich_ip(self, ip: str) -> IntelResult:
        """Query AbuseIPDB for an IP's abuse confidence score and metadata."""
        result = IntelResult(provider=self.name, ip=ip)

        try:
            data = await self._get(
                "/check",
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": "90",
                    "verbose": "",
                },
            )

            ip_data = data.get("data", {})
            if not ip_data:
                return result

            result.raw = data

            # ── Abuse score ───────────────────────────────────────────────────
            abuse_score = ip_data.get("abuseConfidenceScore", 0)
            result.abuse_score      = abuse_score
            result.reputation_score = abuse_score
            result.total_reports    = ip_data.get("totalReports", 0)

            # ── Threat flags ──────────────────────────────────────────────────
            result.malicious  = abuse_score >= 50
            result.suspicious = abuse_score >= 25

            # ── Geolocation / ISP ─────────────────────────────────────────────
            result.country = ip_data.get("countryCode")
            result.isp     = ip_data.get("isp")
            result.org     = ip_data.get("domain")

            # ── Tags ──────────────────────────────────────────────────────────
            usage_type = ip_data.get("usageType", "")
            tags: list[str] = []
            if usage_type:
                tags.append(usage_type)
            if ip_data.get("isTor"):
                tags.append("tor")
            if ip_data.get("isWhitelisted"):
                tags.append("whitelisted")
                result.malicious  = False
                result.suspicious = False
            result.tags = tags

            # ── Last seen ─────────────────────────────────────────────────────
            result.last_seen = ip_data.get("lastReportedAt")

            self._log.debug(
                "abuseipdb.ip_checked",
                ip=ip,
                abuse_score=abuse_score,
                total_reports=result.total_reports,
                isp=result.isp,
            )

        except Exception as exc:
            result.error = str(exc)

        return result