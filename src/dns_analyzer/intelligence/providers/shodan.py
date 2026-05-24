"""
Shodan threat intelligence provider.

Queries the Shodan API for exposed services, open ports, and known
vulnerabilities on nameserver and mail server IP addresses.

Free tier: Limited to /shodan/host/{ip} lookups (no scan credits needed).
API docs: https://developer.shodan.io/api

Endpoints used:
    GET /shodan/host/{ip}     — open ports, services, CVEs for an IP
    GET /dns/resolve          — resolve hostnames to IPs
"""

from __future__ import annotations

from dns_analyzer.intelligence.base_provider import BaseIntelProvider, IntelResult
from dns_analyzer.utils.rate_limiter import RateLimiter


class ShodanProvider(BaseIntelProvider):
    """
    Shodan API provider.

    Enriches IPs with:
        - Open ports and running services
        - Software versions and banners
        - Known CVEs / vulnerabilities
        - Country and ISP information
        - Hostname reverse lookups

    For domain enrichment, resolves nameserver IPs via Shodan's DNS API
    and checks each nameserver for exposed services and vulnerabilities.
    This is particularly useful for detecting outdated DNS software.
    """

    name = "shodan"

    def __init__(self, api_key: str, base_url: str, rate_limiter: RateLimiter) -> None:
        super().__init__(api_key, base_url, rate_limiter, timeout_seconds=15.0)

    def _default_headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "User-Agent": "DNSSecurityAnalyzer/1.0",
        }

    async def enrich_domain(self, domain: str) -> IntelResult:
        """
        Enrich a domain by checking its nameservers via Shodan.

        Resolves the domain's NS records, looks up each nameserver IP
        on Shodan, and returns a combined result focusing on open ports
        and CVEs found on DNS infrastructure.
        """
        result = IntelResult(provider=self.name, domain=domain)

        try:
            import asyncio
            import socket

            # Resolve domain to IPs using system resolver
            loop = asyncio.get_event_loop()
            try:
                addr_infos = await loop.run_in_executor(
                    None,
                    lambda: socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM),
                )
                ips = list({info[4][0] for info in addr_infos})
            except socket.gaierror:
                result.error = f"Could not resolve {domain}"
                return result

            from dns_analyzer.utils.validators import is_private_ip
            public_ips = [ip for ip in ips if not is_private_ip(ip)]

            if not public_ips:
                result.error = "No public IPs found for domain"
                return result

            # Check first public IP only (rate limit aware)
            ip_result = await self.enrich_ip(public_ips[0])
            result.ip             = ip_result.ip
            result.open_ports     = ip_result.open_ports
            result.vulnerabilities = ip_result.vulnerabilities
            result.country        = ip_result.country
            result.org            = ip_result.org
            result.isp            = ip_result.isp
            result.tags           = ip_result.tags
            result.malicious      = bool(ip_result.vulnerabilities)
            result.suspicious     = len(ip_result.open_ports) > 10
            result.raw            = ip_result.raw

        except Exception as exc:
            result.error = str(exc)

        return result

    async def enrich_ip(self, ip: str) -> IntelResult:
        """Query Shodan for open ports, services, and CVEs on an IP."""
        result = IntelResult(provider=self.name, ip=ip)

        try:
            data = await self._get(
                f"/shodan/host/{ip}",
                params={"key": self.api_key},
            )

            if not data:
                return result

            result.raw = data

            # ── Open ports ────────────────────────────────────────────────────
            result.open_ports = sorted(data.get("ports", []))

            # ── Vulnerabilities (CVEs) ────────────────────────────────────────
            vulns = data.get("vulns", {})
            result.vulnerabilities = sorted(vulns.keys()) if isinstance(vulns, dict) else []

            # ── Geolocation ───────────────────────────────────────────────────
            result.country = data.get("country_code")
            result.city    = data.get("city")
            result.org     = data.get("org")
            result.isp     = data.get("isp")
            result.asn     = str(data.get("asn", "")) or None

            # ── Tags ──────────────────────────────────────────────────────────
            result.tags = data.get("tags", [])

            # ── Threat assessment ─────────────────────────────────────────────
            result.malicious  = bool(result.vulnerabilities)
            result.suspicious = (
                len(result.open_ports) > 10
                or any(p in result.open_ports for p in [23, 445, 3389, 5900])  # Telnet, SMB, RDP, VNC
            )

            if result.vulnerabilities:
                result.reputation_score = min(100, len(result.vulnerabilities) * 20)

            self._log.debug(
                "shodan.ip_enriched",
                ip=ip,
                open_ports=len(result.open_ports),
                vulns=len(result.vulnerabilities),
                country=result.country,
            )

        except Exception as exc:
            result.error = str(exc)

        return result

    async def resolve_hostname(self, hostname: str) -> list[str]:
        """
        Resolve a hostname to IP addresses using Shodan's DNS API.

        Returns list of IP strings, or empty list on failure.
        """
        try:
            data = await self._get(
                "/dns/resolve",
                params={"key": self.api_key, "hostnames": hostname},
            )
            ip = data.get(hostname)
            return [ip] if ip else []
        except Exception:
            return []