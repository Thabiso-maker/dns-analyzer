"""
IPInfo geolocation and ASN intelligence provider.

Queries the IPInfo API for IP geolocation, ASN, and hosting organization data.

Free tier: 50,000 requests/month.
API docs: https://ipinfo.io/developers

Endpoints used:
    GET /{ip}/json   — full IP info (location, ASN, org, abuse contacts)
"""

from __future__ import annotations

from dns_analyzer.intelligence.base_provider import BaseIntelProvider, IntelResult
from dns_analyzer.utils.rate_limiter import RateLimiter


# Hosting providers and cloud ASNs that are commonly associated with
# malicious infrastructure — flag as suspicious when nameservers or mail
# servers are hosted on these networks
_SUSPICIOUS_ORGS = frozenset({
    "AS16276",   # OVH — frequently abused for bulletproof hosting
    "AS24940",   # Hetzner — commonly used for botnets
    "AS9009",    # M247 — bulletproof hosting
    "AS57043",   # Hostkey — frequently abused
    "AS59729",   # NIAGAHOSTER
    "AS3223",    # Voxility — DDoS-for-hire
})

# Countries with elevated risk profiles for DNS infrastructure
_ELEVATED_RISK_COUNTRIES = frozenset({
    "KP",  # North Korea
    "IR",  # Iran
    "RU",  # Russia (in context of suspicious infrastructure)
    "CN",  # China (in context of suspicious infrastructure)
})


class IPInfoProvider(BaseIntelProvider):
    """
    IPInfo API provider.

    Enriches IPs with:
        - Geographic location (country, region, city, coordinates)
        - ASN and organization name
        - Hosting provider detection
        - Abuse contact information
        - VPN, proxy, and Tor detection (paid feature — degrades gracefully)
        - Suspicious ASN flagging

    For domain enrichment, resolves the domain to its primary IP
    and enriches that IP.
    """

    name = "ipinfo"

    def __init__(self, api_key: str, base_url: str, rate_limiter: RateLimiter) -> None:
        super().__init__(api_key, base_url, rate_limiter, timeout_seconds=10.0)

    def _default_headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": "DNSSecurityAnalyzer/1.0",
        }

    async def enrich_domain(self, domain: str) -> IntelResult:
        """
        Enrich a domain by resolving its primary IP and querying IPInfo.
        """
        result = IntelResult(provider=self.name, domain=domain)

        try:
            import asyncio
            import socket

            loop = asyncio.get_event_loop()
            try:
                addr_infos = await loop.run_in_executor(
                    None,
                    lambda: socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM),
                )
                ips = list({info[4][0] for info in addr_infos})
            except socket.gaierror:
                result.error = f"Could not resolve {domain} to an IP"
                return result

            from dns_analyzer.utils.validators import is_private_ip
            public_ips = [ip for ip in ips if not is_private_ip(ip)]
            if not public_ips:
                result.error = "No public IPs resolved for domain"
                return result

            ip_result = await self.enrich_ip(public_ips[0])
            # Merge IP result into domain result
            result.ip         = ip_result.ip
            result.asn        = ip_result.asn
            result.org        = ip_result.org
            result.country    = ip_result.country
            result.city       = ip_result.city
            result.isp        = ip_result.isp
            result.tags       = ip_result.tags
            result.suspicious = ip_result.suspicious
            result.malicious  = ip_result.malicious
            result.raw        = ip_result.raw

        except Exception as exc:
            result.error = str(exc)

        return result

    async def enrich_ip(self, ip: str) -> IntelResult:
        """Query IPInfo for full geolocation, ASN, and organization data."""
        result = IntelResult(provider=self.name, ip=ip)

        try:
            data = await self._get(f"/{ip}/json")

            if not data or "bogon" in data:
                result.error = "Bogon/private IP — no public data available"
                return result

            result.raw = data

            # ── Geolocation ───────────────────────────────────────────────────
            result.country = data.get("country")
            result.city    = data.get("city")

            # ── ASN / Organization ────────────────────────────────────────────
            org_field = data.get("org", "")  # Format: "AS15169 Google LLC"
            if org_field:
                parts = org_field.split(" ", 1)
                if len(parts) == 2 and parts[0].startswith("AS"):
                    result.asn = parts[0]
                    result.org = parts[1]
                else:
                    result.org = org_field

            result.isp = data.get("company", {}).get("name") if isinstance(data.get("company"), dict) else result.org

            # ── Hosting detection (paid feature — degrades gracefully) ────────
            privacy = data.get("privacy", {})
            tags: list[str] = []

            if isinstance(privacy, dict):
                if privacy.get("vpn"):
                    tags.append("vpn")
                if privacy.get("proxy"):
                    tags.append("proxy")
                if privacy.get("tor"):
                    tags.append("tor")
                if privacy.get("relay"):
                    tags.append("relay")
                if privacy.get("hosting"):
                    tags.append("hosting")

            # ── Abuse contact ─────────────────────────────────────────────────
            abuse = data.get("abuse", {})
            if isinstance(abuse, dict) and abuse.get("address"):
                tags.append(f"abuse:{abuse['address']}")

            result.tags = tags

            # ── Suspicious flags ──────────────────────────────────────────────
            asn_suspicious = result.asn in _SUSPICIOUS_ORGS if result.asn else False
            country_risk   = result.country in _ELEVATED_RISK_COUNTRIES if result.country else False
            privacy_risk   = any(t in tags for t in ("vpn", "proxy", "tor"))

            result.suspicious = asn_suspicious or privacy_risk
            result.malicious  = False  # IPInfo doesn't classify IPs as malicious

            if result.suspicious:
                reasons = []
                if asn_suspicious:
                    reasons.append(f"ASN {result.asn} is associated with bulletproof hosting")
                if privacy_risk:
                    reasons.append(f"Privacy flags: {[t for t in tags if t in ('vpn','proxy','tor')]}")
                result.categories = reasons

            self._log.debug(
                "ipinfo.ip_enriched",
                ip=ip,
                asn=result.asn,
                org=result.org,
                country=result.country,
                suspicious=result.suspicious,
                tags=tags,
            )

        except Exception as exc:
            result.error = str(exc)

        return result