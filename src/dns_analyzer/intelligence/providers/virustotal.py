"""
VirusTotal threat intelligence provider.

Queries the VirusTotal API v3 for domain and IP reputation data.

Free tier limits: 4 requests/minute, 500 requests/day.
API docs: https://developers.virustotal.com/reference/overview

Endpoints used:
    GET /domains/{domain}     — domain reputation, categories, votes
    GET /ip_addresses/{ip}    — IP reputation, ASN, geolocation
"""

from __future__ import annotations

from typing import Any

from dns_analyzer.intelligence.base_provider import BaseIntelProvider, IntelResult
from dns_analyzer.utils.rate_limiter import RateLimiter


class VirusTotalProvider(BaseIntelProvider):
    """
    VirusTotal API v3 provider.

    Enriches domains and IPs with:
        - Malicious/suspicious/harmless vote counts from 90+ AV engines
        - Domain categories (e.g. "phishing", "malware distribution")
        - Last analysis stats
        - WHOIS registrar data
        - IP geolocation and ASN info
    """

    name = "virustotal"

    def __init__(self, api_key: str, base_url: str, rate_limiter: RateLimiter) -> None:
        super().__init__(api_key, base_url, rate_limiter, timeout_seconds=15.0)

    def _default_headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "x-apikey": self.api_key,
            "User-Agent": "DNSSecurityAnalyzer/1.0",
        }

    async def enrich_domain(self, domain: str) -> IntelResult:
        """Query VirusTotal for domain reputation and threat categories."""
        result = IntelResult(provider=self.name, domain=domain)

        try:
            data = await self._get(f"/domains/{domain}")
            attrs = data.get("data", {}).get("attributes", {})

            if not attrs:
                result.error = "No attributes returned from VirusTotal"
                return result

            result.raw = data

            # ── Reputation score ──────────────────────────────────────────────
            # last_analysis_stats: {"malicious": N, "suspicious": N, "harmless": N, ...}
            stats = attrs.get("last_analysis_stats", {})
            malicious_count  = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)
            harmless_count   = stats.get("harmless", 0)
            total_engines    = malicious_count + suspicious_count + harmless_count

            if total_engines > 0:
                # Normalise to 0–100: 100 = all engines flag as malicious
                raw_score = ((malicious_count + suspicious_count * 0.5) / total_engines) * 100
                result.reputation_score = min(100, round(raw_score))
            else:
                result.reputation_score = 0

            result.malicious  = malicious_count > 0
            result.suspicious = suspicious_count > 0

            # ── Categories ────────────────────────────────────────────────────
            # categories is a dict of {engine_name: category_string}
            categories_raw = attrs.get("categories", {})
            unique_categories = list(set(categories_raw.values()))
            result.categories = unique_categories

            # ── Tags ──────────────────────────────────────────────────────────
            result.tags = attrs.get("tags", [])

            # ── Last seen ─────────────────────────────────────────────────────
            last_analysis_date = attrs.get("last_analysis_date")
            if last_analysis_date:
                from datetime import datetime, timezone
                dt = datetime.fromtimestamp(last_analysis_date, tz=timezone.utc)
                result.last_seen = dt.isoformat()

            self._log.debug(
                "virustotal.domain_analyzed",
                domain=domain,
                malicious=malicious_count,
                suspicious=suspicious_count,
                harmless=harmless_count,
                categories=unique_categories,
            )

        except Exception as exc:
            result.error = str(exc)

        return result

    async def enrich_ip(self, ip: str) -> IntelResult:
        """Query VirusTotal for IP reputation and geolocation."""
        result = IntelResult(provider=self.name, ip=ip)

        try:
            data = await self._get(f"/ip_addresses/{ip}")
            attrs = data.get("data", {}).get("attributes", {})

            if not attrs:
                return result

            result.raw = data

            # ── Reputation ────────────────────────────────────────────────────
            stats = attrs.get("last_analysis_stats", {})
            malicious_count  = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)
            harmless_count   = stats.get("harmless", 0)
            total            = malicious_count + suspicious_count + harmless_count

            if total > 0:
                result.reputation_score = min(100, round(
                    ((malicious_count + suspicious_count * 0.5) / total) * 100
                ))

            result.malicious  = malicious_count > 0
            result.suspicious = suspicious_count > 0

            # ── Geolocation / ASN ─────────────────────────────────────────────
            result.country = attrs.get("country")
            result.asn     = str(attrs.get("asn", "")) or None
            result.org     = attrs.get("as_owner")

        except Exception as exc:
            result.error = str(exc)

        return result

    def _parse_reputation(self, attrs: dict[str, Any]) -> tuple[int, bool, bool]:
        """
        Parse VirusTotal analysis stats into (score, malicious, suspicious).

        Returns:
            score:      0–100 normalised reputation score
            malicious:  True if any engine flagged as malicious
            suspicious: True if any engine flagged as suspicious
        """
        stats = attrs.get("last_analysis_stats", {})
        mal = stats.get("malicious", 0)
        sus = stats.get("suspicious", 0)
        har = stats.get("harmless", 0)
        total = mal + sus + har
        if total > 0:
            score = min(100, round(((mal + sus * 0.5) / total) * 100))
        else:
            score = 0
        return score, mal > 0, sus > 0